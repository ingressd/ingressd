// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ingressd/ingressd/internal/controlsrv"
)

// Options configure an Observer.
type Options struct {
	// Store receives entries; nil keeps only the ring buffer and counters.
	Store *Store
	// RingSize is the live-tail buffer length (default 2000).
	RingSize int
	// OnEvent receives non-access Caddy log lines (certificate events).
	OnEvent func(LogEvent)
	Log     *slog.Logger
	// FlushInterval batches database writes (default 1s).
	FlushInterval time.Duration
}

// Observer ingests log lines and fans them out to the store, ring buffer,
// subscribers and counters.
type Observer struct {
	opts Options
	log  *slog.Logger

	mu        sync.Mutex
	ring      []Entry
	ringNext  int
	ringFull  bool
	subs      map[*subscriber]struct{}
	pending   batch
	hosts     hostSet
	sampling  float64
	retention time.Duration
	counters  map[string]*Totals // per aggregate host, since start
	usage     map[string]*Totals // per exact host since the last TakeUsage (usage.go)

	ingested atomic.Int64
	dropped  atomic.Int64
	invalid  atomic.Int64
}

type subscriber struct {
	f  Filter
	ch chan Entry
}

// New creates an Observer. Call Run to start background flushing.
func New(opts Options) *Observer {
	if opts.RingSize <= 0 {
		opts.RingSize = 2000
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	return &Observer{
		opts: opts, log: opts.Log,
		ring:      make([]Entry, opts.RingSize),
		subs:      map[*subscriber]struct{}{},
		sampling:  1,
		retention: 7 * 24 * time.Hour,
		counters:  map[string]*Totals{},
	}
}

// Configure updates policy after a config apply: the configured hosts (for
// aggregate bucketing; "*.example.com" wildcards allowed), the sampling
// ratio for stored entries, and log retention.
func (o *Observer) Configure(hosts []string, sampling float64, retention time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.hosts = newHostSet(hosts)
	if sampling > 0 && sampling <= 1 {
		o.sampling = sampling
	}
	if retention > 0 {
		o.retention = retention
	}
}

// Ingest processes one Caddy JSON log line.
func (o *Observer) Ingest(line []byte) {
	e, ev, err := parseLine(line)
	if err != nil {
		o.invalid.Add(1)
		return
	}
	if ev != nil {
		if o.opts.OnEvent != nil {
			o.opts.OnEvent(*ev)
		}
		return
	}
	o.Add(*e)
}

// Add records one entry.
func (o *Observer) Add(e Entry) {
	o.ingested.Add(1)
	o.mu.Lock()
	o.ring[o.ringNext] = e
	o.ringNext = (o.ringNext + 1) % len(o.ring)
	if o.ringNext == 0 {
		o.ringFull = true
	}
	agg := o.hosts.bucket(e.Host)
	c := o.counters[agg]
	if c == nil {
		c = &Totals{}
		o.counters[agg] = c
	}
	c.add(e)
	o.meter(e)
	keep := o.sampling >= 1 || rand.Float64() < o.sampling
	if o.opts.Store != nil {
		if len(o.pending.entries) >= 50000 {
			o.dropped.Add(1) // database is not keeping up
			keep = false
		}
		o.pending.add(e, agg, keep)
	}
	for s := range o.subs {
		if s.f.Match(e) {
			select {
			case s.ch <- e:
			default: // slow consumer: drop rather than block ingestion
			}
		}
	}
	o.mu.Unlock()
}

// Recent returns up to n of the newest entries matching f, oldest first.
func (o *Observer) Recent(f Filter, n int) []Entry {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []Entry
	size := len(o.ring)
	count := o.ringNext
	if o.ringFull {
		count = size
	}
	for i := 1; i <= count && len(out) < n; i++ {
		e := o.ring[(o.ringNext-i+size)%size]
		if f.Match(e) {
			out = append(out, e)
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Subscribe streams new entries matching f until ctx is done.
func (o *Observer) Subscribe(ctx context.Context, f Filter) <-chan Entry {
	s := &subscriber{f: f, ch: make(chan Entry, 256)}
	o.mu.Lock()
	o.subs[s] = struct{}{}
	o.mu.Unlock()
	out := make(chan Entry)
	go func() {
		defer close(out)
		defer func() {
			o.mu.Lock()
			delete(o.subs, s)
			o.mu.Unlock()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case e := <-s.ch:
				select {
				case out <- e:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// HostCounters returns request totals per aggregate host since start.
func (o *Observer) HostCounters() []HostStats {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []HostStats
	for h, t := range o.counters {
		out = append(out, HostStats{Host: h, Totals: *t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// Run flushes to the store and prunes old rows until ctx is done.
func (o *Observer) Run(ctx context.Context) {
	if o.opts.Store == nil {
		<-ctx.Done()
		return
	}
	flush := time.NewTicker(o.opts.FlushInterval)
	defer flush.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	o.pruneNow(ctx)
	for {
		select {
		case <-ctx.Done():
			o.flush(context.Background())
			return
		case <-flush.C:
			o.flush(ctx)
		case <-prune.C:
			o.pruneNow(ctx)
		}
	}
}

func (o *Observer) pruneNow(ctx context.Context) {
	o.mu.Lock()
	r := o.retention
	o.mu.Unlock()
	if err := o.opts.Store.Prune(ctx, time.Now(), r); err != nil {
		o.log.Warn("pruning access logs", "err", err)
	}
}

// Flush writes pending entries now (tests, shutdown).
func (o *Observer) Flush() { o.flush(context.Background()) }

func (o *Observer) flush(ctx context.Context) {
	o.mu.Lock()
	b := o.pending
	o.pending = batch{}
	o.mu.Unlock()
	if len(b.entries) == 0 && len(b.aggs) == 0 {
		return
	}
	if err := o.opts.Store.write(ctx, &b); err != nil {
		o.dropped.Add(int64(len(b.entries)))
		o.log.Warn("writing access logs", "err", err, "entries", len(b.entries))
	}
}

// Listen accepts Caddy's net log writer connections on a unix socket at
// path until ctx is done. Each connection carries newline-delimited JSON.
func (o *Observer) Listen(ctx context.Context, path string) error {
	ln, err := controlsrv.Listen(path)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					o.log.Warn("access log socket", "err", err)
				}
				return
			}
			go o.serveConn(ctx, c)
		}
	}()
	return nil
}

func (o *Observer) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := sc.Bytes(); len(line) > 0 {
			o.Ingest(line)
		}
	}
}

// Ingested, Dropped and Invalid are lifetime counters for /metrics.
func (o *Observer) Ingested() int64 { return o.ingested.Load() }
func (o *Observer) Dropped() int64  { return o.dropped.Load() }
func (o *Observer) Invalid() int64  { return o.invalid.Load() }

// hostSet maps request hosts to aggregate buckets.
type hostSet struct {
	exact map[string]bool
	wild  []string // ".example.com" suffixes
}

func newHostSet(hosts []string) hostSet {
	s := hostSet{exact: map[string]bool{}}
	for _, h := range hosts {
		h = strings.ToLower(h)
		if suf, ok := strings.CutPrefix(h, "*"); ok {
			s.wild = append(s.wild, suf)
		} else {
			s.exact[h] = true
		}
	}
	return s
}

// bucket returns host if it is configured (or no hosts are known yet),
// otherwise OtherHost.
func (s hostSet) bucket(host string) string {
	if s.exact == nil || s.exact[host] {
		return host
	}
	for _, suf := range s.wild {
		if strings.HasSuffix(host, suf) && !strings.Contains(strings.TrimSuffix(host, suf), ".") {
			return "*" + suf // one bucket per wildcard bounds cardinality
		}
	}
	return OtherHost
}

func sortHosts(h []HostStats) {
	sort.Slice(h, func(i, j int) bool {
		if h[i].Requests != h[j].Requests {
			return h[i].Requests > h[j].Requests
		}
		return h[i].Host < h[j].Host
	})
}

// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// maxPendingUsage caps unacknowledged usage messages (a week at 60 s).
const maxPendingUsage = 7 * 24 * 60

// usageQueue is the persisted usage state: the last seq, the WireGuard
// counter baselines, and every message the panel has not acknowledged.
type usageQueue struct {
	path string
	mu   sync.Mutex
	d    usageData
}

type usageData struct {
	Seq     int64                 `json:"seq"`
	Acked   int64                 `json:"acked"`
	LastTo  time.Time             `json:"last_to"`
	WG      map[string]wgCounters `json:"wg,omitempty"`
	Pending []nodeproto.Usage     `json:"pending,omitempty"`
}

type wgCounters struct {
	Rx int64 `json:"rx"`
	Tx int64 `json:"tx"`
}

func loadUsage(path string) (*usageQueue, error) {
	q := &usageQueue{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return q, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &q.d); err != nil {
		// A corrupt file must not stop managed mode; start a new baseline
		// but keep the sequence moving forward.
		q.d = usageData{Seq: time.Now().Unix()}
	}
	return q, nil
}

func (q *usageQueue) save() error { return writeJSON(q.path, q.d, 0o600) }

func (q *usageQueue) seq() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.d.Seq
}

func (q *usageQueue) pendingLen() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.d.Pending)
}

func (q *usageQueue) pendingCopy() []nodeproto.Usage {
	q.mu.Lock()
	defer q.mu.Unlock()
	return slices.Clone(q.d.Pending)
}

func (q *usageQueue) ack(seq int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if seq <= q.d.Acked {
		return
	}
	q.d.Acked = seq
	q.d.Pending = slices.DeleteFunc(q.d.Pending, func(u nodeproto.Usage) bool { return u.Seq <= seq })
	_ = q.save()
}

// collector supplies the raw inputs of one usage interval.
type collector struct {
	cfg   *config.Config
	hosts map[string]observe.Totals
	wg    []tunnel.Status
	smart []nodeproto.ServiceUsage
}

// record turns one interval's inputs into a usage message (nil when there
// is nothing to report), persists it and returns it.
func (q *usageQueue) record(c collector, now time.Time) (*nodeproto.Usage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	from := q.d.LastTo
	if from.IsZero() {
		from = now
	}
	u := nodeproto.Usage{From: from.UTC(), To: now.UTC()}
	if c.cfg != nil {
		u.Apps = appUsage(c.cfg, c.hosts)
	}
	if q.d.WG == nil {
		q.d.WG = map[string]wgCounters{}
	}
	for _, s := range c.wg {
		if !s.Up {
			continue
		}
		last, seen := q.d.WG[s.Tunnel]
		cur := wgCounters{Rx: s.RxBytes, Tx: s.TxBytes}
		q.d.WG[s.Tunnel] = cur
		d := wgCounters{Rx: cur.Rx - last.Rx, Tx: cur.Tx - last.Tx}
		if !seen {
			// First sight since enrolment: the counters may include traffic
			// from before managed mode; start the baseline here.
			continue
		}
		if d.Rx < 0 || d.Tx < 0 { // interface recreated: counters restarted
			d = cur
		}
		if d.Rx > 0 || d.Tx > 0 {
			u.Sites = append(u.Sites, nodeproto.SiteUsage{Site: s.Tunnel, RxBytes: d.Rx, TxBytes: d.Tx})
		}
	}
	u.Smart = c.smart
	q.d.LastTo = now
	if len(u.Apps) == 0 && len(u.Sites) == 0 && len(u.Smart) == 0 {
		return nil, q.save()
	}
	q.d.Seq++
	u.Seq = q.d.Seq
	q.d.Pending = append(q.d.Pending, u)
	if n := len(q.d.Pending) - maxPendingUsage; n > 0 {
		q.d.Pending = q.d.Pending[n:]
	}
	return &u, q.save()
}

// appUsage maps per-host totals to apps (hosts that belong to no app, e.g.
// scanners or control hosts, are not app usage).
func appUsage(cfg *config.Config, hosts map[string]observe.Totals) []nodeproto.AppUsage {
	idx := newHostIndex(cfg)
	byApp := map[string]*nodeproto.AppUsage{}
	for h, t := range hosts {
		app := idx.app(h)
		if app == "" {
			continue
		}
		u := byApp[app]
		if u == nil {
			u = &nodeproto.AppUsage{App: app}
			byApp[app] = u
		}
		u.Requests += t.Requests
		u.BytesIn += t.BytesIn
		u.BytesOut += t.BytesOut
		u.Status2xx += t.Status[2]
		u.Status3xx += t.Status[3]
		u.Status4xx += t.Status[4]
		u.Status5xx += t.Status[5]
	}
	var out []nodeproto.AppUsage
	for _, u := range byApp {
		out = append(out, *u)
	}
	slices.SortFunc(out, func(a, b nodeproto.AppUsage) int { return strings.Compare(a.App, b.App) })
	return out
}

// hostIndex maps request hosts to app keys (exact hosts, redirect sources
// and "*.example.com" wildcards).
type hostIndex struct {
	exact map[string]string
	wild  map[string]string // ".example.com" → app
}

func newHostIndex(cfg *config.Config) hostIndex {
	idx := hostIndex{exact: map[string]string{}, wild: map[string]string{}}
	for name, app := range cfg.Apps {
		hs := slices.Clone(app.Hosts)
		for _, r := range app.Redirects {
			hs = append(hs, r.From)
		}
		for _, h := range hs {
			h = strings.ToLower(h)
			if suf, ok := strings.CutPrefix(h, "*"); ok {
				idx.wild[suf] = name
			} else {
				idx.exact[h] = name
			}
		}
	}
	return idx
}

func (idx hostIndex) app(host string) string {
	host = strings.ToLower(host)
	if a, ok := idx.exact[host]; ok {
		return a
	}
	if _, rest, ok := strings.Cut(host, "."); ok {
		return idx.wild["."+rest]
	}
	return ""
}

// usageLoop records usage every interval whether or not the panel is
// connected, and once more at shutdown so nothing is lost.
func (a *Agent) usageLoop(ctx context.Context) {
	t := time.NewTicker(a.o.UsageInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.collectUsage(false)
			return
		case <-t.C:
			a.collectUsage(true)
		}
	}
}

func (a *Agent) collectUsage(send bool) {
	c := collector{smart: hookServiceUsage()}
	c.cfg, _ = a.loadConfig()
	if a.o.Logs != nil {
		c.hosts = a.o.Logs.TakeUsage()
	}
	if c.cfg != nil && len(c.cfg.Tunnels) > 0 {
		c.wg, _ = tunnel.ReadStatus(c.cfg)
	}
	u, err := a.usage.record(c, time.Now())
	if err != nil {
		a.log.Error("persisting usage", "err", err)
	}
	if u != nil && send {
		_ = a.send(nodeproto.TypeUsage, "", *u) // offline: resent on reconnect
	}
}

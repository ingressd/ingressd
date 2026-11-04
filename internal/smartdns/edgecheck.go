// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// Edge geolocation checks (ported from an earlier prototype).
//
// CDN edges each geolocate the viewer themselves and do not always agree:
// one edge can place an exit in another country than its neighbours do,
// and a session that mixes edges then fails. For services with a known
// location API (smartdns.checks), every upstream IP is checked once from
// the exit (CDNs that route by hostname let any edge answer the check),
// and the relay prefers known-good edges in a stable order, then unknown
// ones, and bad ones only as a last resort.

const (
	verdictGood    = "good"
	verdictBad     = "bad"
	verdictUnknown = "unknown"

	goodTTL      = 6 * time.Hour
	badTTL       = 6 * time.Hour
	unknownTTL   = 10 * time.Minute
	probeTimeout = 5 * time.Second
)

type edgeKey struct {
	exit string
	ip   netip.Addr
}

// EdgeResult is one edge check outcome.
type EdgeResult struct {
	Exit    string    `json:"exit"`
	IP      string    `json:"ip"`
	Verdict string    `json:"verdict"`        // good, bad or unknown
	Seen    string    `json:"seen,omitempty"` // country the edge reported
	Want    string    `json:"want"`
	At      time.Time `json:"at"`
}

type edgeChecker struct {
	checkFor func(host string) (config.SmartDNSCheck, bool)
	// probe returns the country the edge at ip reports for e, "" if unknown.
	probe func(ctx context.Context, e *egress, ip netip.Addr, c config.SmartDNSCheck) string
	now   func() time.Time

	checks atomic.Pointer[[]config.SmartDNSCheck]

	mu      sync.Mutex
	results map[edgeKey]EdgeResult
	pending map[edgeKey]chan struct{}
}

func newEdgeChecker() *edgeChecker {
	c := &edgeChecker{
		probe:   probeEdge,
		now:     time.Now,
		results: map[edgeKey]EdgeResult{},
		pending: map[edgeKey]chan struct{}{},
	}
	c.checkFor = c.configured
	return c
}

// setChecks replaces the configured checks (smartdns.checks).
func (c *edgeChecker) setChecks(s *config.SmartDNS) {
	var checks []config.SmartDNSCheck
	if s != nil {
		checks = s.Checks
	}
	c.checks.Store(&checks)
}

// configured returns the configured check for host (a check domain or any
// name under one), if any.
func (c *edgeChecker) configured(host string) (config.SmartDNSCheck, bool) {
	p := c.checks.Load()
	if p == nil {
		return config.SmartDNSCheck{}, false
	}
	host = normalize(host)
	for _, ck := range *p {
		for _, d := range ck.Domains {
			if d = normalize(d); host == d || strings.HasSuffix(host, "."+d) {
				return ck, true
			}
		}
	}
	return config.SmartDNSCheck{}, false
}

func (c *edgeChecker) freshLocked(k edgeKey) (EdgeResult, bool) {
	r, ok := c.results[k]
	if !ok {
		return r, false
	}
	ttl := unknownTTL
	switch r.Verdict {
	case verdictGood:
		ttl = goodTTL
	case verdictBad:
		ttl = badTTL
	}
	return r, c.now().Sub(r.At) < ttl
}

// start launches checks for ips that have no fresh result and returns the
// channels of every check still running for them.
func (c *edgeChecker) start(e *egress, ck config.SmartDNSCheck, ips []netip.Addr) []chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	var wait []chan struct{}
	for _, ip := range ips {
		k := edgeKey{e.exit, ip}
		if ch, ok := c.pending[k]; ok {
			wait = append(wait, ch)
			continue
		}
		if _, fresh := c.freshLocked(k); fresh {
			continue
		}
		ch := make(chan struct{})
		c.pending[k] = ch
		wait = append(wait, ch)
		go c.run(e, ck, ip, ch)
	}
	return wait
}

func (c *edgeChecker) run(e *egress, ck config.SmartDNSCheck, ip netip.Addr, done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	seen := c.probe(ctx, e, ip, ck)
	cancel()
	verdict := verdictUnknown
	switch {
	case seen == "":
	case seen == e.country:
		verdict = verdictGood
	default:
		verdict = verdictBad
	}
	k := edgeKey{e.exit, ip}
	c.mu.Lock()
	c.results[k] = EdgeResult{Exit: e.exit, IP: ip.String(), Verdict: verdict, Seen: seen, Want: e.country, At: c.now()}
	delete(c.pending, k)
	c.mu.Unlock()
	close(done)
}

// prewarm starts background checks for addresses an exit just resolved.
func (c *edgeChecker) prewarm(e *egress, host string, ips []netip.Addr) {
	if ck, ok := c.checkFor(host); ok && e.country != "" {
		c.start(e, ck, ips)
	}
}

// order returns ips best first: known-good sorted (so a host keeps using the
// same edge), then unknown in their original order, then bad. It waits for
// running checks up to the probe timeout.
func (c *edgeChecker) order(ctx context.Context, e *egress, host string, ips []netip.Addr) []netip.Addr {
	ck, ok := c.checkFor(host)
	if !ok || e.country == "" {
		return ips
	}
	wait := c.start(e, ck, ips)
	deadline := time.NewTimer(probeTimeout + time.Second)
	defer deadline.Stop()
wait:
	for _, ch := range wait {
		select {
		case <-ch:
		case <-deadline.C:
			break wait
		case <-ctx.Done():
			break wait
		}
	}
	c.mu.Lock()
	verdict := map[netip.Addr]string{}
	for _, ip := range ips {
		r, fresh := c.freshLocked(edgeKey{e.exit, ip})
		verdict[ip] = verdictUnknown
		if fresh {
			verdict[ip] = r.Verdict
		}
	}
	c.mu.Unlock()
	return orderByVerdict(ips, verdict)
}

func orderByVerdict(ips []netip.Addr, verdict map[netip.Addr]string) []netip.Addr {
	var good, unknown, bad []netip.Addr
	for _, ip := range ips {
		switch verdict[ip] {
		case verdictGood:
			good = append(good, ip)
		case verdictBad:
			bad = append(bad, ip)
		default:
			unknown = append(unknown, ip)
		}
	}
	slices.SortFunc(good, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Concat(good, unknown, bad)
}

// results returns every check result, sorted by exit and IP.
func (c *edgeChecker) snapshot() []EdgeResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]EdgeResult, 0, len(c.results))
	for _, r := range c.results {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b EdgeResult) int {
		return cmp.Or(cmp.Compare(a.Exit, b.Exit), cmp.Compare(a.IP, b.IP))
	})
	return out
}

// summary describes an exit's edge results for its status: the country
// edges report and counts by verdict.
func (c *edgeChecker) summary(exit string) (country, msg string) {
	var good, bad, unknown int
	var latest time.Time
	var badInfo []string
	for _, r := range c.snapshot() {
		if r.Exit != exit {
			continue
		}
		switch r.Verdict {
		case verdictGood:
			good++
		case verdictBad:
			bad++
			badInfo = append(badInfo, fmt.Sprintf("%s sees %s", r.IP, r.Seen))
		default:
			unknown++
		}
		if r.Seen != "" && r.At.After(latest) && r.Verdict == verdictGood {
			country, latest = r.Seen, r.At
		}
	}
	if good+bad+unknown == 0 {
		return "", ""
	}
	if country == "" && len(badInfo) > 0 {
		for _, r := range c.snapshot() {
			if r.Exit == exit && r.Seen != "" {
				country = r.Seen
			}
		}
	}
	msg = fmt.Sprintf("edges: %d good, %d bad, %d unknown", good, bad, unknown)
	if len(badInfo) > 0 {
		msg += " (" + strings.Join(badInfo, ", ") + ")"
	}
	return country, msg
}

var fieldRe = map[string]*regexp.Regexp{}
var fieldReMu sync.Mutex

func fieldRegexp(field string) *regexp.Regexp {
	fieldReMu.Lock()
	defer fieldReMu.Unlock()
	re, ok := fieldRe[field]
	if !ok {
		re = regexp.MustCompile(`"` + regexp.QuoteMeta(field) + `"\s*:\s*"([A-Z]{2})"`)
		fieldRe[field] = re
	}
	return re
}

// probeTLSConfig and probePort are replaced in tests. The system roots
// honour SSL_CERT_FILE.
var (
	probeTLSConfig = func(host string) *tls.Config { return &tls.Config{ServerName: host} }
	probePort      = "443"
)

// probeEdge sends the check request to one edge IP through the exit's
// egress and extracts the reported country.
func probeEdge(ctx context.Context, e *egress, ip netip.Addr, ck config.SmartDNSCheck) string {
	cfg := probeTLSConfig(ck.Host)
	cfg.NextProtos = []string{"http/1.1"}
	d := tls.Dialer{NetDialer: e.dialer(), Config: cfg}
	conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), probePort))
	if err != nil {
		return ""
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	path := ck.Path
	if ck.CacheBuster != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		var b [6]byte
		rand.Read(b[:])
		path += fmt.Sprintf("%s%s=%d", sep, ck.CacheBuster, binary.BigEndian.Uint64(append([]byte{0, 0}, b[:]...)))
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ingressd-smartdns\r\nAccept: application/json\r\nConnection: close\r\n\r\n", path, ck.Host)
	body, _ := io.ReadAll(io.LimitReader(conn, 64<<10))
	m := fieldRegexp(ck.Field).FindSubmatch(body)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/envcompat"
)

// Exit health beyond "can the egress be used": where it really comes out
// (IP and country), from a trace endpoint reached through the egress itself.

// TraceURLEnv overrides the trace endpoint (tests, or a self-hosted
// equivalent). It must answer plain "key=value" lines including ip= and
// loc= (Cloudflare's /cdn-cgi/trace format).
const TraceURLEnv = "INGRESSD_SMARTDNS_TRACE_URL"

const defaultTraceURL = "https://1.1.1.1/cdn-cgi/trace"

var (
	traceEvery   = 10 * time.Minute // after a successful trace
	traceRetry   = time.Minute      // after a failed one
	traceTimeout = 8 * time.Second
)

// probeState is the latest trace for one exit; it survives reconfigures as
// long as the exit's egress does not change.
type probeState struct {
	sig string

	mu      sync.Mutex
	ip      string
	country string
	err     string
	at      time.Time
	running bool
	wasUp   bool
}

func (p *probeState) snapshot() (ip, country, err string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ip, p.country, p.err
}

// prober traces every local egress: at once when it comes up, then every
// 10 minutes (1 minute after a failure).
type prober struct {
	log      *slog.Logger
	traceURL string
	ctx      func() context.Context

	mu     sync.Mutex
	probes map[string]*probeState // exit name -> latest trace
}

func newProber(log *slog.Logger, traceURL string, ctx func() context.Context) *prober {
	if traceURL == "" {
		traceURL = traceURLFromEnv()
	}
	return &prober{log: log, traceURL: traceURL, ctx: ctx, probes: map[string]*probeState{}}
}

func (pr *prober) probe(e *egress) *probeState {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	p, ok := pr.probes[e.exit]
	if !ok || p.sig != e.sig() {
		p = &probeState{sig: e.sig()}
		pr.probes[e.exit] = p
	}
	return p
}

// watch starts due traces for egs and forgets exits no longer present.
func (pr *prober) watch(egs map[string]*egress, now time.Time) {
	pr.mu.Lock()
	for name := range pr.probes {
		if _, ok := egs[name]; !ok {
			delete(pr.probes, name)
		}
	}
	pr.mu.Unlock()
	for _, name := range sortedKeys(egs) {
		e := egs[name]
		p := pr.probe(e)
		up, _ := e.up()
		up = up || e.alwaysTrace
		p.mu.Lock()
		due := false
		switch {
		case !up:
			p.wasUp = false
		case p.running:
		case !p.wasUp, p.at.IsZero():
			due = true
		case p.err != "":
			due = now.Sub(p.at) >= traceRetry
		default:
			due = now.Sub(p.at) >= traceEvery
		}
		if up {
			p.wasUp = true
		}
		if due {
			p.running = true
		}
		p.mu.Unlock()
		if due {
			go pr.run(e, p)
		}
	}
}

func (pr *prober) run(e *egress, p *probeState) {
	ctx, cancel := context.WithTimeout(pr.ctx(), traceTimeout)
	defer cancel()
	ip, country, err := trace(ctx, e, pr.traceURL)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running, p.at = false, time.Now()
	if err != nil {
		p.err = err.Error()
		pr.log.Debug("egress trace failed", "exit", e.exit, "err", err)
		return
	}
	if ip != p.ip || country != p.country {
		pr.log.Info("exit egress", "exit", e.exit, "ip", ip, "country", country)
	}
	p.ip, p.country, p.err = ip, country, ""
}

// trace fetches the trace URL through the egress and returns the ip= and
// loc= values.
func trace(ctx context.Context, e *egress, url string) (ip, country string, err error) {
	tr := &http.Transport{DialContext: e.dialContext, Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "ingressd-smartdns")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("trace: HTTP %d", resp.StatusCode)
	}
	return parseTrace(io.LimitReader(resp.Body, 8<<10))
}

func parseTrace(r io.Reader) (ip, country string, err error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			if a, err := netip.ParseAddr(v); err == nil {
				ip = a.String()
			}
		case "loc":
			if len(v) == 2 && v != "XX" && v != "T1" {
				country = strings.ToUpper(v)
			}
		}
	}
	if ip == "" {
		return "", "", fmt.Errorf("trace: no ip in the answer")
	}
	return ip, country, nil
}

func traceURLFromEnv() string {
	if u := strings.TrimSpace(envcompat.Get(TraceURLEnv)); u != "" {
		return u
	}
	return defaultTraceURL
}

// exitHealth describes what the trace found, for the exit's status.
func exitHealth(e *egress, ip, country, traceErr string, up bool) (egressIP, msg string) {
	egressIP = e.public
	if ip != "" {
		egressIP = ip
	}
	switch {
	case !up:
	case country != "" && e.country != "" && country != e.country:
		msg = fmt.Sprintf("egress %s geolocates to %s, expected %s", egressIP, country, e.country)
	case traceErr != "" && ip == "":
		msg = "egress check failed: " + traceErr
	}
	return egressIP, msg
}

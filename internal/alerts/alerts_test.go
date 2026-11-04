// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
)

func TestKindsMatchConfig(t *testing.T) {
	var ks []string
	for _, k := range Kinds {
		ks = append(ks, string(k))
	}
	if !slices.Equal(ks, config.AlertEvents) {
		t.Fatalf("alerts.Kinds and config.AlertEvents differ:\n%v\n%v", ks, config.AlertEvents)
	}
}

// sink records webhook deliveries.
type sink struct {
	mu   sync.Mutex
	got  []WebhookPayload
	hdrs []http.Header
	raw  []string
}

func (s *sink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.raw = append(s.raw, string(b))
	s.hdrs = append(s.hdrs, r.Header.Clone())
	var p WebhookPayload
	if json.Unmarshal(b, &p) == nil {
		s.got = append(s.got, p)
	}
}

func (s *sink) statuses() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, p := range s.got {
		st := p.Status
		if p.Reminder {
			st += "+reminder"
		}
		out = append(out, string(p.Event)+":"+p.Key+":"+st)
	}
	return out
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func testEngine(t *testing.T, extra string) (*Engine, *sink, *clock) {
	t.Helper()
	s := &sink{}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	cfg, err := config.Parse([]byte(`
version: 1
edge: { name: lab, acme: { ca: internal } }
alerts:
  channels:
    hook: { type: webhook, url: ` + srv.URL + ` }
  rules:
    - { on: [tunnel_down, disk_low, backup_failed], notify: [hook] }
` + extra))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	e := NewEngine(EngineOptions{Now: c.now, StatePath: filepath.Join(t.TempDir(), "state.json")})
	if err := e.Configure(cfg, nil); err != nil {
		t.Fatal(err)
	}
	return e, s, c
}

func TestEngineDedupAndRecovery(t *testing.T) {
	e, s, c := testEngine(t, "  repeat_after: 1h\n")
	ctx := context.Background()
	down := Event{Kind: TunnelDown, Key: "home", Message: "gone"}
	e.Process(ctx, down)
	e.Process(ctx, down) // duplicate
	c.t = c.t.Add(30 * time.Minute)
	e.Process(ctx, down)                               // still within repeat_after
	e.Process(ctx, Event{Kind: PoolAllDown, Key: "p"}) // no rule
	if got := s.statuses(); !slices.Equal(got, []string{"tunnel_down:home:firing"}) {
		t.Fatalf("after duplicates: %v", got)
	}
	if f := e.Firing(); len(f) != 2 {
		t.Fatalf("firing = %+v", f)
	}
	c.t = c.t.Add(31 * time.Minute)
	e.Tick(ctx) // reminder
	e.Process(ctx, Event{Kind: TunnelDown, Key: "home", Resolved: true})
	e.Process(ctx, Event{Kind: TunnelDown, Key: "home", Resolved: true}) // nothing firing
	e.Process(ctx, Event{Kind: DiskLow, Key: "/", Resolved: true})       // never fired
	want := []string{"tunnel_down:home:firing", "tunnel_down:home:firing+reminder", "tunnel_down:home:resolved"}
	if got := s.statuses(); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	p := s.got[0]
	if p.Edge != "lab" || p.Severity != Critical || p.Title != "Tunnel home is down" || p.Message != "gone" {
		t.Errorf("payload = %+v", p)
	}
	if s.got[2].Title != "Tunnel home is back up" || s.got[2].Severity != Info {
		t.Errorf("recovery = %+v", s.got[2])
	}

	// State survives a restart: a firing alert is not re-sent.
	e.Process(ctx, Event{Kind: BackupFailed, Key: "scheduled"})
	e2 := NewEngine(EngineOptions{Now: c.now, StatePath: e.opts.StatePath})
	e2.channels, e2.rules = e.channels, e.rules
	e2.Process(ctx, Event{Kind: BackupFailed, Key: "scheduled"})
	e2.Process(ctx, Event{Kind: BackupFailed, Key: "scheduled", Resolved: true})
	want = append(want, "backup_failed:scheduled:firing", "backup_failed:scheduled:resolved")
	if got := s.statuses(); !slices.Equal(got, want) {
		t.Fatalf("after restart: %v", got)
	}
}

func TestQuietHours(t *testing.T) {
	e, s, c := testEngine(t, `  quiet_hours: { start: "22:00", end: "07:00", timezone: UTC, except: [disk_low] }`+"\n")
	ctx := context.Background()
	c.t = time.Date(2026, 11, 2, 23, 0, 0, 0, time.UTC)
	e.Process(ctx, Event{Kind: TunnelDown, Key: "a"})                 // held
	e.Process(ctx, Event{Kind: TunnelDown, Key: "b"})                 // held, then resolves: dropped
	e.Process(ctx, Event{Kind: TunnelDown, Key: "b", Resolved: true}) //
	e.Process(ctx, Event{Kind: DiskLow, Key: "/"})                    // exempt
	if got := s.statuses(); !slices.Equal(got, []string{"disk_low:/:firing"}) {
		t.Fatalf("during quiet hours: %v", got)
	}
	e.Tick(ctx)
	if len(s.statuses()) != 1 {
		t.Fatal("sent during quiet hours")
	}
	c.t = time.Date(2026, 11, 3, 7, 1, 0, 0, time.UTC)
	e.Tick(ctx)
	want := []string{"disk_low:/:firing", "tunnel_down:a:firing"}
	if got := s.statuses(); !slices.Equal(got, want) {
		t.Fatalf("after quiet hours: %v", got)
	}

	// A recovery during quiet hours waits too.
	c.t = time.Date(2026, 11, 3, 22, 30, 0, 0, time.UTC)
	e.Process(ctx, Event{Kind: TunnelDown, Key: "a", Resolved: true})
	if len(s.statuses()) != 2 {
		t.Fatal("recovery sent during quiet hours")
	}
	c.t = time.Date(2026, 11, 4, 7, 0, 0, 0, time.UTC)
	e.Tick(ctx)
	if got := s.statuses(); !slices.Contains(got, "tunnel_down:a:resolved") {
		t.Fatalf("pending recovery not sent: %v", got)
	}
}

func TestChannels(t *testing.T) {
	s := &sink{}
	srv := httptest.NewServer(s)
	defer srv.Close()
	n := Notification{Event: Event{Kind: TunnelDown, Key: "home", Message: "gone", Fields: map[string]string{"endpoint": "1.2.3.4:5"}}, Edge: "lab"}
	n.normalize(time.Unix(0, 0))
	ctx := context.Background()

	ch, _ := NewChannel(config.AlertChannel{Type: "ntfy", URL: srv.URL}, nil, nil, nil)
	if err := ch.Send(ctx, n); err != nil {
		t.Fatal(err)
	}
	if h := s.hdrs[0]; h.Get("Title") != "[lab] Tunnel home is down" || h.Get("Priority") != "urgent" || !strings.Contains(s.raw[0], "endpoint: 1.2.3.4:5") {
		t.Errorf("ntfy: %v %q", h, s.raw[0])
	}

	ch, _ = NewChannel(config.AlertChannel{Type: "discord", Webhook: "secret://d"}, resolver{"secret://d": srv.URL}, nil, nil)
	if err := ch.Send(ctx, n); err != nil {
		t.Fatal(err)
	}
	var d struct {
		Embeds []struct {
			Title string `json:"title"`
			Color int    `json:"color"`
		} `json:"embeds"`
	}
	if json.Unmarshal([]byte(s.raw[1]), &d); len(d.Embeds) != 1 || !strings.Contains(d.Embeds[0].Title, "Tunnel home is down") || d.Embeds[0].Color != 0xDC2626 {
		t.Errorf("discord: %s", s.raw[1])
	}

	ch, _ = NewChannel(config.AlertChannel{Type: "email", To: []string{"a@b.c"}}, nil, nil, nil)
	if err := ch.Send(ctx, n); err != ErrEmailNotConfigured {
		t.Errorf("email without sender: %v", err)
	}
	fs := &fakeSender{}
	ch, _ = NewChannel(config.AlertChannel{Type: "email", To: []string{"a@b.c"}}, nil, fs, nil)
	if err := ch.Send(ctx, n); err != nil || fs.subject != "[lab] 🚨 Tunnel home is down" || fs.to[0] != "a@b.c" {
		t.Errorf("email: %v %+v", err, fs)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", 403) }))
	defer bad.Close()
	ch, _ = NewChannel(config.AlertChannel{Type: "webhook", URL: bad.URL}, nil, nil, nil)
	if err := ch.Send(ctx, n); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("error status: %v", err)
	}
}

type resolver map[string]string

func (r resolver) Resolve(v string) (string, error) {
	if x, ok := r[v]; ok {
		return x, nil
	}
	return v, nil
}

type fakeSender struct {
	to      []string
	subject string
}

func (f *fakeSender) SendEmail(_ context.Context, to []string, subject, _ string) error {
	f.to, f.subject = to, subject
	return nil
}

func TestTunnelMonitor(t *testing.T) {
	cfg := &config.Config{Tunnels: map[string]config.Tunnel{"home": {Keepalive: 2}, "new": {}}}
	now := time.Unix(1_000_000, 0)
	st := map[string]tunnel.Status{
		"home": {Tunnel: "home", Interface: "ix-home", Up: true, LastHandshake: now.Add(-time.Minute), RxBytes: 100},
		"new":  {Tunnel: "new", Interface: "ix-new", Up: true},
	}
	var events []Event
	m := &Monitor{
		Publish: func(e Event) { events = append(events, e) },
		Config:  func() *config.Config { return cfg },
		Now:     func() time.Time { return now },
		ReadTunnels: func(*config.Config) ([]tunnel.Status, error) {
			return []tunnel.Status{st["home"], st["new"]}, nil
		},
	}
	step := func(d time.Duration, rx int64) {
		now = now.Add(d)
		s := st["home"]
		s.RxBytes = rx
		st["home"] = s
		m.CheckTunnels()
	}
	step(0, 100)
	step(5*time.Second, 132) // keepalive received
	step(5*time.Second, 164)
	if len(events) != 0 {
		t.Fatalf("healthy tunnel alerted: %+v", events)
	}
	step(5*time.Second, 164)
	step(7*time.Second, 164) // 12s without rx > 3*2s+5s
	if len(events) != 1 || events[0].Kind != TunnelDown || events[0].Resolved || !strings.Contains(events[0].Message, "nothing received") {
		t.Fatalf("down: %+v", events)
	}
	step(5*time.Second, 164)
	if len(events) != 1 {
		t.Fatal("down published twice")
	}
	step(1*time.Second, 300)
	if len(events) != 2 || !events[1].Resolved {
		t.Fatalf("recovery: %+v", events)
	}
	// Interface deleted.
	s := st["home"]
	s.Up = false
	st["home"] = s
	step(time.Second, 300)
	if len(events) != 3 || !strings.Contains(events[2].Message, "missing") {
		t.Fatalf("missing interface: %+v", events)
	}
}

func writeCert(t *testing.T, path string, lifetime, left time.Duration) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notAfter := time.Now().Add(left)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: notAfter.Add(-lifetime), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func TestCertMonitor(t *testing.T) {
	dir := t.TempDir()
	acme := "acme-v02.api.letsencrypt.org-directory"
	writeCert(t, filepath.Join(dir, acme, "ok.example.com", "ok.example.com.crt"), 90*24*time.Hour, 60*24*time.Hour)
	writeCert(t, filepath.Join(dir, acme, "old.example.com", "old.example.com.crt"), 90*24*time.Hour, 5*24*time.Hour)
	writeCert(t, filepath.Join(dir, acme, "wildcard_.example.com", "wildcard_.example.com.crt"), 90*24*time.Hour, -time.Hour)
	writeCert(t, filepath.Join(dir, "local", "lan.test", "lan.test.crt"), 12*time.Hour, time.Hour)
	writeCert(t, filepath.Join(dir, acme, "short.example.com", "short.example.com.crt"), 6*24*time.Hour, 2*24*time.Hour)
	var firing []string
	m := &Monitor{CertDir: dir, Publish: func(e Event) {
		if !e.Resolved {
			firing = append(firing, e.Key+":"+string(e.Severity))
		}
	}}
	m.CheckCerts()
	slices.Sort(firing)
	if want := []string{"*.example.com:critical", "old.example.com:warning"}; !slices.Equal(firing, want) {
		t.Fatalf("firing %v, want %v", firing, want)
	}
}

func TestCertLogEvent(t *testing.T) {
	ev, ok := CertLogEvent(observe.LogEvent{Logger: "tls.obtain", Level: "error", Msg: "could not get certificate from issuer",
		Fields: map[string]any{"identifier": "a.example.com", "error": "rate limited"}})
	if !ok || ev.Kind != CertRenewalFailed || ev.Key != "a.example.com" || ev.Resolved || ev.Fields["error"] != "rate limited" {
		t.Fatalf("failure: %+v %v", ev, ok)
	}
	ev, ok = CertLogEvent(observe.LogEvent{Logger: "tls.renew", Level: "info", Msg: "certificate renewed successfully",
		Fields: map[string]any{"identifier": "a.example.com"}})
	if !ok || !ev.Resolved {
		t.Fatalf("success: %+v %v", ev, ok)
	}
	if _, ok := CertLogEvent(observe.LogEvent{Logger: "http.log.error", Level: "error"}); ok {
		t.Fatal("unrelated logger mapped")
	}
}

func TestPublishBuffersUntilEngine(t *testing.T) {
	Publish(Event{Kind: DiskLow, Key: "/buffered"})
	e := NewEngine(EngineOptions{})
	SetDefault(e)
	defer SetDefault(nil)
	select {
	case ev := <-e.queue:
		if ev.Key != "/buffered" {
			t.Fatalf("got %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("buffered event not delivered")
	}
}

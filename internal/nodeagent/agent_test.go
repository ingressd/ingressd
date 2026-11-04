// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/apply"
	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/gitstore"
	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/internal/pipeline"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/nodeproto"
	"github.com/ingressd/ingressd/test/fakepanel"
)

const testConfig = `version: 1
edge:
  public_ipv4: 203.0.113.10
  acme: { ca: internal }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
  conn:
    site: connector
    listen_port: 51821
    transit: 10.100.2.0/24
apps:
  web:
    hosts: [web.example.test]
    origin: http://192.168.0.17:8080
    tunnel: home
  wild:
    hosts: ["*.apps.example.test"]
    origin: http://192.168.0.18:8080
    tunnel: home
`

// fakeLogs is a LogSource for tests.
type fakeLogs struct {
	mu    sync.Mutex
	usage map[string]observe.Totals
	subs  []chan observe.Entry
}

func (f *fakeLogs) Subscribe(ctx context.Context, _ observe.Filter) <-chan observe.Entry {
	ch := make(chan observe.Entry, 1000)
	f.mu.Lock()
	f.subs = append(f.subs, ch)
	f.mu.Unlock()
	return ch
}

func (f *fakeLogs) TakeUsage() map[string]observe.Totals {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.usage
	f.usage = nil
	return u
}

func (f *fakeLogs) add(host string, status int, bytes int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.usage == nil {
		f.usage = map[string]observe.Totals{}
	}
	t := f.usage[host]
	t.Requests++
	t.Status[status/100]++
	t.BytesOut += bytes
	f.usage[host] = t
}

func (f *fakeLogs) emit(e observe.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ch := range f.subs {
		ch <- e
	}
}

type harness struct {
	t      *testing.T
	dir    string
	panel  *fakepanel.Server
	srv    *httptest.Server
	pipe   *pipeline.Pipeline
	logs   *fakeLogs
	opts   Options
	caddy  func(context.Context, json.RawMessage) error
	cancel context.CancelFunc
	done   chan error
	agent  *Agent
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), panel: fakepanel.New(), logs: &fakeLogs{}}
	h.srv = httptest.NewTLSServer(h.panel.Handler())
	t.Cleanup(h.srv.Close)
	conf := filepath.Join(h.dir, "conf")
	repo := gitstore.Repo{Dir: conf}
	if err := repo.Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf, "config.yaml"), []byte("version: 1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(h.dir, "keys", "age.key")
	state := filepath.Join(h.dir, "state")
	h.pipe = &pipeline.Pipeline{
		ConfigPath: filepath.Join(conf, "config.yaml"), SecretsPath: filepath.Join(conf, "secrets.age"), KeyPath: key, Repo: repo,
		Engine: func() *apply.Engine {
			return &apply.Engine{StatePath: filepath.Join(h.dir, "last.json"), Backends: apply.Backends{Caddy: func(ctx context.Context, b json.RawMessage) error {
				if h.caddy != nil {
					return h.caddy(ctx, b)
				}
				return nil
			}}}
		},
	}
	h.panel.AddToken("tok1")
	if _, err := Enroll(context.Background(), EnrollOptions{PanelURL: h.srv.URL, Token: "tok1", PublicIPv4: "203.0.113.10", KeyPath: key, StateDir: state, HTTPClient: h.srv.Client()}); err != nil {
		t.Fatal(err)
	}
	h.opts = Options{
		StateDir: state, KeyPath: key, ConfigPath: h.pipe.ConfigPath,
		CaddyStorage: filepath.Join(state, "caddy"), Pipeline: h.pipe, Logs: h.logs,
		UsageInterval: 100 * time.Millisecond, StatusPoll: 200 * time.Millisecond, HTTPClient: h.srv.Client(),
	}
	return h
}

func (h *harness) start() {
	h.t.Helper()
	a, err := New(h.opts)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.agent, h.cancel, h.done = a, cancel, make(chan error, 1)
	go func() { h.done <- a.Run(ctx) }()
	h.wait("connected", func(s fakepanel.State) bool { return s.Connected && s.Hello != nil })
}

func (h *harness) stop() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		h.t.Fatal("agent did not stop")
	}
}

func (h *harness) ctx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	h.t.Cleanup(cancel)
	return ctx
}

func (h *harness) wait(what string, cond func(fakepanel.State) bool) fakepanel.State {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if s := h.panel.State(); cond(s) {
			return s
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %s", what)
	return fakepanel.State{}
}

func TestEnrollWritesState(t *testing.T) {
	h := newHarness(t)
	fi, err := os.Stat(StatePath(h.opts.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("node.json mode = %v", fi.Mode().Perm())
	}
	st, err := LoadState(h.opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.OrgSigningKey != h.panel.OrgPublicKey() || st.PanelURL != h.srv.URL || st.PublicIPv4 != "203.0.113.10" {
		t.Errorf("state = %+v", st)
	}
	if ep := LoadEndpoint(h.opts.StateDir); ep.Host() != "203.0.113.10" || !ep.HostIsIP() {
		t.Errorf("endpoint = %+v", ep)
	}
	// A second enrolment needs a detach first; a used token is rejected.
	if _, err := Enroll(context.Background(), EnrollOptions{PanelURL: h.srv.URL, Token: "tok1", KeyPath: h.opts.KeyPath, StateDir: h.opts.StateDir, HTTPClient: h.srv.Client()}); err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Errorf("re-enrol: %v", err)
	}
	if _, err := Enroll(context.Background(), EnrollOptions{PanelURL: h.srv.URL, Token: "tok1", KeyPath: h.opts.KeyPath, StateDir: t.TempDir(), HTTPClient: h.srv.Client()}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("used token: %v", err)
	}
}

func TestHelloAndSnapshot(t *testing.T) {
	h := newHarness(t)
	h.start()
	defer h.stop()
	s := h.panel.State()
	if s.Hello.MeshPublicKey == "" || s.Hello.AgeRecipient == "" || s.Hello.ProtocolVersion != nodeproto.Version {
		t.Fatalf("hello = %+v", s.Hello)
	}

	a, err := h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{Secrets: map[string]string{"smtp_password": "hunter2-secret"}})
	if err != nil || !a.OK || a.Revision != 1 {
		t.Fatalf("applied = %+v, %v", a, err)
	}
	b, _ := os.ReadFile(h.pipe.ConfigPath)
	if string(b) != testConfig {
		t.Fatalf("config.yaml not written")
	}
	err = h.pipe.WithSecrets(func(st *secrets.Store) error {
		if v, _ := st.Get("smtp_password"); v != "hunter2-secret" {
			t.Errorf("secret = %q", v)
		}
		if _, ok := st.Get(MeshKeyName); !ok {
			t.Error("mesh key missing")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := LoadState(h.opts.StateDir); st.AppliedRevision != 1 {
		t.Errorf("applied revision = %d", st.AppliedRevision)
	}
	h.wait("status with revision 1", func(s fakepanel.State) bool { return s.Status != nil && s.Status.AppliedRevision == 1 })

	// Tampered: rejected, nothing changes.
	a, _ = h.panel.SendSnapshot(h.ctx(), testConfig+"# v2\n", fakepanel.SnapshotOptions{Tamper: true})
	if a.OK || !strings.Contains(a.Error, "signature") {
		t.Errorf("tampered = %+v", a)
	}
	// Stale revision: rejected; redelivery of the applied one: ok.
	if a, _ = h.panel.SendSnapshot(h.ctx(), testConfig+"# old\n", fakepanel.SnapshotOptions{Revision: 1}); a.OK {
		t.Errorf("stale accepted: %+v", a)
	}
	if a, err = h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{Revision: 1}); a.OK || err != nil {
		t.Errorf("same revision with different secrets accepted: %+v %v", a, err)
	}
	// Force resync with an older revision is applied.
	if a, _ = h.panel.SendSnapshot(h.ctx(), testConfig+"# forced\n", fakepanel.SnapshotOptions{Revision: 1, Force: true}); !a.OK {
		t.Errorf("force rejected: %+v", a)
	}
	// Invalid config: rejected with the field path.
	if a, _ = h.panel.SendSnapshot(h.ctx(), "version: 1\napps: {x: {hosts: [a.test], origin: nope}}\n", fakepanel.SnapshotOptions{}); a.OK || !strings.Contains(a.Error, "apps.x") {
		t.Errorf("invalid = %+v", a)
	}
	// Reserved secret names cannot be set.
	if a, _ = h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{Secrets: map[string]string{MeshKeyName: "x"}}); a.OK {
		t.Errorf("reserved secret accepted")
	}

	// Failing apply: previous config and secrets restored.
	before, _ := os.ReadFile(h.pipe.ConfigPath)
	h.caddy = func(context.Context, json.RawMessage) error { return errors.New("caddy exploded") }
	a, _ = h.panel.SendSnapshot(h.ctx(), testConfig+"  extra:\n    hosts: [extra.example.test]\n    origin: http://192.168.0.19:80\n    tunnel: home\n",
		fakepanel.SnapshotOptions{Secrets: map[string]string{"other": "value-123"}})
	h.caddy = nil
	if a.OK || !strings.Contains(a.Error, "caddy exploded") {
		t.Errorf("failing apply = %+v", a)
	}
	after, _ := os.ReadFile(h.pipe.ConfigPath)
	if string(after) != string(before) {
		t.Error("config not restored after failed apply")
	}
	_ = h.pipe.WithSecrets(func(st *secrets.Store) error {
		if _, ok := st.Get("other"); ok {
			t.Error("secret from failed snapshot kept")
		}
		return nil
	})
	if st, _ := LoadState(h.opts.StateDir); st.AppliedRevision != 1 {
		t.Errorf("applied revision moved to %d after failure", st.AppliedRevision)
	}
	// Removal of a secret.
	if a, _ = h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{Revision: 5, RemoveSecrets: []string{"smtp_password"}}); !a.OK {
		t.Fatalf("remove = %+v", a)
	}
	_ = h.pipe.WithSecrets(func(st *secrets.Store) error {
		if _, ok := st.Get("smtp_password"); ok {
			t.Error("secret not removed")
		}
		return nil
	})
}

func TestUsageSeqAckAndRestart(t *testing.T) {
	h := newHarness(t)
	h.start()
	if a, err := h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{}); err != nil || !a.OK {
		t.Fatalf("%+v %v", a, err)
	}
	for range 3 {
		h.logs.add("web.example.test", 200, 100)
	}
	h.logs.add("x.apps.example.test", 503, 5)
	h.logs.add("unknown.example.test", 200, 5)
	s := h.wait("usage", func(s fakepanel.State) bool { return s.Apps["web"].Requests == 3 && s.Apps["wild"].Requests == 1 })
	if s.Apps["wild"].Status5xx != 1 || s.Apps["web"].BytesOut != 300 {
		t.Errorf("apps = %+v", s.Apps)
	}
	if _, ok := s.Apps[""]; ok {
		t.Error("unknown host counted as an app")
	}
	h.wait("ack", func(fakepanel.State) bool { return h.agent.usage.pendingLen() == 0 })
	seq1 := h.agent.usage.seq()

	// Without acks, deltas stay pending and are resent after a restart.
	h.panel.AckUsage = false
	h.logs.add("web.example.test", 200, 1)
	h.wait("second usage", func(s fakepanel.State) bool { return s.Apps["web"].Requests == 4 })
	h.logs.add("web.example.test", 200, 1) // recorded at shutdown
	h.stop()
	h.start()
	h.wait("resent", func(s fakepanel.State) bool { return s.Apps["web"].Requests == 5 })
	s = h.panel.State()
	if s.UsageMsgs <= len(s.UsageSeqs) {
		t.Errorf("expected resends: %d messages for %d seqs", s.UsageMsgs, len(s.UsageSeqs))
	}
	for i := 1; i < len(s.UsageSeqs); i++ {
		if s.UsageSeqs[i] != s.UsageSeqs[i-1]+1 {
			t.Errorf("seqs not contiguous: %v", s.UsageSeqs)
		}
	}
	if h.agent.usage.seq() <= seq1 {
		t.Error("seq did not increase")
	}
	h.stop()
}

func TestLiveSubscription(t *testing.T) {
	h := newHarness(t)
	h.start()
	defer h.stop()
	if a, _ := h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{}); !a.OK {
		t.Fatal(a.Error)
	}
	if err := h.panel.Send(h.ctx(), nodeproto.TypeLiveSubscribe, "", nodeproto.LiveSubscribe{
		SubscriptionID: "sub1", Apps: []string{"web"}, Until: time.Now().Add(time.Minute), MaxPerSecond: 5,
	}); err != nil {
		t.Fatal(err)
	}
	h.wait("subscribed", func(fakepanel.State) bool {
		h.logs.mu.Lock()
		defer h.logs.mu.Unlock()
		return len(h.logs.subs) > 0
	})
	h.logs.emit(observe.Entry{Time: time.Now(), Host: "other.example.test", Path: "/no", Status: 200})
	for i := range 10 {
		h.logs.emit(observe.Entry{Time: time.Now(), Host: "web.example.test", Method: "GET", Path: "/p?token=secret&x=1", Status: 200 + i})
	}
	s := h.wait("logs", func(s fakepanel.State) bool { return len(s.Logs) >= 5 && s.LogDrops >= 5 })
	for _, e := range s.Logs {
		if e.Host != "web.example.test" || e.App != "web" {
			t.Errorf("unexpected entry %+v", e)
		}
		if e.Path != "/p?token=&x=" {
			t.Errorf("query not redacted: %q", e.Path)
		}
	}
	if len(s.Logs) != 5 {
		t.Errorf("rate limit: got %d entries", len(s.Logs))
	}
	_ = h.panel.Send(h.ctx(), nodeproto.TypeLiveUnsubscribe, "", nodeproto.LiveUnsubscribe{SubscriptionID: "sub1"})
	time.Sleep(1200 * time.Millisecond)
	h.logs.emit(observe.Entry{Time: time.Now(), Host: "web.example.test", Path: "/after", Status: 200})
	time.Sleep(800 * time.Millisecond)
	for _, e := range h.panel.State().Logs {
		if e.Path == "/after" {
			t.Error("entry streamed after unsubscribe")
		}
	}
}

func TestNodeAnsweredRequests(t *testing.T) {
	h := newHarness(t)
	h.start()
	defer h.stop()
	if a, _ := h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{}); !a.OK {
		t.Fatal(a.Error)
	}
	env, err := h.panel.Request(h.ctx(), nodeproto.TypeSiteConfigRequest, nodeproto.SiteConfigRequest{Site: "home"})
	if err != nil {
		t.Fatal(err)
	}
	var sc nodeproto.SiteConfig
	_ = env.Decode(&sc)
	if env.Type != nodeproto.TypeSiteConfig || !strings.Contains(sc.Config, "DNS = ") || !strings.Contains(sc.Config, "Endpoint = 203.0.113.10:51820") {
		t.Errorf("site config = %+v", sc)
	}

	// Bare-IP edge: the join string carries the internal CA.
	env, _ = h.panel.Request(h.ctx(), nodeproto.TypeConnectorTokenRequest, nodeproto.ConnectorTokenRequest{Site: "conn"})
	var ct nodeproto.ConnectorToken
	_ = env.Decode(&ct)
	if ct.Error == "" || !strings.Contains(ct.Error, "internal CA") {
		t.Errorf("expected CA-not-ready error, got %+v", ct)
	}
	caDir := filepath.Join(h.opts.CaddyStorage, "pki", "authorities", "local")
	_ = os.MkdirAll(caDir, 0o700)
	_ = os.WriteFile(filepath.Join(caDir, "root.crt"), []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o600)
	env, _ = h.panel.Request(h.ctx(), nodeproto.TypeConnectorTokenRequest, nodeproto.ConnectorTokenRequest{Site: "conn"})
	ct = nodeproto.ConnectorToken{}
	_ = env.Decode(&ct)
	j, err := proto.DecodeJoin(ct.JoinString)
	if err != nil || j.URL != "https://203.0.113.10" || !strings.Contains(j.CA, "BEGIN CERTIFICATE") || len(j.Token) != 48 {
		t.Fatalf("join = %+v (%v) from %+v", j, err, ct)
	}
	if ct.ExpiresAt.IsZero() {
		t.Error("no expiry")
	}
	env, _ = h.panel.Request(h.ctx(), nodeproto.TypeConnectorTokenRequest, nodeproto.ConnectorTokenRequest{Site: "home"})
	ct = nodeproto.ConnectorToken{}
	_ = env.Decode(&ct)
	if !strings.Contains(ct.Error, "not a connector site") {
		t.Errorf("router site token = %+v", ct)
	}

	env, _ = h.panel.Request(h.ctx(), nodeproto.TypeSmartDNSRecentRequest, nodeproto.SmartDNSRecentRequest{Limit: 5})
	if env.Type != nodeproto.TypeSmartDNSRecent {
		t.Errorf("recent reply type %q", env.Type)
	}
	SetSmartDNS(fakeSmart{})
	defer SetSmartDNS(nil)
	env, _ = h.panel.Request(h.ctx(), nodeproto.TypeSmartDNSRecentRequest, nodeproto.SmartDNSRecentRequest{Limit: 5})
	var rec nodeproto.SmartDNSRecent
	_ = env.Decode(&rec)
	if len(rec.Lookups) != 1 || rec.Lookups[0].Name != "tv.stream.example" {
		t.Errorf("recent = %+v", rec)
	}
	h.wait("exits in status", func(s fakepanel.State) bool { return s.Status != nil && len(s.Status.Exits) == 1 })

	env, _ = h.panel.Request(h.ctx(), nodeproto.TypePing, nil)
	if env.Type != nodeproto.TypePong {
		t.Errorf("ping reply %q", env.Type)
	}
}

type fakeSmart struct{}

func (fakeSmart) Exits() []nodeproto.ExitStatus {
	return []nodeproto.ExitStatus{{Name: "uk", Country: "GB", Up: true}}
}
func (fakeSmart) RecentLookups(limit int) []nodeproto.RecentLookup {
	return []nodeproto.RecentLookup{{Name: "tv.stream.example", Type: "A", Routed: true}}
}

func TestDetachAndReconnect(t *testing.T) {
	h := newHarness(t)
	h.start()
	// Reconnect after the panel drops the connection.
	h.panel.Drop()
	h.wait("reconnect", func(s fakepanel.State) bool { return s.Connects >= 2 && s.Connected })

	if err := h.panel.Send(h.ctx(), nodeproto.TypeDetach, "", nodeproto.Detach{Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-h.done:
		if !errors.Is(err, ErrDetached) {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not stop after detach")
	}
	if Managed(h.opts.StateDir) {
		t.Error("node.json still present")
	}
	if _, err := os.Stat(h.pipe.ConfigPath); err != nil {
		t.Error("config removed by detach")
	}
	if LoadEndpoint(h.opts.StateDir).Host() == "" {
		t.Error("endpoint removed by detach")
	}
}

func TestLocalDetachStopsAgent(t *testing.T) {
	h := newHarness(t)
	h.start()
	_ = RemoveState(h.opts.StateDir)
	select {
	case err := <-h.done:
		if !errors.Is(err, ErrDetached) {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not notice node.json removal")
	}
	h.wait("detached event", func(s fakepanel.State) bool {
		for _, e := range s.Events {
			if e.Kind == "detached" {
				return true
			}
		}
		return false
	})
}

func TestRestoreSnapshotConfig(t *testing.T) {
	h := newHarness(t)
	h.start()
	if a, _ := h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{}); !a.OK {
		t.Fatal(a.Error)
	}
	h.stop()
	_ = os.WriteFile(h.pipe.ConfigPath, []byte("version: 1\n# local edit\n"), 0o640)
	restored, err := RestoreSnapshotConfig(h.opts.StateDir, h.pipe.ConfigPath)
	if err != nil || !restored {
		t.Fatalf("restored=%v err=%v", restored, err)
	}
	if b, _ := os.ReadFile(h.pipe.ConfigPath); string(b) != testConfig {
		t.Error("not restored")
	}
	if restored, _ := RestoreSnapshotConfig(h.opts.StateDir, h.pipe.ConfigPath); restored {
		t.Error("restored twice")
	}
}

func TestSSHPortGuard(t *testing.T) {
	h := newHarness(t)
	st, _ := LoadState(h.opts.StateDir)
	st.SSHPort = 2222
	_ = SaveState(h.opts.StateDir, st)
	h.start()
	defer h.stop()
	if s := h.panel.State(); s.Hello.SSHPort != 2222 {
		t.Errorf("hello ssh_port = %d", s.Hello.SSHPort)
	}
	a, err := h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{})
	if a.OK || !strings.Contains(a.Error, "lock you out") {
		t.Errorf("snapshot closing SSH accepted: %+v %v", a, err)
	}
	a, _ = h.panel.SendSnapshot(h.ctx(), strings.Replace(testConfig, "  acme:", "  ssh_port: 2222\n  acme:", 1), fakepanel.SnapshotOptions{})
	if !a.OK {
		t.Errorf("snapshot with the right ssh_port rejected: %+v", a)
	}
}

func TestRedelivery(t *testing.T) {
	h := newHarness(t)
	h.start()
	defer h.stop()
	for i := range 2 { // the panel resends the stored snapshot after a reconnect
		if a, err := h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{Revision: 3}); err != nil || !a.OK {
			t.Fatalf("delivery %d: %+v %v", i, a, err)
		}
	}
}

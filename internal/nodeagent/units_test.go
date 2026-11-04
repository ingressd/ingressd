// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

func TestRedactQuery(t *testing.T) {
	for in, want := range map[string]string{
		"/":                     "/",
		"/a?":                   "/a?",
		"/a?token=abc&x=1":      "/a?token=&x=",
		"/a?flag&k=v":           "/a?flag&k=",
		"/a?a%20b=secret":       "/a?a+b=",
		"/p?redirect=/x?y=z":    "/p?redirect=",
		"/search?q=a+b&page=2&": "/search?q=&page=&",
	} {
		if got := RedactQuery(in); got != want {
			t.Errorf("RedactQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func mustConfig(t *testing.T, y string) *config.Config {
	t.Helper()
	c, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHostIndex(t *testing.T) {
	cfg := mustConfig(t, testConfig)
	idx := newHostIndex(cfg)
	for host, want := range map[string]string{
		"web.example.test": "web", "WEB.example.test": "web",
		"a.apps.example.test": "wild", "a.b.apps.example.test": "", "apps.example.test": "",
		"other.test": "",
	} {
		if got := idx.app(host); got != want {
			t.Errorf("app(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestUsageRecord(t *testing.T) {
	q, _ := loadUsage(t.TempDir() + "/u.json")
	cfg := mustConfig(t, testConfig)
	now := time.Now()
	// First interval: WireGuard baselines only, no message.
	u, err := q.record(collector{cfg: cfg, wg: []tunnel.Status{{Tunnel: "home", Up: true, RxBytes: 1000, TxBytes: 500}}}, now)
	if err != nil || u != nil {
		t.Fatalf("first = %+v %v", u, err)
	}
	u, _ = q.record(collector{cfg: cfg,
		hosts: map[string]observe.Totals{"web.example.test": {Requests: 2, BytesOut: 10, Status: [6]int64{0, 0, 2}}},
		wg:    []tunnel.Status{{Tunnel: "home", Up: true, RxBytes: 1500, TxBytes: 700}},
		smart: []nodeproto.ServiceUsage{{Service: "streamtv", Bytes: 99, Conns: 1}},
	}, now.Add(time.Minute))
	if u == nil || u.Seq != 1 || len(u.Apps) != 1 || u.Apps[0].Status2xx != 2 || len(u.Sites) != 1 || u.Sites[0].RxBytes != 500 || u.Sites[0].TxBytes != 200 || len(u.Smart) != 1 {
		t.Fatalf("second = %+v", u)
	}
	if !u.From.Equal(now.UTC()) {
		t.Errorf("from = %v", u.From)
	}
	// Counter reset (interface recreated): the new value is the delta.
	u, _ = q.record(collector{cfg: cfg, wg: []tunnel.Status{{Tunnel: "home", Up: true, RxBytes: 40, TxBytes: 0}}}, now.Add(2*time.Minute))
	if u == nil || u.Seq != 2 || u.Sites[0].RxBytes != 40 {
		t.Fatalf("reset = %+v", u)
	}
	// Persisted across reloads.
	q2, _ := loadUsage(q.path)
	if q2.seq() != 2 || q2.pendingLen() != 2 {
		t.Fatalf("reloaded seq=%d pending=%d", q2.seq(), q2.pendingLen())
	}
	q2.ack(1)
	if q2.pendingLen() != 1 {
		t.Errorf("ack left %d", q2.pendingLen())
	}
}

func TestHealthAndSignature(t *testing.T) {
	ok := []nodeproto.Check{{Name: "x", OK: true}}
	if health(ok) != nodeproto.HealthOK {
		t.Error("ok")
	}
	if health(append(ok, nodeproto.Check{Name: "tunnel home", Warn: true})) != nodeproto.HealthDegraded {
		t.Error("degraded")
	}
	if health(append(ok, nodeproto.Check{Name: checkEdge})) != nodeproto.HealthDown {
		t.Error("down")
	}
	a := nodeproto.Status{Health: "ok", Uptime: 1, DiskFreeBytes: 5}
	b := a
	b.Uptime, b.DiskFreeBytes = 99, 6
	if statusSignature(a) != statusSignature(b) {
		t.Error("counters must not change the signature")
	}
	b.Certs = []nodeproto.CertStatus{{Host: "a", State: nodeproto.CertValid}}
	if statusSignature(a) == statusSignature(b) {
		t.Error("cert state must change the signature")
	}
}

func selfSigned(t *testing.T, notAfter time.Time, names ...string) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, Issuer: pkix.Name{CommonName: "Test CA"},
		DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestCertState(t *testing.T) {
	now := time.Now()
	certs := []*x509.Certificate{selfSigned(t, now.Add(48*time.Hour), "a.test"), selfSigned(t, now.Add(-time.Minute), "old.test"), selfSigned(t, now.Add(time.Hour), "*.w.test")}
	cases := []struct {
		host, failure, state string
	}{
		{"a.test", "", nodeproto.CertValid},
		{"x.w.test", "", nodeproto.CertValid},
		{"b.test", "", nodeproto.CertIssuing},
		{"b.test", "acme: rate limited", nodeproto.CertFailed},
		{"old.test", "", nodeproto.CertIssuing},
		{"a.test", "stale error", nodeproto.CertValid},
	}
	for _, c := range cases {
		got := CertState(certs, c.host, now, c.failure)
		if got.State != c.state {
			t.Errorf("%s (%q): %s, want %s", c.host, c.failure, got.State, c.state)
		}
	}
	// Caddy log events drive the failure map.
	ObserveCaddyEvent(observe.LogEvent{Logger: "tls.obtain", Level: "error", Msg: "could not get certificate from issuer", Fields: map[string]any{"identifier": "Fail.test", "error": "HTTP 429 urn:ietf:params:acme:error:rateLimited"}})
	if f := certFailures.failure("fail.test"); !strings.Contains(f, "rateLimited") {
		t.Errorf("failure = %q", f)
	}
	ObserveCaddyEvent(observe.LogEvent{Logger: "tls.obtain", Level: "info", Msg: "certificate obtained successfully", Fields: map[string]any{"identifier": "fail.test"}})
	if f := certFailures.failure("fail.test"); f != "" {
		t.Errorf("failure not cleared: %q", f)
	}
}

func originCfg(t *testing.T, origin string) *config.Config {
	return mustConfig(t, fmt.Sprintf("version: 1\napps:\n  web:\n    hosts: [web.example.test]\n    origin: %s\n", origin))
}

func TestDiagnoseOrigin(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "web.example.test" {
			w.WriteHeader(400)
		}
	}))
	defer ok.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }))
	defer broken.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsSrv.Close()
	silent, _ := net.Listen("tcp", "127.0.0.1:0")
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	closed.Close()
	notTLS := ok.URL

	cases := map[string]struct{ origin, code string }{
		"ok":         {ok.URL, nodeproto.DiagCodeOK},
		"http_error": {broken.URL, nodeproto.DiagCodeHTTPError},
		"https ok":   {tlsSrv.URL, nodeproto.DiagCodeOK},
		"tls_error":  {strings.Replace(notTLS, "http://", "https://", 1), nodeproto.DiagCodeTLSError},
		"timeout":    {"http://" + silent.Addr().String(), nodeproto.DiagCodeTimeout},
		"refused":    {"http://" + closedAddr, nodeproto.DiagCodeRefused},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			r := DiagnoseOrigin(ctx, originCfg(t, c.origin), "web", 2*time.Second)
			if r.Code != c.code {
				t.Errorf("code = %s (%s), want %s; steps %+v", r.Code, r.Message, c.code, r.Steps)
			}
			if len(r.Steps) == 0 {
				t.Error("no steps")
			}
		})
	}
}

func TestDiagnoseOriginTunnel(t *testing.T) {
	cfg := mustConfig(t, testConfig)
	defer func() { readTunnelStatus = tunnel.ReadStatus }()
	readTunnelStatus = func(*config.Config) ([]tunnel.Status, error) {
		return []tunnel.Status{{Tunnel: "home", Up: true}}, nil
	}
	r := DiagnoseOrigin(context.Background(), cfg, "web", time.Second)
	if r.Code != nodeproto.DiagCodeTunnelDown || len(r.Steps) != 2 || r.Steps[1].Name != "tunnel" {
		t.Errorf("no handshake: %+v", r)
	}
	if r := DiagnoseOrigin(context.Background(), cfg, "nope", time.Second); r.Code != "error" {
		t.Errorf("unknown app: %+v", r)
	}
	if r := diagnoseTunnel(cfg, nodeproto.DiagRequest{App: "web"}); r.Code != nodeproto.DiagCodeTunnelDown {
		t.Errorf("tunnel diag: %+v", r)
	}
	readTunnelStatus = func(*config.Config) ([]tunnel.Status, error) {
		return []tunnel.Status{{Tunnel: "home", Up: true, LastHandshake: time.Now()}}, nil
	}
	if r := diagnoseTunnel(cfg, nodeproto.DiagRequest{Host: "home"}); r.Code != nodeproto.DiagCodeOK {
		t.Errorf("tunnel diag up: %+v", r)
	}
}

func TestClassifyDialError(t *testing.T) {
	_, err := (&net.Dialer{Timeout: time.Millisecond}).Dial("tcp", "192.0.2.1:9")
	if err == nil {
		t.Skip("unexpectedly connected")
	}
	if code, _ := classifyDialError(err); code != nodeproto.DiagCodeNoReply {
		t.Errorf("timeout → %s (%v)", code, err)
	}
}

func TestIsPublic(t *testing.T) {
	for a, want := range map[string]bool{"8.8.8.8": true, "10.0.0.1": false, "192.168.1.1": false, "100.64.0.1": false, "127.0.0.1": false} {
		if got := IsPublic(mustAddr(a)); got != want {
			t.Errorf("%s: %v", a, got)
		}
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

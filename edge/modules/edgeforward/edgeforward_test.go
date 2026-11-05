// SPDX-License-Identifier: Apache-2.0

package edgeforward

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"

	"github.com/ingressd/ingressd/edge/modules/edgestate"
)

var (
	secret = []byte("0123456789abcdef0123456789abcdef")
	t0     = time.Unix(1_800_000_000, 0)
)

func TestHopSignVerify(t *testing.T) {
	h := SignHop(secret, "10.255.0.1", "tq7k2m.nas", t0)
	node, app, err := VerifyHop(secret, h, t0.Add(29*time.Second), DefaultMaxAge)
	if err != nil || node != "10.255.0.1" || app != "tq7k2m.nas" {
		t.Fatalf("VerifyHop = %q, %q, %v", node, app, err)
	}
	if _, _, err := VerifyHop(secret, h, t0.Add(-29*time.Second), DefaultMaxAge); err != nil {
		t.Errorf("small clock skew refused: %v", err)
	}
	parts := strings.Split(h, ";")
	tamper := func(i int, v string) string {
		p := append([]string(nil), parts...)
		p[i] = v
		return strings.Join(p, ";")
	}
	for name, tc := range map[string]struct {
		hdr  string
		now  time.Time
		want error
	}{
		"empty":         {"", t0, errNoHop},
		"garbage":       {"hello", t0, errBadHop},
		"wrong version": {tamper(0, "v2"), t0, errBadHop},
		"other app":     {tamper(2, "tb4x9p.nas"), t0, errBadMAC},
		"other node":    {tamper(1, "10.255.0.9"), t0, errBadMAC},
		"moved stamp":   {tamper(3, "1800000100"), t0, errBadMAC},
		"other secret":  {SignHop([]byte("another-secret-of-32-bytes-xxxxx"), "10.255.0.1", "tq7k2m.nas", t0), t0, errBadMAC},
		"expired":       {h, t0.Add(31 * time.Second), errStaleHop},
		"from future":   {h, t0.Add(-31 * time.Second), errStaleHop},
	} {
		if _, _, err := VerifyHop(secret, tc.hdr, tc.now, DefaultMaxAge); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

func withVars(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
}

func newVerify(t *testing.T) *Verify {
	t.Helper()
	v := &Verify{Secret: string(secret), Self: "10.255.0.2", Peers: []string{"10.255.0.1", "10.255.0.3"}, now: func() time.Time { return t0 }}
	if err := v.setup(); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyHandler(t *testing.T) {
	v := newVerify(t)
	req := func(remote, hop string) *http.Request {
		r := withVars(httptest.NewRequest("GET", "http://nas.alice.example/x", nil))
		r.RemoteAddr = remote + ":40000"
		if hop != "" {
			r.Header.Set(HopHeader, hop)
		}
		return r
	}
	for name, tc := range map[string]struct {
		r    *http.Request
		code int
	}{
		"unsigned":          {req("10.255.0.1", ""), http.StatusForbidden},
		"bad signature":     {req("10.255.0.1", SignHop([]byte("another-secret-of-32-bytes-xxxxx"), "10.255.0.1", "nas", t0)), http.StatusForbidden},
		"stale":             {req("10.255.0.1", SignHop(secret, "10.255.0.1", "nas", t0.Add(-time.Minute))), http.StatusForbidden},
		"own hop (loop)":    {req("10.255.0.1", SignHop(secret, "10.255.0.2", "nas", t0)), http.StatusLoopDetected},
		"not a peer":        {req("10.255.0.9", SignHop(secret, "10.255.0.9", "nas", t0)), http.StatusForbidden},
		"replayed by other": {req("10.255.0.3", SignHop(secret, "10.255.0.1", "nas", t0)), http.StatusForbidden},
	} {
		called := false
		err := v.ServeHTTP(httptest.NewRecorder(), tc.r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			called = true
			return nil
		}))
		var he caddyhttp.HandlerError
		if called || !errors.As(err, &he) || he.StatusCode != tc.code {
			t.Errorf("%s: called=%v err=%v, want HTTP %d", name, called, err, tc.code)
		}
	}

	r := req("10.255.0.1", SignHop(secret, "10.255.0.1", "tq7k2m.nas", t0))
	var app string
	err := v.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		app, _ = caddyhttp.GetVar(r.Context(), VarApp).(string)
		if r.Header.Get(HopHeader) != "" {
			t.Error("hop header passed on to the origin")
		}
		return nil
	}))
	if err != nil || app != "tq7k2m.nas" {
		t.Errorf("valid hop: app %q, err %v", app, err)
	}
}

type recordRT struct{ reqs []*http.Request }

func (rt *recordRT) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.reqs = append(rt.reqs, r.Clone(r.Context()))
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

func newTransport(t *testing.T) (*Transport, *recordRT) {
	t.Helper()
	tr := &Transport{Forward: Hop{Secret: string(secret), Node: "10.255.0.1", App: "nas", Siblings: []string{"10.255.0.2:51880"}}, now: func() time.Time { return t0 }}
	if err := tr.setup(); err != nil {
		t.Fatal(err)
	}
	rec := &recordRT{}
	tr.HTTPTransport.Transport = &http.Transport{}
	tr.HTTPTransport.Transport.RegisterProtocol("http", rec)
	tr.HTTPTransport.Transport.RegisterProtocol("https", rec)
	return tr, rec
}

func TestTransportSignsSiblingRequests(t *testing.T) {
	tr, rec := newTransport(t)
	r := withVars(httptest.NewRequest("GET", "https://nas.example.com/", nil))
	r.URL = &url.URL{Scheme: "https", Host: "10.255.0.2:51880", Path: "/"}
	if _, err := tr.RoundTrip(r); err != nil {
		t.Fatal(err)
	}
	got := rec.reqs[0]
	if got.URL.Scheme != "http" {
		t.Errorf("sibling request scheme %q, want plain http over the mesh", got.URL.Scheme)
	}
	node, app, err := VerifyHop(secret, got.Header.Get(HopHeader), t0, DefaultMaxAge)
	if err != nil || node != "10.255.0.1" || app != "nas" {
		t.Errorf("hop header %q: %q %q %v", got.Header.Get(HopHeader), node, app, err)
	}

	// Local origins never see a hop header, even one a client sent.
	r = withVars(httptest.NewRequest("GET", "http://nas.example.com/", nil))
	r.URL = &url.URL{Scheme: "http", Host: "192.168.0.10:5000", Path: "/"}
	r.Header.Set(HopHeader, "v1;forged")
	if _, err := tr.RoundTrip(r); err != nil {
		t.Fatal(err)
	}
	if h := rec.reqs[1].Header.Get(HopHeader); h != "" {
		t.Errorf("local origin got hop header %q", h)
	}
}

func TestTransportRefusesSecondHop(t *testing.T) {
	tr, rec := newTransport(t)
	r := withVars(httptest.NewRequest("GET", "http://nas.example.com/", nil))
	caddyhttp.SetVar(r.Context(), VarApp, "nas")
	r.URL = &url.URL{Scheme: "http", Host: "10.255.0.2:51880", Path: "/"}
	if _, err := tr.RoundTrip(r); !errors.Is(err, errLoop) {
		t.Errorf("forwarded request forwarded again: %v", err)
	}
	if len(rec.reqs) != 0 {
		t.Error("request reached the sibling")
	}
}

type firstAvail struct{ down map[string]bool }

func (f firstAvail) Select(pool reverseproxy.UpstreamPool, _ *http.Request, _ http.ResponseWriter) *reverseproxy.Upstream {
	for _, u := range pool {
		if !f.down[u.Dial] {
			return u
		}
	}
	return nil
}

func TestSelection(t *testing.T) {
	store := &edgestate.Store{}
	down := map[string]bool{}
	s := &Selection{
		Tunnels:  map[string]string{"10.0.4.10:5000": "tq7k2m01"},
		Siblings: []string{"10.255.0.2:51880", "10.255.0.3:51880"},
		local:    firstAvail{down},
		store:    store,
		avail:    func(u *reverseproxy.Upstream) bool { return !down[u.Dial] },
	}
	s.setup()
	pool := reverseproxy.UpstreamPool{}
	for _, d := range []string{"10.0.4.10:5000", "10.255.0.2:51880", "10.255.0.3:51880"} {
		pool = append(pool, &reverseproxy.Upstream{Dial: d, Host: new(reverseproxy.Host)})
	}
	pick := func(forwarded bool) string {
		r := withVars(httptest.NewRequest("GET", "http://nas/", nil))
		if forwarded {
			caddyhttp.SetVar(r.Context(), VarApp, "nas")
		}
		if u := s.Select(pool, r, httptest.NewRecorder()); u != nil {
			return u.Dial
		}
		return ""
	}

	if got := pick(false); got != "10.0.4.10:5000" {
		t.Errorf("tunnel up: %s, want the local origin", got)
	}
	store.Set(edgestate.State{Tunnels: map[string]edgestate.TunnelState{"tq7k2m01": {Down: true}}})
	if got := pick(false); got != "10.255.0.2:51880" {
		t.Errorf("tunnel down: %s, want the first sibling", got)
	}
	down["10.255.0.2:51880"] = true
	if got := pick(false); got != "10.255.0.3:51880" {
		t.Errorf("first sibling unavailable: %s, want the second", got)
	}
	if got := pick(true); got != "" {
		t.Errorf("forwarded request with its tunnel down went to %s", got)
	}
	// Passive health (failed dials) alone also moves traffic to a sibling.
	store.Set(edgestate.State{})
	down["10.0.4.10:5000"], down["10.255.0.2:51880"] = true, false
	if got := pick(false); got != "10.255.0.2:51880" {
		t.Errorf("local dial failing: %s, want the first sibling", got)
	}
}

// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

func TestDiscoveryRequestAndReport(t *testing.T) {
	s, ts := newTestServer(t, 51822)
	tok, _ := s.Store.CreateToken("cloud", time.Now())
	_, er := enroll(t, ts.URL, tok)
	auth := proto.Bearer("cloud", er.Credential)
	var forwarded []proto.DiscoveryReport
	s.OnDiscovery = func(tunnel string, rep proto.DiscoveryReport) {
		if tunnel == "cloud" {
			forwarded = append(forwarded, rep)
		}
	}

	// poll: discover is nil for an old connector (no parameter).
	poll := func(discover *string, wait string) (int, proto.TunnelConfig) {
		q := url.Values{"rev": {er.Config.Revision}, "wait": {wait}}
		if discover != nil {
			q.Set(proto.DiscoverParam, *discover)
		}
		req, _ := http.NewRequest("GET", ts.URL+proto.PollPath+"?"+q.Encode(), nil)
		req.Header.Set("Authorization", auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var tc proto.TunnelConfig
		if resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(resp.Body).Decode(&tc)
		}
		return resp.StatusCode, tc
	}
	none := ""

	if _, err := s.RequestDiscovery("nosuch"); err == nil {
		t.Error("discovery for an unknown tunnel accepted")
	}
	// A waiting poll is woken by the request.
	type result struct {
		code int
		tc   proto.TunnelConfig
	}
	done := make(chan result, 1)
	go func() { c, tc := poll(&none, "10s"); done <- result{c, tc} }()
	time.Sleep(200 * time.Millisecond)
	id, err := s.RequestDiscovery("cloud")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.code != http.StatusOK || r.tc.DiscoverID != id || r.tc.Revision != er.Config.Revision {
			t.Errorf("woken poll: %d %+v, want discover_id %s", r.code, r.tc, id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not wake the poll")
	}
	if code, _ := poll(nil, "100ms"); code != http.StatusNoContent {
		t.Errorf("old connector got a discovery request: %d", code)
	}
	seen := id
	if code, _ := poll(&seen, "100ms"); code != http.StatusNoContent {
		t.Errorf("request delivered twice: %d", code)
	}

	rep := proto.DiscoveryReport{ID: id, Subnets: []string{"192.168.0.0/24"}, Services: []proto.DiscoveredService{
		{Address: "192.168.0.17", Port: 8080, Scheme: "http", Title: "Grafana", Server: "nginx"},
	}}
	b, _ := json.Marshal(rep)
	req, _ := http.NewRequest("POST", ts.URL+proto.DiscoveryPath, bytes.NewReader(b))
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("report: %v %v", resp.Status, err)
	}
	d, err := s.Store.DiscoveryState("cloud")
	if err != nil || d == nil || d.Pending != "" || d.Last == nil || d.Last.Services[0].Title != "Grafana" || d.ReceivedAt.IsZero() {
		t.Errorf("stored state = %+v, %v", d, err)
	}
	if len(forwarded) != 1 || forwarded[0].ID != id {
		t.Errorf("OnDiscovery got %+v", forwarded)
	}

	req, _ = http.NewRequest("POST", ts.URL+proto.DiscoveryPath, bytes.NewReader(b))
	req.Header.Set("Authorization", proto.Bearer("cloud", "wrong"))
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("report with a bad credential: %s", resp.Status)
	}

	// A connector that reports Discovery=false refuses requests.
	if err := s.Store.Report("cloud", proto.Health{Mode: "tun"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestDiscovery("cloud"); !errors.Is(err, ErrDiscoveryUnsupported) {
		t.Errorf("request to a --no-discovery connector: err = %v", err)
	}
	if err := s.Store.Report("cloud", proto.Health{Mode: "tun", Discovery: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestDiscovery("cloud"); err != nil {
		t.Errorf("request after Discovery=true: %v", err)
	}
}

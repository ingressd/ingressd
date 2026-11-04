// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func caddyLog(ts time.Time, host, uri string, status int, size int64) string {
	return fmt.Sprintf(`{"level":"info","ts":%f,"logger":"http.log.access.ingressd_access","msg":"handled request",`+
		`"request":{"remote_ip":"10.0.0.1","remote_port":"5555","client_ip":"198.51.100.2","proto":"HTTP/2.0","method":"GET",`+
		`"host":"%s","uri":"%s","headers":{"User-Agent":["curl/8.5"]}},"bytes_read":3,"user_id":"","duration":0.0025,`+
		`"size":%d,"status":%d,"resp_headers":{}}`, float64(ts.UnixNano())/1e9, host, uri, size, status)
}

func TestParseLine(t *testing.T) {
	ts := time.Date(2026, 11, 2, 12, 0, 0, 500_000_000, time.UTC)
	e, ev, err := parseLine([]byte(caddyLog(ts, "Web.Example.com:443", "/a?b=1", 404, 12)))
	if err != nil || ev != nil {
		t.Fatal(err, ev)
	}
	want := Entry{Time: e.Time, Host: "web.example.com", Method: "GET", Path: "/a?b=1", Proto: "HTTP/2.0", Status: 404,
		Bytes: 12, BytesIn: 3, Duration: 2500 * time.Microsecond, ClientIP: "198.51.100.2", UA: "curl/8.5"}
	if *e != want {
		t.Fatalf("got %+v\nwant %+v", *e, want)
	}
	if d := e.Time.Sub(ts); d > time.Millisecond || d < -time.Millisecond {
		t.Errorf("time %v, want %v", e.Time, ts)
	}

	_, ev, err = parseLine([]byte(`{"level":"error","ts":1,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"a.example.com","error":"boom"}`))
	if err != nil || ev == nil || ev.Logger != "tls.obtain" || ev.Fields["identifier"] != "a.example.com" {
		t.Fatalf("event = %+v, %v", ev, err)
	}
	if _, _, err := parseLine([]byte("not json")); err == nil {
		t.Error("expected error")
	}
}

func TestFilter(t *testing.T) {
	e := Entry{Host: "a.com", Status: 503, Path: "/api/x", Method: "POST", ClientIP: "1.2.3.4", Time: time.Unix(100, 0)}
	match := []Filter{{}, {Host: "A.com"}, {Status: "5xx"}, {Status: "500-599"}, {Status: "503"}, {Path: "/api"}, {Method: "post"},
		{Since: time.Unix(50, 0), Until: time.Unix(101, 0)}}
	for _, f := range match {
		if !f.Match(e) {
			t.Errorf("%+v should match", f)
		}
	}
	noMatch := []Filter{{Host: "b.com"}, {Status: "4xx"}, {Status: "200"}, {Path: "/web"}, {ClientIP: "9.9.9.9"}, {Since: time.Unix(101, 0)}}
	for _, f := range noMatch {
		if f.Match(e) {
			t.Errorf("%+v should not match", f)
		}
	}
	if err := (Filter{Status: "abc"}).Validate(); err == nil {
		t.Error("expected invalid status error")
	}
}

func newTestObserver(t *testing.T) (*Observer, *Store) {
	t.Helper()
	st, err := OpenStore(filepath.Join(t.TempDir(), "observe.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	o := New(Options{Store: st, RingSize: 5})
	o.Configure([]string{"a.com", "*.lab.com"}, 1, 24*time.Hour)
	return o, st
}

func TestStoreQueryStatsTop(t *testing.T) {
	o, st := newTestObserver(t)
	ctx := context.Background()
	base := time.Now().Add(-10 * time.Minute).Truncate(time.Minute)
	add := func(min int, host, uri string, status int) {
		o.Ingest([]byte(caddyLog(base.Add(time.Duration(min)*time.Minute), host, uri, status, 100)))
	}
	add(0, "a.com", "/", 200)
	add(0, "a.com", "/x", 404)
	add(1, "a.com", "/x", 500)
	add(1, "x.lab.com", "/", 200)
	add(2, "scanner.invalid", "/wp-login.php", 404)
	o.Flush()

	es, err := st.Query(ctx, Filter{Host: "a.com"})
	if err != nil || len(es) != 3 || es[0].Status != 500 {
		t.Fatalf("Query = %+v, %v", es, err)
	}
	es, _ = st.Query(ctx, Filter{Status: "4xx"})
	if len(es) != 2 {
		t.Fatalf("4xx = %d entries", len(es))
	}
	es, _ = st.Query(ctx, Filter{Limit: 1})
	if len(es) != 1 || es[0].Host != "scanner.invalid" {
		t.Fatalf("limit/newest = %+v", es)
	}

	s, err := st.Stats(ctx, StatsQuery{Since: base.Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if s.Totals.Requests != 5 || s.Totals.Status[2] != 2 || s.Totals.Status[4] != 2 || s.Totals.Status[5] != 1 || s.Totals.BytesOut != 500 {
		t.Fatalf("totals = %+v", s.Totals)
	}
	hosts := map[string]int64{}
	for _, h := range s.Hosts {
		hosts[h.Host] = h.Requests
	}
	if hosts["a.com"] != 3 || hosts["*.lab.com"] != 1 || hosts[OtherHost] != 1 || s.Hosts[0].Host != "a.com" {
		t.Fatalf("hosts = %+v", s.Hosts)
	}
	if len(s.Series) != 3 || s.Series[0].Requests != 2 {
		t.Fatalf("series = %+v", s.Series)
	}
	if s.Totals.AvgLatency != 2500*time.Microsecond {
		t.Errorf("avg latency %v", s.Totals.AvgLatency)
	}

	top, err := st.Top(ctx, Filter{}, TopPath, 2)
	if err != nil || len(top) != 2 || top[0] != (Count{"/", 2}) || top[1] != (Count{"/x", 2}) {
		t.Fatalf("Top = %+v, %v", top, err)
	}
	if _, err := st.Top(ctx, Filter{}, "ua; drop table", 2); err == nil {
		t.Error("Top accepted an unknown field")
	}

	// Aggregates accumulate across flushes.
	add(0, "a.com", "/", 200)
	o.Flush()
	s, _ = st.Stats(ctx, StatsQuery{Since: base.Add(-time.Minute), Host: "a.com"})
	if s.Totals.Requests != 4 {
		t.Fatalf("after second flush: %+v", s.Totals)
	}

	// Retention prunes entries but keeps aggregates.
	if err := st.Prune(ctx, time.Now().Add(48*time.Hour), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	es, _ = st.Query(ctx, Filter{})
	s, _ = st.Stats(ctx, StatsQuery{Since: base.Add(-time.Minute)})
	if len(es) != 0 || s.Totals.Requests != 6 {
		t.Fatalf("after prune: %d entries, %d aggregated", len(es), s.Totals.Requests)
	}
}

func TestSampling(t *testing.T) {
	o, st := newTestObserver(t)
	o.Configure(nil, 0.000001, time.Hour)
	for i := 0; i < 50; i++ {
		o.Add(Entry{Time: time.Now(), Host: "a.com", Status: 200})
	}
	o.Flush()
	es, _ := st.Query(context.Background(), Filter{})
	s, _ := st.Stats(context.Background(), StatsQuery{})
	if len(es) > 2 || s.Totals.Requests != 50 {
		t.Fatalf("sampling: %d stored, %d counted", len(es), s.Totals.Requests)
	}
}

func TestRingAndSubscribe(t *testing.T) {
	o := New(Options{RingSize: 3})
	for i := 0; i < 5; i++ {
		o.Add(Entry{Host: "a.com", Status: 200 + i})
	}
	r := o.Recent(Filter{}, 10)
	if len(r) != 3 || r[0].Status != 202 || r[2].Status != 204 {
		t.Fatalf("Recent = %+v", r)
	}
	if r := o.Recent(Filter{Status: "203"}, 10); len(r) != 1 {
		t.Fatalf("filtered Recent = %+v", r)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := o.Subscribe(ctx, Filter{Host: "b.com"})
	o.Add(Entry{Host: "a.com"})
	o.Add(Entry{Host: "b.com", Status: 418})
	select {
	case e := <-ch:
		if e.Status != 418 {
			t.Fatalf("got %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no entry")
	}
	cancel()
	for range ch {
	}
}

func TestListenAndHandler(t *testing.T) {
	o, _ := newTestObserver(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sock := filepath.Join(t.TempDir(), "log.sock")
	if err := o.Listen(ctx, sock); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(c, caddyLog(time.Now(), "a.com", "/hello", 200, 5))
	fmt.Fprintln(c, caddyLog(time.Now(), "a.com", "/missing", 404, 5))
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for o.Ingested() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	o.Flush()

	reg := NewRegistry()
	reg.Register(o.Collector())
	srv := httptest.NewServer(o.Handler(reg))
	defer srv.Close()

	var es []Entry
	getJSON(t, srv.URL+"/v1/logs?status=404", &es)
	if len(es) != 1 || es[0].Path != "/missing" {
		t.Fatalf("logs = %+v", es)
	}
	var s Stats
	getJSON(t, srv.URL+"/v1/stats?since=1h", &s)
	if s.Totals.Requests != 2 {
		t.Fatalf("stats = %+v", s.Totals)
	}
	resp, err := http.Get(srv.URL + "/v1/logs?status=nope")
	if err != nil || resp.StatusCode != 400 {
		t.Fatalf("bad filter: %v %v", resp.StatusCode, err)
	}

	resp, err = http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b := new(strings.Builder)
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		b.WriteString(sc.Text() + "\n")
	}
	resp.Body.Close()
	for _, want := range []string{
		`ingressd_http_requests_total{host="a.com",code="2xx"} 1`,
		`ingressd_http_requests_total{host="a.com",code="4xx"} 1`,
		`ingressd_http_response_bytes_total{host="a.com"} 10`,
		"# TYPE ingressd_http_requests_total counter",
		"ingressd_access_log_lines_total 2",
		"ingressd_build_info{version=",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("metrics missing %q:\n%s", want, b)
		}
	}
	if strings.Count(b.String(), "# TYPE ingressd_http_requests_total") != 1 {
		t.Error("TYPE line repeated")
	}

	// Live tail: ring entries first, then new ones.
	fctx, fcancel := context.WithTimeout(ctx, 3*time.Second)
	defer fcancel()
	req, _ := http.NewRequestWithContext(fctx, "GET", srv.URL+"/v1/logs?follow=1&limit=1", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc = bufio.NewScanner(resp.Body)
	var got []Entry
	for len(got) < 2 && sc.Scan() {
		var e Entry
		_ = json.Unmarshal(sc.Bytes(), &e)
		got = append(got, e)
		if len(got) == 1 {
			o.Add(Entry{Host: "a.com", Path: "/live", Status: 200, Time: time.Now()})
		}
	}
	if len(got) != 2 || got[0].Path != "/missing" || got[1].Path != "/live" {
		t.Fatalf("follow = %+v", got)
	}
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func TestParseTime(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.Local)
	for in, want := range map[string]time.Time{
		"15m":              now.Add(-15 * time.Minute),
		"7d":               now.AddDate(0, 0, -7),
		"2026-11-01":       time.Date(2026, 11, 1, 0, 0, 0, 0, time.Local),
		"2026-11-01 08:30": time.Date(2026, 11, 1, 8, 30, 0, 0, time.Local),
	} {
		got, err := ParseTime(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseTime(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
}

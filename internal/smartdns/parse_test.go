// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// clientHello captures the ClientHello crypto/tls sends for serverName.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Handshake()
		a.Close()
	}()
	b.SetDeadline(time.Now().Add(2 * time.Second))
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := b.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if _, perr := sniFromHello(buf); !errors.Is(perr, errNeedMore) || err != nil {
			break
		}
	}
	b.Close()
	return buf
}

func TestSNIFromHello(t *testing.T) {
	hello := clientHello(t, "TV.Stream.example")
	got, err := sniFromHello(hello)
	if err != nil || got != "tv.stream.example" {
		t.Fatalf("sni = %q, %v", got, err)
	}
	// Every strict prefix needs more data.
	for _, n := range []int{0, 3, 5, 40, len(hello) - 1} {
		if _, err := sniFromHello(hello[:n]); !errors.Is(err, errNeedMore) {
			t.Errorf("prefix %d: err = %v, want errNeedMore", n, err)
		}
	}
	// IP-literal connections send no SNI.
	noSNI := clientHello(t, "")
	if got, err := sniFromHello(noSNI); err != nil || got != "" {
		t.Errorf("no SNI: %q, %v", got, err)
	}
	if _, err := sniFromHello([]byte("GET / HTTP/1.1\r\n\r\n")); err == nil || errors.Is(err, errNeedMore) {
		t.Errorf("plain HTTP accepted as TLS: %v", err)
	}
	// A handshake record that is not a ClientHello.
	if _, err := sniFromHello([]byte{0x16, 3, 1, 0, 4, 2, 0, 0, 0}); err == nil {
		t.Error("ServerHello accepted")
	}
	// Corrupt lengths must not panic.
	bad := bytes.Clone(hello)
	for i := 9; i < len(bad) && i < 200; i += 7 {
		c := bytes.Clone(bad)
		c[i] = 0xff
		sniFromHello(c)
	}
}

func TestHostFromHTTP(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		more     bool
	}{
		{"GET / HTTP/1.1\r\nHost: TV.stream.example\r\n\r\n", "tv.stream.example", false},
		{"GET / HTTP/1.1\r\nUser-Agent: x\r\nhost:  example.com:8080 \r\nAccept: */*\r\n\r\nbody", "example.com", false},
		{"GET / HTTP/1.1\r\nHost: example.com.\r\n\r\n", "example.com", false},
		{"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", "", false},
		{"GET / HTTP/1.1\r\nHost: example.com\r\n", "", true},
	} {
		got, err := hostFromHTTP([]byte(tc.in))
		if tc.more {
			if !errors.Is(err, errNeedMore) {
				t.Errorf("%q: err = %v, want errNeedMore", tc.in, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: got %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := hostFromHTTP([]byte(strings.Repeat("a", 20000))); err == nil || errors.Is(err, errNeedMore) {
		t.Error("oversized head not rejected")
	}
}

func TestMatcher(t *testing.T) {
	off := false
	m := newMatcher(&config.SmartDNS{Services: map[string]config.SmartDNSService{
		"streamtv": {Domains: []string{"stream.example", "streamtv.example"}, Exit: "nl"},
		"video":    {Domains: []string{"video.stream.example"}, Exit: "de"},
		"off":      {Domains: []string{"disabled.test"}, Exit: "nl", Enabled: &off},
	}})
	for name, want := range map[string]string{
		"stream.example":              "streamtv/nl",
		"TV.Stream.EXAMPLE.":          "streamtv/nl",
		"a.b.streamtv.example":        "streamtv/nl",
		"video.stream.example":        "video/de", // longest suffix wins
		"cdn.video.stream.example":    "video/de",
		"notstream.example":           "",
		"stream.example.evil.example": "",
		"disabled.test":               "",
		"com":                         "",
	} {
		r, ok := m.match(name)
		got := ""
		if ok {
			got = r.Service + "/" + strings.Join(r.Exits, ",")
		}
		if got != want {
			t.Errorf("match(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestCacheSWR(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newCache()
	c.now = func() time.Time { return now }
	k := cacheKey{"nl", "tv.stream.example"}
	if _, s := c.get(k); s != cacheMiss {
		t.Fatal("empty cache hit")
	}
	c.put(k, answer{Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, TTL: 5 * time.Second})
	if _, s := c.get(k); s != cacheFresh {
		t.Fatalf("state %v, want fresh", s)
	}
	now = now.Add(cacheMinTTL - time.Second) // short TTLs are floored
	if _, s := c.get(k); s != cacheFresh {
		t.Fatalf("state %v, want fresh (TTL floor)", s)
	}
	now = now.Add(2 * time.Second)
	if a, s := c.get(k); s != cacheStale || len(a.Addrs) != 1 {
		t.Fatalf("state %v, want stale", s)
	}
	if !c.startRefresh(k) || c.startRefresh(k) {
		t.Error("only one refresh per key may run")
	}
	c.endRefresh(k)
	now = now.Add(staleMax)
	if _, s := c.get(k); s != cacheMiss {
		t.Fatalf("state %v, want miss after 24h stale", s)
	}
	c.put(k, answer{}) // empty answers are not cached
	if _, s := c.get(k); s != cacheMiss {
		t.Fatal("empty answer cached")
	}
}

func TestFraming(t *testing.T) {
	var buf bytes.Buffer
	req := ConnectRequest{Exit: "nl", Service: "streamtv", Host: "tv.stream.example", Port: 443, Addrs: []netip.Addr{netip.MustParseAddr("18.239.36.1")}}
	if err := WriteConnectRequest(&buf, req); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("HER1")) {
		t.Fatal("missing magic")
	}
	buf.WriteString("raw stream bytes")
	got, err := ReadConnectRequest(&buf)
	if err != nil || got.Host != req.Host || got.Port != 443 || got.Addrs[0] != req.Addrs[0] || got.Exit != "nl" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if buf.String() != "raw stream bytes" {
		t.Errorf("reader consumed stream bytes: %q", buf.String())
	}

	buf.Reset()
	WriteConnectResponse(&buf, ConnectResponse{OK: true, Addr: "18.239.36.1"})
	if r, err := ReadConnectResponse(&buf); err != nil || !r.OK || r.Addr != "18.239.36.1" {
		t.Fatalf("response %+v, %v", r, err)
	}

	if _, err := ReadConnectRequest(strings.NewReader("GET / HTTP/1.1\r\n")); err == nil {
		t.Error("bad magic accepted")
	}
	if _, err := ReadConnectRequest(bytes.NewReader([]byte{'H', 'E', 'R', '1', 0xff, 0xff})); err == nil {
		t.Error("oversized frame accepted")
	}
	if err := WriteConnectRequest(&buf, ConnectRequest{Host: strings.Repeat("a", 5000)}); err == nil {
		t.Error("oversized frame written")
	}
}

func TestCheckConnect(t *testing.T) {
	ok := ConnectRequest{Exit: "nl", Host: "tv.stream.example", Port: 443, Addrs: []netip.Addr{netip.MustParseAddr("18.239.36.1")}}
	if err := checkConnect(ok); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*ConnectRequest){
		"port 22":    func(r *ConnectRequest) { r.Port = 22 },
		"no host":    func(r *ConnectRequest) { r.Host = "" },
		"no addrs":   func(r *ConnectRequest) { r.Addrs = nil },
		"loopback":   func(r *ConnectRequest) { r.Addrs = []netip.Addr{netip.MustParseAddr("127.0.0.1")} },
		"lan":        func(r *ConnectRequest) { r.Addrs = []netip.Addr{netip.MustParseAddr("192.168.1.10")} },
		"cgnat/mesh": func(r *ConnectRequest) { r.Addrs = []netip.Addr{netip.MustParseAddr("100.64.0.1")} },
		"link-local": func(r *ConnectRequest) { r.Addrs = []netip.Addr{netip.MustParseAddr("169.254.169.254")} },
		"ipv6":       func(r *ConnectRequest) { r.Addrs = []netip.Addr{netip.MustParseAddr("2001:db8::1")} },
	} {
		r := ok
		mod(&r)
		if err := checkConnect(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

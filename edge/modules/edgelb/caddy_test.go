// SPDX-License-Identifier: Apache-2.0

package edgelb

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

// Ports are unique to this package so caddytests in other packages (and
// other checkouts) can run concurrently.
const (
	adminPort = 2961
	proxyPort = 9161
)

const caddyConfig = `{
  "admin": {"listen": "localhost:%[1]d"},
  "apps": {
    "http": {
      "servers": {
        "a": {"listen": [":9162"], "routes": [{"handle": [{"handler": "static_response", "body": "a"}]}]},
        "b": {"listen": [":9163"], "routes": [{"handle": [{"handler": "static_response", "body": "b"}]}]},
        "c": {"listen": [":9164"], "routes": [{"handle": [{"handler": "static_response", "body": "c"}]}]},
        "proxy": {
          "listen": [":%[2]d"],
          "routes": [{"handle": [{
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "127.0.0.1:9162"}, {"dial": "127.0.0.1:9163"}, {"dial": "127.0.0.1:9164"}],
            "load_balancing": {"selection_policy": {
              "policy": "edge_tiered", "pool": "web", "steering": "weighted",
              "sticky": {"cookie": "edge_aff", "ttl": "1h"},
              "upstreams": [
                {"dial": "127.0.0.1:9162", "origin": "a", "priority": 1, "weight": 3},
                {"dial": "127.0.0.1:9163", "origin": "b", "priority": 1, "weight": 1},
                {"dial": "127.0.0.1:9164", "origin": "c", "priority": 2}
              ]
            }}
          }]}]
        }
      }
    }
  }
}`

func TestCaddyEdgeTiered(t *testing.T) {
	tester := caddytest.NewTester(t).WithDefaultOverrides(caddytest.Config{AdminPort: adminPort})
	tester.InitServer(fmt.Sprintf(caddyConfig, adminPort, proxyPort), "json")
	url := fmt.Sprintf("http://localhost:%d/", proxyPort)

	plain := &http.Client{} // no cookie jar
	get := func(c *http.Client) string {
		t.Helper()
		resp, err := c.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			return fmt.Sprint(resp.StatusCode)
		}
		return string(b)
	}
	push := func(body string) {
		t.Helper()
		resp, err := http.Post(fmt.Sprintf("http://localhost:%d/ingressd/state", adminPort), "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("push state: %s: %s", resp.Status, b)
		}
	}
	push(`{"pools": {}}`)

	got := map[string]int{}
	for range 40 {
		got[get(plain)]++
	}
	if got["a"] != 30 || got["b"] != 10 {
		t.Fatalf("weighted split = %v, want a:30 b:10", got)
	}

	// The tester's client has a cookie jar: it stays on one origin.
	first := get(tester.Client)
	for range 10 {
		if o := get(tester.Client); o != first {
			t.Fatalf("sticky client moved from %s to %s", first, o)
		}
	}

	// Tier 1 down via the state API, without a config reload.
	push(`{"pools": {"web": {"origins": {"a": {"healthy": false}, "b": {"healthy": false}}}}}`)
	for range 5 {
		if o := get(plain); o != "c" {
			t.Fatalf("tier 1 down: got %s", o)
		}
	}
	if o := get(tester.Client); o != "c" {
		t.Fatalf("sticky client not rebalanced: %s", o)
	}

	// Override forces origin b.
	push(`{"pools": {"web": {"override": {"origins": ["b"]}}}}`)
	if o := get(plain); o != "b" {
		t.Fatalf("override: got %s", o)
	}

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/ingressd/state", adminPort))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"origins":["b"]`) || strings.Contains(string(b), "sticky_key") {
		t.Fatalf("GET state = %s", b)
	}
}

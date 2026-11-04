// SPDX-License-Identifier: Apache-2.0

package controlsrv

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMuxRoutesByHost(t *testing.T) {
	var m Mux
	m.SetHosts(map[string]http.Handler{
		"Edge.Example.com": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "admin") }),
	})
	for host, want := range map[string]int{
		"edge.example.com":     200,
		"EDGE.example.com:443": 200,
		"other.example.com":    404,
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host
		m.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: status %d, want %d", host, rec.Code, want)
		}
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	if got := ClientIP(req); got != "203.0.113.5" {
		t.Fatalf("ClientIP = %q", got)
	}
}

// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/test/fakepanel"
)

func TestNormalizePanelURLRequiresHTTPS(t *testing.T) {
	t.Setenv(InsecurePanelEnv, "")
	if u, err := normalizePanelURL(" https://panel.example.com/ "); err != nil || u != "https://panel.example.com" {
		t.Fatalf("https: %q %v", u, err)
	}
	for _, bad := range []string{"http://panel.example.com", "ws://panel.example.com", "panel.example.com", "https://", "https://user:pw@panel.example.com"} {
		if _, err := normalizePanelURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	t.Setenv(InsecurePanelEnv, "1")
	if _, err := normalizePanelURL("http://127.0.0.1:8443"); err != nil {
		t.Fatalf("http with the test escape hatch: %v", err)
	}
}

func TestEnrolledPanelURLNoDowngrade(t *testing.T) {
	t.Setenv(InsecurePanelEnv, "")
	if u, err := checkEnrolledPanelURL("https://a.example.com", "https://b.example.com/"); err != nil || u != "https://b.example.com" {
		t.Fatalf("host change to https: %q %v", u, err)
	}
	if _, err := checkEnrolledPanelURL("https://a.example.com", "http://a.example.com"); err == nil {
		t.Fatal("https -> http accepted")
	}
	// Even with the escape hatch an https enrolment cannot be downgraded.
	t.Setenv(InsecurePanelEnv, "1")
	if _, err := checkEnrolledPanelURL("https://a.example.com", "http://a.example.com"); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("downgrade with escape hatch: %v", err)
	}
	if _, err := checkEnrolledPanelURL("http://127.0.0.1:1", "http://127.0.0.1:2"); err != nil {
		t.Fatalf("http -> http in test mode: %v", err)
	}
}

func TestEnrollRefusesPlainHTTP(t *testing.T) {
	t.Setenv(InsecurePanelEnv, "")
	p := fakepanel.New()
	p.AddToken("tok")
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	dir := t.TempDir()
	o := EnrollOptions{PanelURL: srv.URL, Token: "tok", PublicIPv4: "203.0.113.10", KeyPath: filepath.Join(dir, "age.key"), StateDir: filepath.Join(dir, "state")}
	if _, err := Enroll(context.Background(), o); err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Fatalf("enrol over http: %v", err)
	}
	if p.State().NodeID != "" {
		t.Fatal("the token was sent over plain http")
	}
	// The test escape hatch allows it.
	t.Setenv(InsecurePanelEnv, "1")
	if _, err := Enroll(context.Background(), o); err != nil {
		t.Fatalf("enrol with %s=1: %v", InsecurePanelEnv, err)
	}
}

func TestEnrollRejectsDowngradedPanelURL(t *testing.T) {
	t.Setenv(InsecurePanelEnv, "")
	p := fakepanel.New()
	p.AddToken("tok")
	p.URL = "http://attacker.example.com" // returned as panel_url
	srv := httptest.NewTLSServer(p.Handler())
	defer srv.Close()
	dir := t.TempDir()
	o := EnrollOptions{PanelURL: srv.URL, Token: "tok", PublicIPv4: "203.0.113.10", KeyPath: filepath.Join(dir, "age.key"), StateDir: filepath.Join(dir, "state"), HTTPClient: srv.Client()}
	if _, err := Enroll(context.Background(), o); err == nil {
		t.Fatal("enrolment accepted an http panel_url")
	}
	if Managed(o.StateDir) {
		t.Fatal("node.json written despite the rejected panel_url")
	}
}

func TestConnectURLRequiresHTTPS(t *testing.T) {
	t.Setenv(InsecurePanelEnv, "")
	a := &Agent{state: &State{PanelURL: "https://panel.example.com/base"}}
	if u, err := a.connectURL(); err != nil || u != "wss://panel.example.com/base/api/node/v1/connect" {
		t.Fatalf("https: %q %v", u, err)
	}
	a.state.PanelURL = "http://panel.example.com"
	if _, err := a.connectURL(); err == nil {
		t.Fatal("ws:// control channel allowed without the escape hatch")
	}
}

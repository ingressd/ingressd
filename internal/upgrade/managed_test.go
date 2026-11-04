// SPDX-License-Identifier: Apache-2.0

//go:build unix

package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/pkg/release"
)

func script(version string) []byte {
	return []byte("#!/bin/sh\necho \"ingressd " + version + " (test)\"\n")
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// releaseServer serves assets under /good/; /bad/ serves wrong bytes.
func releaseServer(t *testing.T, assets map[string][]byte) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := assets[strings.TrimPrefix(r.URL.Path, "/good/")]
		if strings.HasPrefix(r.URL.Path, "/bad/") {
			b, ok = []byte("tampered"), true
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestStage(t *testing.T) {
	newBin := script("v1.2.0")
	asset := release.AssetName("ingressd", "linux", "amd64")
	m := &release.Manifest{Version: "v1.2.0", Channel: "stable", Assets: map[string]string{asset: sum(newBin)}}
	srv := releaseServer(t, map[string][]byte{asset: newBin})
	dir := t.TempDir()
	installed := filepath.Join(dir, "ingressd")
	if err := os.WriteFile(installed, script("v1.1.0"), 0o755); err != nil { //nolint:gosec // G306: stands in for an executable
		t.Fatal(err)
	}
	var progress []string
	o := StageOptions{Manifest: m, Sources: []string{srv.URL + "/bad", srv.URL + "/good/"}, OS: "linux", Arch: "amd64", WorkDir: filepath.Join(dir, "work"),
		Binaries: []Binary{{Name: "ingressd", Path: installed, CheckVersion: true}}, From: "v1.1.0", Progress: func(s string) { progress = append(progress, s) }}
	p, err := Stage(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Swaps) != 1 || p.To != "v1.2.0" || p.From != "v1.1.0" {
		t.Fatalf("plan %+v", p)
	}
	if b, _ := os.ReadFile(p.Swaps[0].New); string(b) != string(newBin) {
		t.Error("staged binary content")
	}
	if b, _ := os.ReadFile(installed); string(b) != string(script("v1.1.0")) {
		t.Error("installed binary touched while staging")
	}
	if len(progress) == 0 {
		t.Error("no progress")
	}
	p.Discard()

	// Only tampered sources: refused.
	o.Sources = []string{srv.URL + "/bad"}
	if _, err := Stage(context.Background(), o); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("tampered: %v", err)
	}
	// A binary that reports another version is not installed.
	wrong := script("v1.1.9")
	m.Assets[asset] = sum(wrong)
	srv2 := releaseServer(t, map[string][]byte{asset: wrong})
	o.Sources = []string{srv2.URL + "/good"}
	if _, err := Stage(context.Background(), o); err == nil || !strings.Contains(err.Error(), "reports") {
		t.Errorf("wrong version: %v", err)
	}
	// Missing asset.
	o.OS = "darwin"
	if _, err := Stage(context.Background(), o); err == nil || !strings.Contains(err.Error(), "has no") {
		t.Errorf("missing asset: %v", err)
	}
}

// testPlan stages a fake binary swap in a temp dir.
func testPlan(t *testing.T) (*Plan, string) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ingressd")
	if err := os.WriteFile(bin, []byte("old"), 0o755); err != nil { //nolint:gosec // G306: stands in for an executable
		t.Fatal(err)
	}
	if err := os.WriteFile(stagedPath(bin), []byte("new"), 0o755); err != nil { //nolint:gosec // G306: stands in for an executable
		t.Fatal(err)
	}
	p := &Plan{ID: "upg_test", From: "v1.0.0", To: "v1.1.0", WorkDir: filepath.Join(dir, "work"), HealthTimeout: 700 * time.Millisecond, Created: time.Now(),
		Swaps: []Swap{{Path: bin, New: stagedPath(bin), Old: OldPath(bin)}}}
	if _, err := p.Save(); err != nil {
		t.Fatal(err)
	}
	return p, bin
}

func TestHelperSuccess(t *testing.T) {
	p, bin := testPlan(t)
	restarts := 0
	h := &helper{p: p, log: log.New(os.Stderr, "", 0), restartFn: func(ctx context.Context, h *helper) error {
		restarts++
		if b, _ := os.ReadFile(bin); string(b) != "new" {
			t.Errorf("restart before the swap: %q", b)
		}
		go func() { // the new version comes up and reports healthy
			time.Sleep(100 * time.Millisecond)
			if !WriteBeacon(p.WorkDir, "v1.1.0 (abc)") {
				t.Error("beacon not written")
			}
		}()
		return nil
	}}
	if err := h.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bin); string(b) != "new" || restarts != 1 {
		t.Errorf("after success: %q, %d restarts", b, restarts)
	}
	if b, _ := os.ReadFile(OldPath(bin)); string(b) != "old" {
		t.Error("previous binary not kept")
	}
	if Pending(p.WorkDir) != nil {
		t.Error("plan not removed")
	}
	o := TakeResult(p.WorkDir)
	if o == nil || !o.OK || o.RolledBack || o.ID != "upg_test" || o.To != "v1.1.0" {
		t.Fatalf("result %+v", o)
	}
	if TakeResult(p.WorkDir) != nil || LastResult(p.WorkDir) == nil {
		t.Error("TakeResult must move the result to last-result.json")
	}
}

func TestHelperRollsBack(t *testing.T) {
	p, bin := testPlan(t)
	restarts := 0
	h := &helper{p: p, log: log.New(os.Stderr, "", 0), restartFn: func(context.Context, *helper) error {
		restarts++
		WriteBeacon(p.WorkDir, "v1.0.0") // wrong version: ignored
		return nil
	}}
	if err := h.run(context.Background()); err == nil {
		t.Fatal("unhealthy update succeeded")
	}
	if b, _ := os.ReadFile(bin); string(b) != "old" || restarts != 2 {
		t.Errorf("after rollback: %q, %d restarts", b, restarts)
	}
	o := TakeResult(p.WorkDir)
	if o == nil || o.OK || !o.RolledBack || !strings.Contains(o.Reason, "did not report healthy") {
		t.Fatalf("result %+v", o)
	}
	if _, err := os.Stat(stagedPath(bin)); !os.IsNotExist(err) {
		t.Error("staged binary left behind")
	}
}

// TestHelperExec runs the real exec restart: the "service" is a shell
// script that writes the beacon when it is the new, healthy version.
func TestHelperExec(t *testing.T) {
	for _, healthy := range []bool{true, false} {
		t.Run(fmt.Sprint("healthy=", healthy), func(t *testing.T) {
			dir := t.TempDir()
			work := filepath.Join(dir, "work")
			bin := filepath.Join(dir, "svc")
			old := "#!/bin/sh\necho old >> " + dir + "/ran\nexec sleep 30\n"
			newer := "#!/bin/sh\necho new >> " + dir + "/ran\n"
			if healthy {
				newer += `printf '{"version":"v1.1.0","pid":%d,"time":"%s"}' $$ "$(date -u +%Y-%m-%dT%H:%M:%S.999Z)" > ` + work + "/beacon.json\n"
			}
			newer += "exec sleep 30\n"
			if err := os.WriteFile(bin, []byte(old), 0o755); err != nil { //nolint:gosec // G306: stands in for an executable
				t.Fatal(err)
			}
			if err := os.WriteFile(stagedPath(bin), []byte(newer), 0o755); err != nil { //nolint:gosec // G306: stands in for an executable
				t.Fatal(err)
			}
			running := startProc(t, bin)
			p := &Plan{ID: "upg_x", From: "v1.0.0", To: "v1.1.0", WorkDir: work, HealthTimeout: 3 * time.Second, Created: time.Now(),
				Swaps:   []Swap{{Path: bin, New: stagedPath(bin), Old: OldPath(bin)}},
				Restart: Restart{Mode: RestartExec, PID: running, Argv: []string{bin}, Dir: dir}}
			if _, err := p.Save(); err != nil {
				t.Fatal(err)
			}
			h := &helper{p: p, log: log.New(os.Stderr, "", 0)}
			err := h.run(context.Background())
			if h.child != nil {
				t.Cleanup(func() { _ = h.child.Process.Kill() })
			}
			ran, _ := os.ReadFile(filepath.Join(dir, "ran"))
			o := TakeResult(work)
			if healthy {
				if err != nil || o == nil || !o.OK || strings.TrimSpace(string(ran)) != "old\nnew" {
					t.Fatalf("err=%v result=%+v ran=%q", err, o, ran)
				}
				return
			}
			for i := 0; i < 40 && strings.Count(string(ran), "\n") < 3; i++ { // the restored version starts
				time.Sleep(50 * time.Millisecond)
				ran, _ = os.ReadFile(filepath.Join(dir, "ran"))
			}
			b, _ := os.ReadFile(bin)
			if err == nil || o == nil || !o.RolledBack || string(b) != old || strings.TrimSpace(string(ran)) != "old\nnew\nold" {
				t.Fatalf("err=%v result=%+v ran=%q", err, o, ran)
			}
		})
	}
}

func startProc(t *testing.T, bin string) int {
	t.Helper()
	p, err := os.StartProcess(bin, []string{bin}, &os.ProcAttr{Files: []*os.File{nil, os.Stdout, os.Stderr}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = p.Wait() }() // reap it when the helper stops it
	time.Sleep(200 * time.Millisecond)
	return p.Pid
}

func TestPendingStale(t *testing.T) {
	work := t.TempDir()
	p := &Plan{ID: "upg_old", To: "v1.0.0", WorkDir: work, HealthTimeout: time.Second, Created: time.Now().Add(-time.Hour)}
	if _, err := p.Save(); err != nil {
		t.Fatal(err)
	}
	if Pending(work) != nil {
		t.Error("stale plan is pending")
	}
	if WriteBeacon(work, "v1.0.0") {
		t.Error("beacon without a plan")
	}
}

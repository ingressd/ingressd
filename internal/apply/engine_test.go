// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/render"
)

func TestApplyRollsBack(t *testing.T) {
	var loaded []string
	failOn := ""
	e := &Engine{
		StatePath: filepath.Join(t.TempDir(), "last.json"),
		Backends: Backends{
			Caddy: func(_ context.Context, cfg json.RawMessage) error {
				loaded = append(loaded, string(cfg))
				if string(cfg) == failOn {
					return errors.New("boom")
				}
				return nil
			},
		},
	}
	ctx := context.Background()
	p1 := &render.Plan{Caddy: json.RawMessage(`{"v":1}`)}
	p2 := &render.Plan{Caddy: json.RawMessage(`{"v":2}`)}

	if err := e.Apply(ctx, p1); err != nil {
		t.Fatal(err)
	}
	failOn = `{"v":2}`
	err := e.Apply(ctx, p2)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("Apply = %v, want rollback error", err)
	}
	if got := strings.Join(loaded, " "); got != `{"v":1} {"v":2} {"v":1}` {
		t.Fatalf("load sequence = %s", got)
	}
	last, err := e.Last()
	if err != nil || string(last.Caddy) != `{"v":1}` {
		t.Fatalf("Last = %s, %v; want v1 kept", last.Caddy, err)
	}
}

func TestDiff(t *testing.T) {
	a := &render.Plan{Caddy: json.RawMessage(`{"token":"supersecret"}`), NFT: "x\n"}
	b := &render.Plan{Caddy: json.RawMessage(`{"token":"supersecret","n":1}`), NFT: "x\n"}
	redact := func(s string) string { return strings.ReplaceAll(s, "supersecret", "«secret»") }

	if d := Diff(a, a, redact); d != "" {
		t.Fatalf("Diff of identical plans = %q", d)
	}
	d := Diff(a, b, redact)
	if !strings.Contains(d, `+  "n": 1`) || strings.Contains(d, "supersecret") || strings.Contains(d, "nftables") {
		t.Fatalf("unexpected diff:\n%s", d)
	}
	if d := Diff(nil, b, redact); !strings.Contains(d, "caddy.json (new)") {
		t.Fatalf("Diff from nil:\n%s", d)
	}
}

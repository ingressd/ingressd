// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/apply"
	"github.com/ingressd/ingressd/internal/gitstore"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

const cfgYAML = `version: 1
edge:
  public_ipv4: 203.0.113.10
  acme: { ca: internal }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
`

func setup(t *testing.T, caddy func(context.Context, json.RawMessage) error) *Pipeline {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "conf")
	repo := gitstore.Repo{Dir: conf}
	if err := repo.Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf, "config.yaml"), []byte(cfgYAML), 0o640); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "age.key")
	if err := secrets.GenerateIdentity(key); err != nil {
		t.Fatal(err)
	}
	return &Pipeline{
		ConfigPath: filepath.Join(conf, "config.yaml"), SecretsPath: filepath.Join(conf, "secrets.age"), KeyPath: key, Repo: repo,
		Engine: func() *apply.Engine {
			return &apply.Engine{StatePath: filepath.Join(dir, "last.json"), Backends: apply.Backends{Caddy: caddy}}
		},
	}
}

func TestRunOutput(t *testing.T) {
	p := setup(t, nil)
	var applied *config.Config
	p.OnApplied = func(c *config.Config) { applied = c }
	var out bytes.Buffer
	if err := p.Run(context.Background(), &out, Options{Author: "t", Message: "first"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Applied.") || !strings.Contains(out.String(), "Recorded as") || applied == nil {
		t.Fatalf("output = %q", out.String())
	}
	out.Reset()
	_ = p.Run(context.Background(), &out, Options{DryRun: true})
	if out.String() != "No changes.\n" {
		t.Errorf("dry run = %q", out.String())
	}
}

func TestApplyConflictAndRestore(t *testing.T) {
	fail := false
	p := setup(t, func(context.Context, json.RawMessage) error {
		if fail {
			return errors.New("boom")
		}
		return nil
	})
	edit := func(cur []byte) ([]byte, error) {
		return []byte(strings.Replace(string(cur), "51820", "51821", 1)), nil
	}
	if _, err := p.Apply(context.Background(), Change{Edit: edit, BaseRevision: "stale"}); err == nil {
		t.Fatal("stale base accepted")
	} else if _, ok := err.(*ConflictError); !ok {
		t.Fatalf("err = %v", err)
	}
	cur, rev, _ := p.Read()
	res, err := p.Apply(context.Background(), Change{Edit: edit, BaseRevision: rev, DryRun: true})
	if err != nil || !strings.Contains(res.ConfigDiff, "+    listen_port: 51821") || res.PlanDiff == "" {
		t.Fatalf("dry run = %+v, %v", res, err)
	}
	if now, _, _ := p.Read(); string(now) != string(cur) {
		t.Fatal("dry run wrote the file")
	}
	fail = true
	if _, err := p.Apply(context.Background(), Change{Edit: edit, Author: "t"}); err == nil {
		t.Fatal("failed apply reported success")
	}
	if now, _, _ := p.Read(); string(now) != string(cur) {
		t.Fatal("failed apply did not restore config.yaml")
	}
	fail = false
	res, err = p.Apply(context.Background(), Change{Edit: edit, Author: "Alex <a@example.com>", Message: "port"})
	if err != nil || !res.Applied || res.Commit == "" {
		t.Fatalf("apply = %+v, %v", res, err)
	}
	bad := func([]byte) ([]byte, error) { return []byte("version: 2\n"), nil }
	res, err = p.Apply(context.Background(), Change{Edit: bad, DryRun: true})
	var ie *InvalidError
	if !errors.As(err, &ie) || res.Valid || len(res.Errors) == 0 || res.Errors[0].Path != "version" {
		t.Fatalf("invalid = %+v, %v", res, err)
	}
}

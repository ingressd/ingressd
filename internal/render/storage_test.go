// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

func TestRenderStorage(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	storage := func(o Options) map[string]any {
		t.Helper()
		o.AdminListen = "unix//run/ingressd/caddy-admin.sock"
		p, err := Render(cfg, secrets.NewMemory(map[string]string{"cf": "CF-TOKEN"}), fakeKeys{}, o)
		if err != nil {
			t.Fatal(err)
		}
		var root struct {
			Storage map[string]any `json:"storage"`
		}
		if err := json.Unmarshal(p.Caddy, &root); err != nil {
			t.Fatal(err)
		}
		return root.Storage
	}
	if got, want := storage(Options{StorageDir: "/var/lib/ingressd/caddy"}),
		map[string]any{"module": "file_system", "root": "/var/lib/ingressd/caddy"}; !reflect.DeepEqual(got, want) {
		t.Errorf("standalone storage = %v, want %v", got, want)
	}
	got := storage(Options{StorageDir: "/var/lib/ingressd/caddy", StorageSocket: "/run/ingressd/storage.sock"})
	want := map[string]any{"module": "ingressd", "socket": "/run/ingressd/storage.sock",
		"cache_dir": "/var/lib/ingressd/caddy", "local_prefixes": []any{"pki"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("managed storage = %v, want %v", got, want)
	}
	if got := storage(Options{}); got != nil {
		t.Errorf("no storage options rendered %v", got)
	}
}

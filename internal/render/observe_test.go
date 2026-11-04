// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

func TestAccessLogging(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Render(cfg, secrets.NewMemory(map[string]string{"cf": "x"}), fakeKeys{},
		Options{AdminListen: "unix//a.sock", AccessLogSocket: "/run/ingressd/access-log.sock"})
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Logging struct {
			Logs map[string]struct {
				Writer  map[string]any `json:"writer"`
				Include []string       `json:"include"`
				Exclude []string       `json:"exclude"`
			} `json:"logs"`
		} `json:"logging"`
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Logs map[string]any `json:"logs"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(p.Caddy, &root); err != nil {
		t.Fatal(err)
	}
	acc := root.Logging.Logs["ingressd_access"]
	if acc.Writer["output"] != "net" || acc.Writer["address"] != "unix//run/ingressd/access-log.sock" || acc.Writer["soft_start"] != true {
		t.Errorf("access writer = %v", acc.Writer)
	}
	if len(acc.Include) != 1 || acc.Include[0] != "http.log.access.ingressd_access" {
		t.Errorf("access include = %v", acc.Include)
	}
	if ev := root.Logging.Logs["ingressd_events"]; len(ev.Include) != 2 {
		t.Errorf("event loggers = %v", ev.Include)
	}
	if d := root.Logging.Logs["default"]; len(d.Exclude) != 1 {
		t.Errorf("default log should exclude access logs: %v", d.Exclude)
	}
	if got := root.Apps.HTTP.Servers["edge"].Logs["default_logger_name"]; got != AccessLoggerName {
		t.Errorf("server logs = %v", root.Apps.HTTP.Servers["edge"].Logs)
	}

	// Without a socket nothing changes (golden files stay stable).
	p2, _ := Render(cfg, secrets.NewMemory(map[string]string{"cf": "x"}), fakeKeys{}, Options{})
	var r2 map[string]any
	_ = json.Unmarshal(p2.Caddy, &r2)
	if _, ok := r2["logging"]; ok {
		t.Error("logging rendered without AccessLogSocket")
	}
}

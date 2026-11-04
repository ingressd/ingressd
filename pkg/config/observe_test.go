// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func TestObserveDefaults(t *testing.T) {
	c := mustParse(t, baseYAML)
	if time.Duration(c.Logging.Retention) != 7*24*time.Hour || c.Logging.Sampling() != 1 || c.Backups.Keep != 7 {
		t.Fatalf("defaults: %+v %+v", c.Logging, c.Backups)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParsePeriod(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "36h": 36 * time.Hour, "90m": 90 * time.Minute} {
		got, err := ParsePeriod(in)
		if err != nil || got != want {
			t.Errorf("ParsePeriod(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParsePeriod("7 days"); err == nil {
		t.Error("expected error")
	}
}

func TestValidateObserve(t *testing.T) {
	tests := []struct {
		name, yaml, want string
	}{
		{"ok", `
alerts:
  channels:
    phone: { type: ntfy, url: https://ntfy.sh/x }
    discord: { type: discord, webhook: secret://discord_webhook }
    ops: { type: email, to: ops@example.com }
    hook: { type: webhook, url: http://127.0.0.1:9000/hook }
  rules:
    - { on: [tunnel_down, backup_failed], notify: [phone, discord, ops, hook] }
  quiet_hours: { start: "22:00", end: "07:00", timezone: Europe/London, except: [tunnel_down] }
logging: { retention: 14d, access_log_sampling: 0.5 }
backups:
  schedule: "0 3 * * *"
  keep: 5
  s3: { endpoint: s3.example.com, bucket: b, access_key: AK, secret_key: secret://s3 }
  git_remote: git@example.com:me/edge-backup.git
`, ""},
		{"unknown channel", `
alerts:
  rules: [{ on: [tunnel_down], notify: [nope] }]
`, `alerts.rules[0].notify: unknown channel "nope"`},
		{"unknown event", `
alerts:
  channels: { phone: { type: ntfy, url: https://ntfy.sh/x } }
  rules: [{ on: [tunnel_dwn], notify: [phone] }]
`, `alerts.rules[0].on: unknown event "tunnel_dwn"`},
		{"bad channel type", `
alerts:
  channels: { phone: { type: sms, url: https://x } }
`, `alerts.channels.phone.type: unknown channel type "sms"`},
		{"bad url", `
alerts:
  channels: { phone: { type: ntfy, url: ntfy.sh/x } }
`, `alerts.channels.phone.url: must be an http(s) URL`},
		{"bad email", `
alerts:
  channels: { ops: { type: email, to: [not-an-email] } }
`, `alerts.channels.ops.to[0]: invalid email address`},
		{"bad quiet hours", `
alerts:
  quiet_hours: { start: "25:00", end: "07:00" }
`, `alerts.quiet_hours.start: invalid time "25:00"`},
		{"bad sampling", `
logging: { access_log_sampling: 1.5 }
`, `logging.access_log_sampling: must be in (0, 1]`},
		{"bad schedule", `
backups: { schedule: "0 25 * * *" }
`, `backups.schedule: invalid schedule`},
		{"s3 without schedule", `
backups: { s3: { endpoint: e, bucket: b, access_key: a, secret_key: s } }
`, `backups.schedule: required when s3 or git_remote is set`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mustParse(t, baseYAML+tt.yaml).Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidSchedule(t *testing.T) {
	for _, s := range []string{"@daily", "@hourly", "@weekly", "@every 6h", "@every 1d", "*/15 * * * *", "0 3 * * 1-5", "30 2 1,15 * *"} {
		if err := ValidSchedule(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"@yearly", "@every 10s", "* * * *", "60 * * * *", "0 0 0 * *", "*/0 * * * *"} {
		if err := ValidSchedule(s); err == nil {
			t.Errorf("%q: expected error", s)
		}
	}
}

func TestValidateGitRemote(t *testing.T) {
	for _, s := range []string{
		"git@github.com:me/ingressd-config.git", "github.com:me/x.git",
		"https://user:tok@git.example.com/x.git", "ssh://git@example.com:2222/x.git",
		"/srv/backup/edge.git", "file:///srv/backup/edge.git",
	} {
		if err := ValidateGitRemote(s); err != nil {
			t.Errorf("ValidateGitRemote(%q) = %v", s, err)
		}
	}
	for _, s := range []string{
		"", "--upload-pack=touch /tmp/x", "-oProxyCommand=x:y", "ext::sh -c touch% /tmp/x",
		"ssh://-oProxyCommand=x/y", "git@-oProxyCommand=x:y", "relative/path", "ftp://example.com/x",
		"https://example.com/x y", "host:",
	} {
		if err := ValidateGitRemote(s); err == nil {
			t.Errorf("ValidateGitRemote(%q) accepted", s)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Logging controls access-log storage in the control plane (PLAN §13).
type Logging struct {
	// Retention is how long individual access-log entries are kept
	// (default 7d). Per-minute aggregates are kept for 30 days.
	Retention Period `yaml:"retention"`
	// AccessLogSampling is the fraction (0–1] of requests stored as
	// individual log entries. Aggregates and metrics always count every
	// request. Default 1.0.
	AccessLogSampling *float64 `yaml:"access_log_sampling"`
}

// Sampling returns the effective access-log sampling ratio.
func (l Logging) Sampling() float64 {
	if l.AccessLogSampling == nil {
		return 1
	}
	return *l.AccessLogSampling
}

// Alert channel types.
const (
	ChannelNtfy    = "ntfy"
	ChannelDiscord = "discord"
	ChannelWebhook = "webhook"
	ChannelEmail   = "email"
)

// AlertEvents lists every event an alert rule may subscribe to. It mirrors
// the constants in internal/alerts (kept here so config has no dependency
// on the alerts package); alerts tests check the two stay in sync.
var AlertEvents = []string{
	"tunnel_down", "origin_down", "pool_failover", "pool_all_down",
	"cert_expiring", "cert_renewal_failed", "waf_spike", "auth_bruteforce",
	"admin_login_new_location", "email_delivery_failing", "disk_low",
	"backup_failed", "apply_failed",
}

// Alerts routes events to notification channels.
type Alerts struct {
	Channels   map[string]AlertChannel `yaml:"channels"`
	Rules      []AlertRule             `yaml:"rules"`
	QuietHours *QuietHours             `yaml:"quiet_hours"`
	// RepeatAfter re-sends a still-firing alert after this long (default
	// 24h; "0s" never repeats).
	RepeatAfter *Duration `yaml:"repeat_after"`
}

// AlertChannel is one notification destination. URL and Webhook may be
// secret:// references.
type AlertChannel struct {
	Type    string `yaml:"type"`
	URL     string `yaml:"url"`     // ntfy topic URL, webhook URL
	Webhook string `yaml:"webhook"` // Discord webhook URL
	// To lists email recipients (type email).
	To StringList `yaml:"to"`
}

// Endpoint is the channel's target URL (Webhook for Discord, else URL).
func (c AlertChannel) Endpoint() string {
	if c.Webhook != "" {
		return c.Webhook
	}
	return c.URL
}

// AlertRule sends the listed events (firing and recovery) to channels.
type AlertRule struct {
	On     []string `yaml:"on"`
	Notify []string `yaml:"notify"`
}

// QuietHours hold notifications between Start and End (local clock times,
// "22:00"–"07:00"). Alerts still firing when quiet hours end are sent then.
// Events listed in Except are always sent immediately.
type QuietHours struct {
	Start    string   `yaml:"start"`
	End      string   `yaml:"end"`
	Timezone string   `yaml:"timezone"`
	Except   []string `yaml:"except"`
}

// Backups configures scheduled backups (PLAN §4.5).
type Backups struct {
	// Schedule is a 5-field cron expression ("0 3 * * *"), @hourly, @daily,
	// @weekly or "@every <duration>". Empty disables scheduled backups.
	Schedule string `yaml:"schedule"`
	// Keep is how many archives to retain locally and in S3 (default 7).
	Keep int `yaml:"keep"`
	// LocalDir holds the archives (default <state-dir>/backups).
	LocalDir string `yaml:"local_dir"`
	// Passphrase, if set (normally secret://...), re-encrypts the secrets in
	// each archive to this passphrase so it restores without the key file.
	Passphrase string    `yaml:"passphrase"`
	S3         *BackupS3 `yaml:"s3"`
	// GitRemote, if set, receives a push of the config history after each
	// backup (a private repository; secrets.age stays encrypted).
	GitRemote string `yaml:"git_remote"`
}

// BackupS3 is an S3-compatible bucket (AWS, MinIO, Backblaze B2, R2, ...).
type BackupS3 struct {
	Endpoint  string `yaml:"endpoint"` // host[:port] or https://host
	Region    string `yaml:"region"`
	Bucket    string `yaml:"bucket"`
	Prefix    string `yaml:"prefix"` // object key prefix, default "ingressd/"
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Insecure  bool   `yaml:"insecure"` // plain HTTP (local MinIO)
}

// Period is a duration that also accepts days and weeks ("7d", "2w",
// "36h").
type Period time.Duration

var periodRe = regexp.MustCompile(`^(\d+)([dw])$`)

// ParsePeriod parses a Go duration or a whole number of days/weeks.
func ParsePeriod(s string) (time.Duration, error) {
	if m := periodRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		d := time.Duration(n) * 24 * time.Hour
		if m[2] == "w" {
			d *= 7
		}
		return d, nil
	}
	return time.ParseDuration(s)
}

func (p *Period) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	d, err := ParsePeriod(s)
	if err != nil {
		return fmt.Errorf("line %d: invalid period %q (e.g. 36h, 7d, 2w)", n.Line, s)
	}
	*p = Period(d)
	return nil
}

func (p Period) MarshalYAML() (any, error) {
	d := time.Duration(p)
	if d > 0 && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour)), nil
	}
	return d.String(), nil
}

func (c *Config) applyObserveDefaults() {
	if c.Logging.Retention == 0 {
		c.Logging.Retention = Period(7 * 24 * time.Hour)
	}
	if c.Backups.Keep == 0 {
		c.Backups.Keep = 7
	}
	if s := c.Backups.S3; s != nil && s.Prefix == "" {
		s.Prefix = "ingressd/"
	}
}

func (c *Config) validateObserve(v *validator) {
	if s := c.Logging.Sampling(); s <= 0 || s > 1 {
		v.add("logging.access_log_sampling", "must be in (0, 1], got %v", s)
	}
	if c.Logging.Retention < 0 {
		v.add("logging.retention", "must be positive")
	}

	a := c.Alerts
	for _, name := range sortedKeys(a.Channels) {
		ch := a.Channels[name]
		p := "alerts.channels." + name
		if !nameRe.MatchString(name) {
			v.add(p, "invalid channel name (use lowercase letters, digits and -)")
		}
		switch ch.Type {
		case ChannelNtfy, ChannelWebhook:
			validURL(v, p+".url", ch.URL)
		case ChannelDiscord:
			validURL(v, p+".webhook", ch.Endpoint())
		case ChannelEmail:
			if len(ch.To) == 0 {
				v.add(p+".to", "email channel needs at least one recipient")
			}
			for i, to := range ch.To {
				if _, err := mail.ParseAddress(to); err != nil {
					v.add(fmt.Sprintf("%s.to[%d]", p, i), "invalid email address %q", to)
				}
			}
		default:
			v.add(p+".type", "unknown channel type %q (ntfy, discord, webhook or email)", ch.Type)
		}
	}
	for i, r := range a.Rules {
		p := fmt.Sprintf("alerts.rules[%d]", i)
		if len(r.On) == 0 {
			v.add(p+".on", "list at least one event")
		}
		for _, ev := range r.On {
			if !slices.Contains(AlertEvents, ev) {
				v.add(p+".on", "unknown event %q (one of %s)", ev, strings.Join(AlertEvents, ", "))
			}
		}
		if len(r.Notify) == 0 {
			v.add(p+".notify", "list at least one channel")
		}
		for _, ch := range r.Notify {
			if _, ok := a.Channels[ch]; !ok {
				v.add(p+".notify", "unknown channel %q", ch)
			}
		}
	}
	if q := a.QuietHours; q != nil {
		if _, err := ParseClock(q.Start); err != nil {
			v.add("alerts.quiet_hours.start", "%v", err)
		}
		if _, err := ParseClock(q.End); err != nil {
			v.add("alerts.quiet_hours.end", "%v", err)
		}
		if q.Timezone != "" {
			if _, err := time.LoadLocation(q.Timezone); err != nil {
				v.add("alerts.quiet_hours.timezone", "unknown time zone %q", q.Timezone)
			}
		}
		for _, ev := range q.Except {
			if !slices.Contains(AlertEvents, ev) {
				v.add("alerts.quiet_hours.except", "unknown event %q", ev)
			}
		}
	}
	if a.RepeatAfter != nil && *a.RepeatAfter < 0 {
		v.add("alerts.repeat_after", "must not be negative")
	}

	b := c.Backups
	if b.Schedule != "" {
		if err := ValidSchedule(b.Schedule); err != nil {
			v.add("backups.schedule", "%v", err)
		}
	}
	if b.Keep < 0 {
		v.add("backups.keep", "must be positive")
	}
	if s := b.S3; s != nil {
		if s.Endpoint == "" {
			v.add("backups.s3.endpoint", "required")
		}
		if s.Bucket == "" {
			v.add("backups.s3.bucket", "required")
		}
		if s.AccessKey == "" || s.SecretKey == "" {
			v.add("backups.s3", "access_key and secret_key are required")
		}
	}
	if (b.S3 != nil || b.GitRemote != "") && b.Schedule == "" {
		v.add("backups.schedule", "required when s3 or git_remote is set")
	}
	if b.GitRemote != "" && !strings.HasPrefix(b.GitRemote, "secret://") {
		if err := ValidateGitRemote(b.GitRemote); err != nil {
			v.add("backups.git_remote", "%v", err)
		}
	}
}

// ValidateGitRemote accepts the remotes a backup push may use: https, http,
// ssh (ssh://, git+ssh://), git:// and file:// URLs, scp-like
// [user@]host:path and absolute paths. Anything git could read as an
// option (leading "-") or a transport helper ("ext::…") is refused.
// The backup scheduler checks the resolved value again before pushing.
func ValidateGitRemote(s string) error {
	bad := fmt.Errorf("must be an https/ssh URL, user@host:path or an absolute path")
	if s == "" || strings.HasPrefix(s, "-") || strings.Contains(s, "::") ||
		strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return bad
	}
	if scheme, _, ok := strings.Cut(s, "://"); ok {
		switch scheme {
		case "https", "http", "ssh", "git+ssh", "ssh+git", "git", "file":
		default:
			return bad
		}
		u, err := url.Parse(s)
		if err != nil || (scheme != "file" && u.Host == "") || strings.HasPrefix(u.Hostname(), "-") {
			return bad
		}
		return nil
	}
	if strings.HasPrefix(s, "/") {
		return nil
	}
	// scp-like: a colon before the first slash separates host from path.
	host, path, ok := strings.Cut(s, ":")
	if !ok || strings.Contains(host, "/") || path == "" {
		return bad
	}
	if i := strings.LastIndexByte(host, '@'); i >= 0 {
		host = host[i+1:]
	}
	if host == "" || strings.HasPrefix(host, "-") {
		return bad
	}
	return nil
}

func validURL(v *validator, path, s string) {
	if strings.HasPrefix(s, "secret://") {
		return
	}
	u, err := url.Parse(s)
	if s == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		v.add(path, "must be an http(s) URL or secret:// reference, got %q", s)
	}
}

// ParseClock parses "HH:MM" into minutes after midnight.
func ParseClock(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("invalid time %q (use HH:MM)", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// ValidSchedule checks a backup schedule expression. The scheduler itself
// lives in internal/backup; this only checks the syntax so config has no
// dependency on it.
func ValidSchedule(s string) error {
	switch s {
	case "@hourly", "@daily", "@midnight", "@weekly":
		return nil
	}
	if d, ok := strings.CutPrefix(s, "@every "); ok {
		dur, err := ParsePeriod(strings.TrimSpace(d))
		if err != nil || dur < time.Minute {
			return fmt.Errorf("invalid interval %q (at least 1m)", d)
		}
		return nil
	}
	f := strings.Fields(s)
	if len(f) != 5 {
		return fmt.Errorf("invalid schedule %q (cron \"m h dom mon dow\", @daily or \"@every 6h\")", s)
	}
	ranges := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	for i, field := range f {
		if _, err := CronField(field, ranges[i][0], ranges[i][1]); err != nil {
			return fmt.Errorf("invalid schedule %q: %v", s, err)
		}
	}
	return nil
}

// CronField expands one cron field (*, n, a-b, lists, /step) into the set
// of values it matches.
func CronField(f string, lo, hi int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, part := range strings.Split(f, ",") {
		step := 1
		if base, s, ok := strings.Cut(part, "/"); ok {
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("bad step %q", part)
			}
			step, part = n, base
		}
		from, to := lo, hi
		switch {
		case part == "*":
		case strings.Contains(part, "-"):
			a, b, _ := strings.Cut(part, "-")
			var err1, err2 error
			from, err1 = strconv.Atoi(a)
			to, err2 = strconv.Atoi(b)
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("bad range %q", part)
			}
		default:
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("bad value %q", part)
			}
			from, to = n, n
			if step > 1 {
				to = hi
			}
		}
		if from < lo || to > hi || from > to {
			return nil, fmt.Errorf("%q out of range %d-%d", part, lo, hi)
		}
		for i := from; i <= to; i += step {
			out[i] = true
		}
	}
	return out, nil
}

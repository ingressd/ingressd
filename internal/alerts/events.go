// SPDX-License-Identifier: Apache-2.0

// Package alerts routes operational events (tunnel down, certificate
// problems, failed backups, ...) to notification channels: ntfy, Discord,
// generic webhooks and email (PLAN §13).
//
// Any package can raise an alert with the package-level Publish:
//
//	alerts.Publish(alerts.Event{Kind: alerts.PoolAllDown, Key: "server-pool",
//		Message: "all origins of pool server-pool are down"})
//	// ... later, when it recovers:
//	alerts.Publish(alerts.Event{Kind: alerts.PoolAllDown, Key: "server-pool", Resolved: true})
//
// Kind + Key identify an alert: repeated firing events for the same alert
// are deduplicated, and a Resolved event sends a recovery notice only if
// the firing one was sent. One-off events (a login from a new location)
// use a unique Key and never resolve; they repeat only after repeat_after.
package alerts

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Kind is an event type. Alert rules in config.yaml subscribe to kinds.
type Kind string

// Every event of PLAN §13. Owners in parentheses publish them.
const (
	TunnelDown            Kind = "tunnel_down"              // (alerts: wgctrl monitor) Key: tunnel name; resolves when back up
	OriginDown            Kind = "origin_down"              // (health, Phase 6) Key: "pool/origin"
	PoolFailover          Kind = "pool_failover"            // (health, Phase 6) Key: pool; resolves on failback
	PoolAllDown           Kind = "pool_all_down"            // (health, Phase 6) Key: pool
	CertExpiring          Kind = "cert_expiring"            // (alerts: cert scan) Key: domain; < 14 days left
	CertRenewalFailed     Kind = "cert_renewal_failed"      // (alerts: Caddy tls logs) Key: domain
	WAFSpike              Kind = "waf_spike"                // (WAF, Phase 8) Key: app
	AuthBruteforce        Kind = "auth_bruteforce"          // (auth, Phase 3) Key: email or IP
	AdminLoginNewLocation Kind = "admin_login_new_location" // (admin, Phase 2) Key: "admin@country/ip" (unique, never resolves)
	EmailDeliveryFailing  Kind = "email_delivery_failing"   // (email, Phase 3) Key: provider
	DiskLow               Kind = "disk_low"                 // (alerts: disk monitor) Key: path
	BackupFailed          Kind = "backup_failed"            // (backup scheduler) Key: "scheduled"; resolves on next success
	ApplyFailed           Kind = "apply_failed"             // (serve) Key: "config"; resolves on next successful apply
)

// Kinds lists every event kind (config.AlertEvents mirrors it).
var Kinds = []Kind{
	TunnelDown, OriginDown, PoolFailover, PoolAllDown, CertExpiring, CertRenewalFailed,
	WAFSpike, AuthBruteforce, AdminLoginNewLocation, EmailDeliveryFailing, DiskLow,
	BackupFailed, ApplyFailed,
}

type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

var defaultSeverity = map[Kind]Severity{
	TunnelDown: Critical, PoolAllDown: Critical, CertRenewalFailed: Critical,
	OriginDown: Warning, PoolFailover: Warning, CertExpiring: Warning, WAFSpike: Warning,
	AuthBruteforce: Warning, AdminLoginNewLocation: Warning, EmailDeliveryFailing: Warning,
	DiskLow: Warning, BackupFailed: Warning, ApplyFailed: Warning,
}

var defaultTitle = map[Kind]string{
	TunnelDown:            "Tunnel %s is down",
	OriginDown:            "Origin %s is down",
	PoolFailover:          "Pool %s failed over",
	PoolAllDown:           "All origins of pool %s are down",
	CertExpiring:          "Certificate for %s expires soon",
	CertRenewalFailed:     "Certificate renewal failed for %s",
	WAFSpike:              "WAF block spike on %s",
	AuthBruteforce:        "Possible brute force against %s",
	AdminLoginNewLocation: "Admin login from a new location (%s)",
	EmailDeliveryFailing:  "Email delivery is failing (%s)",
	DiskLow:               "Disk space low on %s",
	BackupFailed:          "Backup failed (%s)",
	ApplyFailed:           "Applying the configuration failed (%s)",
}

var recoveryTitle = map[Kind]string{
	TunnelDown:        "Tunnel %s is back up",
	OriginDown:        "Origin %s recovered",
	PoolFailover:      "Pool %s failed back",
	PoolAllDown:       "Pool %s has healthy origins again",
	CertExpiring:      "Certificate for %s was renewed",
	CertRenewalFailed: "Certificate for %s renewed successfully",
	DiskLow:           "Disk space on %s is OK again",
	BackupFailed:      "Backups are succeeding again (%s)",
	ApplyFailed:       "Configuration applied successfully (%s)",
}

// Event is something that happened. Kind and Key identify the alert.
type Event struct {
	Kind     Kind              `json:"event"`
	Key      string            `json:"key"`
	Resolved bool              `json:"resolved"`
	Severity Severity          `json:"severity"`
	Title    string            `json:"title"`
	Message  string            `json:"message"`
	Fields   map[string]string `json:"fields,omitempty"`
	Time     time.Time         `json:"time"`
}

// normalize fills defaults.
func (e *Event) normalize(now time.Time) {
	if e.Time.IsZero() {
		e.Time = now
	}
	if e.Severity == "" {
		e.Severity = defaultSeverity[e.Kind]
		if e.Severity == "" {
			e.Severity = Warning
		}
	}
	if e.Resolved {
		e.Severity = Info
	}
	if e.Title == "" {
		t := defaultTitle[e.Kind]
		if e.Resolved {
			t = recoveryTitle[e.Kind]
			if t == "" {
				t = "Resolved: " + defaultTitle[e.Kind]
			}
		}
		if t == "" {
			t = string(e.Kind) + " (%s)"
		}
		e.Title = fmt.Sprintf(t, e.Key)
	}
}

func (k Kind) Valid() bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

var (
	defaultMu      sync.Mutex
	defaultEngine  *Engine
	defaultPending []Event
)

// SetDefault installs the engine used by Publish (serve does this) and
// delivers events published before it was set.
func SetDefault(e *Engine) {
	defaultMu.Lock()
	defaultEngine = e
	pending := defaultPending
	defaultPending = nil
	defaultMu.Unlock()
	for _, ev := range pending {
		e.Publish(ev)
	}
}

// Publish sends an event to the default engine. It never blocks. Before
// serve starts the engine, up to 100 events are buffered.
func Publish(ev Event) {
	defaultMu.Lock()
	e := defaultEngine
	if e == nil {
		if len(defaultPending) < 100 {
			defaultPending = append(defaultPending, ev)
		} else {
			slog.Warn("alert dropped: alert engine not running", "event", ev.Kind, "key", ev.Key)
		}
	}
	defaultMu.Unlock()
	if e != nil {
		e.Publish(ev)
	}
}

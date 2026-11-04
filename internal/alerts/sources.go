// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
)

// Built-in event sources run by serve.

// Monitor runs the built-in checks: tunnel handshakes (tunnel_down),
// certificate expiry (cert_expiring) and free disk space (disk_low).
type Monitor struct {
	Publish func(Event)
	// Config returns the current config (nil before the first apply).
	Config func() *config.Config
	// CertDir is Caddy's certificate storage (<state-dir>/caddy/certificates).
	CertDir string
	// DiskPaths are checked for free space (state and config dirs).
	DiskPaths []string
	// ReadTunnels reads WireGuard status (default tunnel.ReadStatus).
	ReadTunnels func(*config.Config) ([]tunnel.Status, error)
	// TunnelInterval (default 5s) and SlowInterval (certs, disk; default
	// 10m) set how often checks run.
	TunnelInterval, SlowInterval time.Duration
	Now                          func() time.Time

	tunnels map[string]*tunnelTrack
	disk    map[string]bool
}

type tunnelTrack struct {
	rx       int64
	rxAt     time.Time // last time rx bytes increased
	down     bool
	everSeen bool
}

// Run checks until ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	if m.TunnelInterval <= 0 {
		m.TunnelInterval = 5 * time.Second
	}
	if m.SlowInterval <= 0 {
		m.SlowInterval = 10 * time.Minute
	}
	fast := time.NewTicker(m.TunnelInterval)
	defer fast.Stop()
	slow := time.NewTicker(m.SlowInterval)
	defer slow.Stop()
	m.CheckSlow()
	for {
		select {
		case <-ctx.Done():
			return
		case <-fast.C:
			m.CheckTunnels()
		case <-slow.C:
			m.CheckSlow()
		}
	}
}

func (m *Monitor) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// CheckTunnels publishes tunnel_down when a site stops talking to the edge
// and resolves it when it comes back. A tunnel is down when its last
// handshake is older than tunnel.HandshakeTimeout, or when nothing has
// been received for three keepalive intervals (sites send keepalives, so
// silence means the link is gone; this detects outages in seconds rather
// than minutes). Tunnels that never connected are not reported.
func (m *Monitor) CheckTunnels() {
	cfg := m.Config()
	if cfg == nil {
		return
	}
	read := m.ReadTunnels
	if read == nil {
		read = tunnel.ReadStatus
	}
	sts, err := read(cfg)
	if err != nil {
		return
	}
	if m.tunnels == nil {
		m.tunnels = map[string]*tunnelTrack{}
	}
	now := m.now()
	seen := map[string]bool{}
	for _, s := range sts {
		seen[s.Tunnel] = true
		t := m.tunnels[s.Tunnel]
		if t == nil {
			t = &tunnelTrack{rx: s.RxBytes, rxAt: now}
			m.tunnels[s.Tunnel] = t
		}
		if s.RxBytes != t.rx {
			t.rx, t.rxAt = s.RxBytes, now
		}
		if s.LastHandshake.IsZero() && !t.everSeen {
			continue
		}
		t.everSeen = true
		keepalive := time.Duration(cfg.Tunnels[s.Tunnel].Keepalive) * time.Second
		if keepalive <= 0 {
			keepalive = 25 * time.Second
		}
		stall := 3*keepalive + 5*time.Second
		var reason string
		switch {
		case !s.Up:
			reason = "interface " + s.Interface + " is missing"
		case s.LastHandshake.IsZero() || now.Sub(s.LastHandshake) >= tunnel.HandshakeTimeout:
			reason = fmt.Sprintf("no handshake for %s", ago(now, s.LastHandshake))
		case now.Sub(t.rxAt) >= stall:
			reason = fmt.Sprintf("nothing received from the site for %s", now.Sub(t.rxAt).Round(time.Second))
		}
		switch {
		case reason != "" && !t.down:
			t.down = true
			m.Publish(Event{Kind: TunnelDown, Key: s.Tunnel, Message: "Tunnel " + s.Tunnel + ": " + reason + ".",
				Fields: map[string]string{"interface": s.Interface, "last_handshake": fmtTime(s.LastHandshake), "endpoint": s.Endpoint}})
		case reason == "" && t.down:
			t.down = false
			m.Publish(Event{Kind: TunnelDown, Key: s.Tunnel, Resolved: true,
				Message: "Tunnel " + s.Tunnel + " is passing traffic again.", Fields: map[string]string{"endpoint": s.Endpoint}})
		}
	}
	for name, t := range m.tunnels {
		if !seen[name] { // removed from config
			if t.down {
				m.Publish(Event{Kind: TunnelDown, Key: name, Resolved: true, Message: "Tunnel " + name + " was removed."})
			}
			delete(m.tunnels, name)
		}
	}
}

func ago(now, t time.Time) string {
	if t.IsZero() {
		return "ever"
	}
	return now.Sub(t).Round(time.Second).String()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// CheckSlow runs the certificate and disk checks.
func (m *Monitor) CheckSlow() {
	m.CheckCerts()
	m.CheckDisk()
}

// CertExpiryWarning is how long before expiry cert_expiring fires.
const CertExpiryWarning = 14 * 24 * time.Hour

// CertInfo describes one certificate in Caddy's storage.
type CertInfo struct {
	Name     string // storage name (domain, or wildcard_.example.com)
	Path     string
	Issuer   string // storage issuer directory
	NotAfter time.Time
	Lifetime time.Duration
}

// ScanCerts lists the leaf certificates in Caddy's storage directory.
func ScanCerts(dir string) ([]CertInfo, error) {
	var out []CertInfo
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == dir {
				return err
			}
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(p, ".crt") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		issuer, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
		out = append(out, CertInfo{
			Name: strings.TrimSuffix(filepath.Base(p), ".crt"), Path: p, Issuer: issuer,
			NotAfter: c.NotAfter, Lifetime: c.NotAfter.Sub(c.NotBefore),
		})
		return nil
	})
	return out, err
}

// expiryThreshold is when a certificate counts as expiring: 14 days, or a
// sixth of its lifetime for short-lived certificates (Caddy renews them
// with a third left, so reaching a sixth means renewals are failing).
func expiryThreshold(lifetime time.Duration) time.Duration {
	if lifetime < 6*CertExpiryWarning/2 {
		return lifetime / 6
	}
	return CertExpiryWarning
}

// CheckCerts publishes cert_expiring for certificates close to expiry.
// Caddy's internal CA ("local" issuer) is skipped.
func (m *Monitor) CheckCerts() {
	if m.CertDir == "" {
		return
	}
	certs, err := ScanCerts(m.CertDir)
	if err != nil {
		return
	}
	now := m.now()
	for _, c := range certs {
		if c.Issuer == "local" {
			continue
		}
		left := c.NotAfter.Sub(now)
		name := strings.Replace(c.Name, "wildcard_", "*", 1)
		fields := map[string]string{"expires": c.NotAfter.UTC().Format(time.RFC3339), "issuer": c.Issuer}
		if left < expiryThreshold(c.Lifetime) {
			sev := Warning
			msg := fmt.Sprintf("The certificate for %s expires in %s and has not been renewed.", name, left.Round(time.Hour))
			if left <= 0 {
				sev, msg = Critical, fmt.Sprintf("The certificate for %s has expired.", name)
			}
			m.Publish(Event{Kind: CertExpiring, Key: name, Severity: sev, Message: msg, Fields: fields})
		} else {
			m.Publish(Event{Kind: CertExpiring, Key: name, Resolved: true, Fields: fields})
		}
	}
}

// DiskLowFraction and DiskLowBytes: disk_low fires when free space drops
// below either.
const (
	DiskLowFraction = 0.10
	DiskLowBytes    = 1 << 30
)

// CheckDisk publishes disk_low per filesystem.
func (m *Monitor) CheckDisk() {
	if m.disk == nil {
		m.disk = map[string]bool{}
	}
	var checked []uint64
	for _, p := range m.DiskPaths {
		u, err := DiskUsage(p)
		if err != nil || slices.Contains(checked, u.Device) {
			continue
		}
		checked = append(checked, u.Device)
		low := u.Low()
		fields := map[string]string{"free": humanBytes(u.Free), "total": humanBytes(u.Total)}
		if low {
			m.Publish(Event{Kind: DiskLow, Key: p, Fields: fields,
				Message: fmt.Sprintf("Only %s free of %s (%.0f%%) on %s.", humanBytes(u.Free), humanBytes(u.Total), u.FreeFraction()*100, p)})
		} else if m.disk[p] {
			m.Publish(Event{Kind: DiskLow, Key: p, Resolved: true, Fields: fields})
		}
		m.disk[p] = low
	}
}

// Disk is filesystem usage.
type Disk struct {
	Free, Total uint64
	Device      uint64
}

func (d Disk) FreeFraction() float64 {
	if d.Total == 0 {
		return 1
	}
	return float64(d.Free) / float64(d.Total)
}

// Low reports whether free space is below the disk_low thresholds.
func (d Disk) Low() bool {
	return d.Total > 0 && (d.FreeFraction() < DiskLowFraction || d.Free < DiskLowBytes)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// HumanBytes formats a byte count (1.5 GiB).
func HumanBytes(n uint64) string { return humanBytes(n) }

// CertLogEvent maps Caddy certificate obtain/renew log lines (forwarded on
// the access-log socket) to cert_renewal_failed events.
func CertLogEvent(ev observe.LogEvent) (Event, bool) {
	if !strings.HasPrefix(ev.Logger, "tls.obtain") && !strings.HasPrefix(ev.Logger, "tls.renew") {
		return Event{}, false
	}
	id, _ := ev.Fields["identifier"].(string)
	if id == "" {
		return Event{}, false
	}
	msg := strings.ToLower(ev.Msg)
	switch {
	case ev.Level == "error" || strings.Contains(msg, "could not get certificate"):
		errText, _ := ev.Fields["error"].(string)
		return Event{Kind: CertRenewalFailed, Key: id, Time: ev.Time,
			Message: "Caddy could not obtain or renew the certificate for " + id + ".",
			Fields:  map[string]string{"error": truncate(errText, 500)}}, true
	case strings.Contains(msg, "obtained successfully") || strings.Contains(msg, "renewed successfully"):
		return Event{Kind: CertRenewalFailed, Key: id, Resolved: true, Time: ev.Time}, true
	}
	return Event{}, false
}

// Collector exports alert state for /metrics.
func (e *Engine) Collector() observe.Collector {
	return func(x *observe.Exposition) {
		counts := map[Kind]int{}
		for _, st := range e.Firing() {
			counts[st.Event.Kind]++
		}
		for _, k := range Kinds {
			x.Gauge("ingressd_alerts_firing", "Alerts currently firing, by event.", float64(counts[k]), "event", string(k))
		}
		for ch, c := range e.SentCounts() {
			x.Counter("ingressd_alert_notifications_total", "Alert notifications sent, by channel and result.", float64(c[0]), "channel", ch, "result", "ok")
			x.Counter("ingressd_alert_notifications_total", "Alert notifications sent, by channel and result.", float64(c[1]), "channel", ch, "result", "error")
		}
	}
}

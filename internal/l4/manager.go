// SPDX-License-Identifier: Apache-2.0

package l4

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/pkg/config"
)

// NFTRunner loads an nft script atomically (apply.NFT).
type NFTRunner func(ctx context.Context, script string) error

// Manager adds and removes allowlist entries, keeping the store and the
// live nftables sets in step.
type Manager struct {
	Cfg   *config.Config
	Store *Store
	// NFT updates the live sets; nil skips nftables (tests, dry runs).
	NFT NFTRunner
}

// Allow adds (or refreshes) ip for service. ttl 0 means no expiry. The
// entry is persisted even if updating nftables fails, so the next apply
// installs it; the error is still returned.
func (m *Manager) Allow(ctx context.Context, service, ip, email string, ttl time.Duration) (Entry, error) {
	s, ok := m.Cfg.L4[service]
	if !ok {
		return Entry{}, fmt.Errorf("unknown l4 service %q", service)
	}
	if !s.Restricted() {
		return Entry{}, fmt.Errorf("l4 service %q has access %s; allowlist entries need access allowlist or login_to_play", service, s.Access)
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return Entry{}, fmt.Errorf("invalid IPv4 address %q", ip)
	}
	if ttl < 0 {
		return Entry{}, fmt.Errorf("ttl must not be negative")
	}
	now := m.Store.now()
	e := Entry{Service: service, IP: addr.String(), Email: email, Added: now}
	if ttl > 0 {
		e.Expires = now.Add(ttl).Truncate(time.Second)
	}
	if err := m.Store.Put(e); err != nil {
		return Entry{}, err
	}
	if m.NFT != nil {
		if err := m.NFT(ctx, AddScript(e, now)); err != nil {
			return e, fmt.Errorf("saved, but updating nftables failed (it is installed on the next apply): %w", err)
		}
	}
	return e, nil
}

// Revoke removes ip from service's runtime allowlist.
func (m *Manager) Revoke(ctx context.Context, service, ip string) error {
	if addr, err := netip.ParseAddr(ip); err == nil {
		ip = addr.String()
	}
	found, err := m.Store.Delete(service, ip)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s is not on the allowlist of %q", ip, service)
	}
	if m.NFT != nil {
		if s, ok := m.Cfg.L4[service]; ok && s.Restricted() {
			if err := m.NFT(ctx, DeleteScript(service, ip)); err != nil {
				return fmt.Errorf("removed from the store, but updating nftables failed: %w", err)
			}
		}
	}
	return nil
}

func element(e Entry, now time.Time) string {
	if e.Expires.IsZero() {
		return e.IP
	}
	secs := int(e.Expires.Sub(now).Round(time.Second) / time.Second)
	return fmt.Sprintf("%s timeout %ds", e.IP, max(secs, 1))
}

// AddScript adds e to its live set, replacing any existing element so the
// timeout is refreshed ("add; delete; add" is atomic and never fails on a
// missing or present element).
func AddScript(e Entry, now time.Time) string {
	set := fmt.Sprintf("ip %s %s", render.L4Table, render.L4AllowSet(e.Service))
	return fmt.Sprintf("add element %[1]s { %[2]s }\ndelete element %[1]s { %[2]s }\nadd element %[1]s { %[3]s }\n",
		set, e.IP, element(e, now))
}

// DeleteScript removes ip from service's live set, whether present or not.
func DeleteScript(service, ip string) string {
	set := fmt.Sprintf("ip %s %s", render.L4Table, render.L4AllowSet(service))
	return fmt.Sprintf("add element %[1]s { %[2]s }\ndelete element %[1]s { %[2]s }\n", set, ip)
}

var allowSetRe = regexp.MustCompile(`(?m)^\s*set (svc_[a-z0-9_]+_allow) \{`)

// SyncScript re-adds the unexpired entries to the sets defined by a freshly
// applied nft script (applies recreate the table, emptying the sets).
// Entries for services without a set (removed, or now public) are skipped.
// It returns "" when there is nothing to add.
func SyncScript(rendered string, entries []Entry, now time.Time) string {
	sets := map[string]bool{}
	for _, m := range allowSetRe.FindAllStringSubmatch(rendered, -1) {
		sets[m[1]] = true
	}
	elems := map[string][]string{}
	var order []string
	for _, e := range entries {
		set := render.L4AllowSet(e.Service)
		if !sets[set] || e.Expired(now) {
			continue
		}
		if elems[set] == nil {
			order = append(order, set)
		}
		elems[set] = append(elems[set], element(e, now))
	}
	var b strings.Builder
	for _, set := range order {
		fmt.Fprintf(&b, "add element ip %s %s { %s }\n", render.L4Table, set, strings.Join(elems[set], ", "))
	}
	return b.String()
}

// Sync loads the store's entries into the sets of a just-applied script.
func Sync(ctx context.Context, store *Store, rendered string, run NFTRunner) error {
	entries, err := store.List()
	if err != nil {
		return err
	}
	script := SyncScript(rendered, entries, store.now())
	if script == "" {
		return nil
	}
	if err := run(ctx, script); err != nil {
		return fmt.Errorf("restore l4 allowlist: %w", err)
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
)

// edgeMatch evaluates a rendered policy the way edge_auth does
// (edge/modules/edgeauth compiledPolicy.match).
func edgeMatch(p EdgePolicy, id Identity) bool {
	sel := func(s EdgeSelector) bool {
		switch {
		case s.Never:
			return false
		case s.Everyone:
			return true
		}
		if id.Email != "" {
			e := strings.ToLower(id.Email)
			if slices.ContainsFunc(s.Email, func(v string) bool { return strings.ToLower(v) == e }) {
				return true
			}
			if slices.ContainsFunc(s.EmailDomain, func(v string) bool { return strings.ToLower(v) == emailDomainOf(e) }) {
				return true
			}
		}
		if id.IP.IsValid() {
			for _, v := range s.IP {
				pf, err := netip.ParsePrefix(v)
				if err != nil {
					a, _ := netip.ParseAddr(v)
					pf = netip.PrefixFrom(a, a.BitLen())
				}
				if pf.Masked().Contains(id.IP.Unmap()) {
					return true
				}
			}
		}
		if id.Country != "" && slices.ContainsFunc(s.Country, func(v string) bool { return strings.EqualFold(v, id.Country) }) {
			return true
		}
		return id.ServiceToken != "" && slices.Contains(s.ServiceToken, id.ServiceToken)
	}
	if !slices.ContainsFunc(p.Include, sel) {
		return false
	}
	for _, s := range p.Require {
		if !sel(s) {
			return false
		}
	}
	return !slices.ContainsFunc(p.Exclude, sel)
}

func emailDomainOf(e string) string { return e[strings.LastIndexByte(e, '@')+1:] }

// Every policy rendered for edge_auth must decide exactly like the engine
// for every identity, so per-request checks never diverge from sign-in.
func TestEdgeSelectorsMatchEngine(t *testing.T) {
	cfg := testConfig(t)
	st := secrets.NewMemory(map[string]string{"hook": "hook-secret"})
	EnsureKeys(cfg, st)
	ec, err := BuildEdgeConfig(cfg, st, "web", "")
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(cfg)
	emails := []string{"", "alice@gmail.com", "ALICE@gmail.com", "bob@outlook.com", "x@example.com", "eve@example.com", "me@example.org", "y@corp.test", "y@sub.corp.test"}
	ips := []string{"", "81.2.3.4", "10.1.1.1", "203.0.113.5", "2001:db8::1", "::ffff:10.2.2.2", "198.51.100.1"}
	countries := []string{"", "GB", "ie", "CN", "RU", "US"}
	tokens := []string{"", "hook"}
	n := 0
	for name, ep := range ec.Policies {
		for _, e := range emails {
			for _, ip := range ips {
				for _, c := range countries {
					for _, tok := range tokens {
						a, _ := netip.ParseAddr(ip)
						id := Identity{Email: e, IP: a, Country: c, ServiceToken: tok}
						want := eng.Evaluate([]string{name}, id).Policy == name
						if got := edgeMatch(ep, id); got != want {
							t.Errorf("%s %+v: edge %v, engine %v", name, id, got, want)
						}
						n++
					}
				}
			}
		}
		if wantOffline := name != "blocked" && name != "family-or-work" && name != "admins" && name != "domain-and-net"; ep.Offline != wantOffline {
			t.Errorf("%s: offline %v", name, ep.Offline)
		}
	}
	if n == 0 {
		t.Fatal("no policies rendered")
	}
}

// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// The allowlist is this host's own limit on the networks the edges may
// reach: what is forwarded is the edge's Subnets and transparent sources
// intersected with this list, so an edge config can only narrow it. It has
// its own file beside the state file, with the same protections, because a
// running connector rewrites the state file from memory and `allow` must be
// able to change the list under it.

// Where a list came from.
const (
	allowFromEnroll = "enroll"
	allowFromPin    = "pinned"
	allowFromLocal  = "local"
)

// errAnyNetwork refuses a /0 entry without the operator's override.
var errAnyNetwork = errors.New("that is every network: pass --allow-any-network if this host really may forward anywhere")

// Allowlist is the allowlist file.
type Allowlist struct {
	Networks []string `json:"networks"`
	// AnyNetwork records the operator's override for 0.0.0.0/0 and ::/0.
	AnyNetwork bool      `json:"any_network,omitempty"`
	Source     string    `json:"source,omitempty"`
	Updated    time.Time `json:"updated"`
}

// AllowlistPath is the allowlist file of the given state file.
func AllowlistPath(statePath string) string {
	return strings.TrimSuffix(statePath, ".json") + ".allowlist.json"
}

// parseNetwork reads an allowlist entry: a prefix, or an address for one host.
func parseNetwork(s string, anyNetwork bool) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a network (for example 192.168.1.0/24)", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q: use the IPv4 form", s)
	}
	if p.Bits() == 0 && !anyNetwork {
		return netip.Prefix{}, fmt.Errorf("%s: %w", s, errAnyNetwork)
	}
	return p.Masked(), nil
}

func parseNetworks(in []string, anyNetwork bool) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, s := range in {
		p, err := parseNetwork(s, anyNetwork)
		if err != nil {
			return nil, err
		}
		out = append(out, p.String())
	}
	return out, nil
}

// readAllowlist returns the list and the bytes it was read from.
func readAllowlist(statePath string) (*Allowlist, []byte, error) {
	raw, err := os.ReadFile(AllowlistPath(statePath))
	if err != nil {
		return nil, nil, err
	}
	var a Allowlist
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, raw, fmt.Errorf("%s: %w", AllowlistPath(statePath), err)
	}
	return &a, raw, nil
}

func (a *Allowlist) save(statePath, source string) error {
	a.Source, a.Updated = source, time.Now().UTC()
	slices.Sort(a.Networks)
	a.Networks = slices.Compact(a.Networks)
	if a.Networks == nil {
		a.Networks = []string{}
	}
	// `allow` may run as root beside a connector that does not: the list
	// only appears once the connector can read it.
	path := AllowlistPath(statePath)
	tmp := path + ".new"
	err := writeJSONFile(tmp, a)
	if err == nil {
		err = matchOwner(tmp, statePath)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// privateNetworks are in every default list: origins are added from the panel,
// one address at a time, and each must work without a step on this host.
var privateNetworks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// pinnedAllowlist is the default list: private networks, plus what the site
// reaches now. A /0 is left out, since only the operator can allow one; it
// shows as refused like any other network outside the list, and the origins
// the site tests through it are pinned one by one so that they keep working.
// --allow replaces this with a tighter list.
func pinnedAllowlist(st *State) *Allowlist {
	asked := st.asked()
	nets := slices.DeleteFunc(slices.Clone(asked), func(p netip.Prefix) bool {
		return p.Bits() == 0 || p.IsSingleIP() && hostOnly(p.Addr())
	})
	for _, t := range st.Targets() {
		ap, err := netip.ParseAddrPort(t)
		if err != nil || hostOnly(ap.Addr()) {
			continue
		}
		a := ap.Addr().Unmap()
		if slices.ContainsFunc(asked, func(p netip.Prefix) bool { return p.Contains(a) }) {
			nets = append(nets, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	nets = append(nets, privateNetworks...)
	a := &Allowlist{}
	for _, p := range outermost(nets) {
		a.Networks = append(a.Networks, p.String())
	}
	return a
}

// localReach is the allowlist in effect. A nil one allows nothing.
type localReach struct {
	nets []netip.Prefix
	// raw is the file it was read from, to notice a change.
	raw []byte
	// problem says why the list in effect is not the whole file.
	problem string
	// unfiltered is set while TUN mode could not install its filter.
	unfiltered atomic.Bool
}

func (a *Allowlist) reach(raw []byte) *localReach {
	r := &localReach{raw: raw}
	var bad []string
	for _, s := range a.Networks {
		p, err := parseNetwork(s, a.AnyNetwork)
		if err != nil {
			bad = append(bad, s)
			continue
		}
		r.nets = append(r.nets, p)
	}
	if len(bad) > 0 {
		r.problem = "ignoring invalid allowlist entries: " + strings.Join(bad, ", ")
	}
	return r
}

// narrow returns the parts of p inside the list.
func (r *localReach) narrow(p netip.Prefix) []netip.Prefix {
	if r == nil {
		return nil
	}
	var out []netip.Prefix
	for _, n := range r.nets {
		switch {
		case !n.Overlaps(p):
		case n.Bits() > p.Bits():
			out = append(out, n)
		default:
			out = append(out, p)
		}
	}
	return out
}

// usable reports whether the file gave a whole, non-empty list.
func (r *localReach) usable() bool {
	return r != nil && r.problem == "" && len(r.nets) > 0
}

// report is the problem to show, if any.
func (r *localReach) report() string {
	if r == nil {
		return ""
	}
	return r.problem
}

func (r *localReach) setUnfiltered(v bool) {
	if r != nil {
		r.unfiltered.Store(v)
	}
}

// openReach loads the allowlist for a run. The first start of a connector
// enrolled before the list existed pins what it reaches now. A list that
// was pinned and is now missing or unreadable forwards nothing and is never
// pinned again from an edge's config; the tunnel, the control channel and
// updates carry on so the site can be repaired.
func openReach(statePath string, st *State, log *slog.Logger) *localReach {
	a, raw, err := readAllowlist(statePath)
	switch {
	case err == nil:
		markPinned(statePath, st, log)
		return a.reach(raw)
	case errors.Is(err, fs.ErrNotExist) && !st.AllowlistPinned:
		a = pinnedAllowlist(st)
		if err := a.save(statePath, allowFromPin); err != nil {
			log.Error("could not save the allowlist; using it for this run only", "file", AllowlistPath(statePath), "err", err)
			return a.reach(nil)
		}
		markPinned(statePath, st, log)
		log.Info("pinned the networks this connector may reach", "networks", a.Networks, "file", AllowlistPath(statePath))
		raw, _ = os.ReadFile(AllowlistPath(statePath))
		return a.reach(raw)
	case errors.Is(err, fs.ErrNotExist):
		return &localReach{problem: "allowlist file is missing: forwarding nothing to the LAN until `ingressd-connector allow add` restores it"}
	default:
		return &localReach{raw: raw, problem: fmt.Sprintf("allowlist cannot be used (%v): forwarding nothing to the LAN until `ingressd-connector allow add` replaces it", err)}
	}
}

func markPinned(statePath string, st *State, log *slog.Logger) {
	if st.AllowlistPinned {
		return
	}
	st.AllowlistPinned = true
	if err := st.Save(statePath); err != nil {
		log.Warn("save state", "err", err)
	}
}

// editAllowlist reads the list to change it. A list that cannot be parsed
// is started afresh, which is how the operator repairs one.
func editAllowlist(statePath string, st *State) (*Allowlist, error) {
	a, _, err := readAllowlist(statePath)
	switch {
	case err == nil:
		return a, nil
	case errors.Is(err, fs.ErrPermission):
		return nil, err
	case errors.Is(err, fs.ErrNotExist) && !st.AllowlistPinned:
		// Not started since the upgrade: keep what the first start would pin.
		return pinnedAllowlist(st), nil
	}
	return &Allowlist{}, nil
}

// AllowAdd adds networks to the allowlist. A running connector applies the
// change within seconds.
func AllowAdd(statePath string, networks []string, anyNetwork bool) (*Allowlist, error) {
	st, err := LoadState(statePath)
	if err != nil {
		return nil, err
	}
	add, err := parseNetworks(networks, anyNetwork)
	if err != nil {
		return nil, err
	}
	a, err := editAllowlist(statePath, st)
	if err != nil {
		return nil, err
	}
	a.Networks = append(a.Networks, add...)
	a.AnyNetwork = a.AnyNetwork || anyNetwork
	return a, a.save(statePath, allowFromLocal)
}

// AllowRemove removes networks from the allowlist.
func AllowRemove(statePath string, networks []string) (*Allowlist, error) {
	st, err := LoadState(statePath)
	if err != nil {
		return nil, err
	}
	drop, err := parseNetworks(networks, true)
	if err != nil {
		return nil, err
	}
	a, err := editAllowlist(statePath, st)
	if err != nil {
		return nil, err
	}
	for _, d := range drop {
		if !slices.Contains(a.Networks, d) {
			return nil, fmt.Errorf("%s is not in the allowlist", d)
		}
	}
	a.Networks = slices.DeleteFunc(a.Networks, func(s string) bool { return slices.Contains(drop, s) })
	a.AnyNetwork = a.AnyNetwork && slices.ContainsFunc(a.Networks, func(s string) bool {
		p, err := netip.ParsePrefix(s)
		return err == nil && p.Bits() == 0
	})
	return a, a.save(statePath, allowFromLocal)
}

// ReachReport describes the allowlist for `status` and `allow list`.
type ReachReport struct {
	Path    string
	Allowed []string
	// Refused are networks the edges ask for that the list does not fully
	// cover: forwarded only as far as the list goes, if at all.
	Refused []string
	Problem string
	// Pending: not started since the upgrade, so nothing is pinned yet.
	Pending bool
}

// DescribeReach reports the allowlist without changing anything.
func DescribeReach(statePath string, st *State) ReachReport {
	out := ReachReport{Path: AllowlistPath(statePath)}
	cp := *st
	a, raw, err := readAllowlist(statePath)
	switch {
	case err == nil:
		cp.reach = a.reach(raw)
		out.Problem = cp.reach.problem
	case errors.Is(err, fs.ErrNotExist) && !st.AllowlistPinned:
		out.Pending = true
		cp.reach = pinnedAllowlist(st).reach(nil)
	case errors.Is(err, fs.ErrNotExist):
		out.Problem = "allowlist file is missing: nothing is forwarded to the LAN"
	default:
		out.Problem = fmt.Sprintf("allowlist cannot be used (%v): nothing is forwarded to the LAN", err)
	}
	if cp.reach != nil {
		for _, p := range cp.reach.nets {
			out.Allowed = append(out.Allowed, p.String())
		}
	}
	out.Refused = cp.refused()
	return out
}

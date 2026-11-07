// SPDX-License-Identifier: Apache-2.0

//go:build linux

package apply

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/ingressd/ingressd/internal/render"
)

// shapeAlias tags the IFB devices ingressd owns, so stale ones can be
// removed without touching anyone else's.
const shapeAlias = "ingressd-shape"

var (
	htbRoot    = netlink.MakeHandle(1, 0)
	htbClass   = netlink.MakeHandle(1, 0x10)
	leafHandle = netlink.MakeHandle(0x10, 0)
	ingressQ   = netlink.MakeHandle(0xffff, 0)
)

// reconcileShapes applies the realms' bandwidth caps. Only IFBs aliased
// shapeAlias and the root HTB (1:) and ingress qdiscs of ix-* WireGuard
// interfaces are ever changed. Rates change in place (class change), so a
// new rate never drops packets in flight or touches the tunnels.
func reconcileShapes(shapes []render.Shape) error {
	type target struct {
		ifb  int
		rate int
	}
	shaped := map[string]target{}
	wantIFB := map[string]bool{}
	for _, s := range shapes {
		ifb, err := ensureIFB(s.IFB)
		if err != nil {
			return fmt.Errorf("shape %s: %w", s.Realm, err)
		}
		wantIFB[s.IFB] = true
		if err := ensureHTB(ifb, s.RateMbit); err != nil {
			return fmt.Errorf("shape %s: %s: %w", s.Realm, s.IFB, err)
		}
		for _, t := range s.Tunnels {
			shaped[t] = target{ifb.Attrs().Index, s.RateMbit}
		}
	}

	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, l := range links {
		name := l.Attrs().Name
		switch {
		case strings.HasPrefix(name, ifPrefix) && l.Type() == "wireguard":
			if t, ok := shaped[name]; ok {
				if err := ensureHTB(l, t.rate); err != nil {
					return fmt.Errorf("shape %s egress: %w", name, err)
				}
				if err := ensureRedirect(l, t.ifb); err != nil {
					return fmt.Errorf("shape %s ingress: %w", name, err)
				}
			} else if err := removeShaping(l); err != nil {
				return fmt.Errorf("unshape %s: %w", name, err)
			}
		case l.Type() == "ifb" && l.Attrs().Alias == shapeAlias && !wantIFB[name]:
			if err := netlink.LinkDel(l); err != nil {
				return fmt.Errorf("remove %s: %w", name, err)
			}
		}
	}
	return nil
}

func ensureIFB(name string) (netlink.Link, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if !errors.As(err, &nf) {
			return nil, err
		}
		la := netlink.NewLinkAttrs()
		la.Name = name
		if err := netlink.LinkAdd(&netlink.Ifb{LinkAttrs: la}); err != nil {
			return nil, fmt.Errorf("create %s (is the ifb kernel module available?): %w", name, err)
		}
		if link, err = netlink.LinkByName(name); err != nil {
			return nil, err
		}
	} else if link.Type() != "ifb" {
		return nil, fmt.Errorf("%s exists and is not an IFB device", name)
	}
	if link.Attrs().Alias != shapeAlias {
		if err := netlink.LinkSetAlias(link, shapeAlias); err != nil {
			return nil, err
		}
	}
	return link, netlink.LinkSetUp(link)
}

// ensureHTB gives link a root HTB whose default class 1:10 runs at rateMbit,
// with an fq_codel leaf.
func ensureHTB(link netlink.Link, rateMbit int) error {
	qs, err := netlink.QdiscList(link)
	if errors.Is(err, unix.EOPNOTSUPP) {
		return fmt.Errorf("bandwidth caps need traffic control, which this kernel does not support: %w", err)
	}
	if err != nil {
		return err
	}
	idx := link.Attrs().Index
	haveRoot, haveLeaf := false, false
	for _, q := range qs {
		a := q.Attrs()
		switch {
		case a.Parent == netlink.HANDLE_ROOT && q.Type() == "htb" && a.Handle == htbRoot:
			haveRoot = true
		case a.Parent == htbClass && q.Type() == "fq_codel":
			haveLeaf = true
		}
	}
	if !haveRoot {
		q := netlink.NewHtb(netlink.QdiscAttrs{LinkIndex: idx, Handle: htbRoot, Parent: netlink.HANDLE_ROOT})
		q.Defcls = 0x10
		if err := netlink.QdiscReplace(q); err != nil {
			return fmt.Errorf("root htb: %w", err)
		}
		haveLeaf = false
	}
	bits := uint64(rateMbit) * 1_000_000 //nolint:gosec // G115: rate_mbit is validated to 1-100000
	bytes := bits / 8
	// A 10 ms burst (at least 32 KiB) keeps virtual devices that send in
	// bursts from being held well below the rate.
	burst := uint32(max(bytes/100, 32<<10)) //nolint:gosec // G115: bytes/100 of a rate capped at 100000 Mbit/s fits in uint32
	quantum := uint32(min(max(bytes/10, 1600), 200000))
	class := netlink.NewHtbClass(
		netlink.ClassAttrs{LinkIndex: idx, Parent: htbRoot, Handle: htbClass},
		netlink.HtbClassAttrs{Rate: bits, Ceil: bits, Buffer: burst, Cbuffer: burst, Quantum: quantum},
	)
	if err := netlink.ClassReplace(class); err != nil {
		return fmt.Errorf("htb class: %w", err)
	}
	if !haveLeaf {
		leaf := netlink.NewFqCodel(netlink.QdiscAttrs{LinkIndex: idx, Handle: leafHandle, Parent: htbClass})
		if err := netlink.QdiscReplace(leaf); err != nil {
			return fmt.Errorf("fq_codel leaf: %w", err)
		}
	}
	return nil
}

// ensureRedirect sends everything link receives through the IFB ifb.
func ensureRedirect(link netlink.Link, ifb int) error {
	idx := link.Attrs().Index
	if ok, err := hasRedirect(link, ifb); err != nil || ok {
		return err
	}
	// Recreating the ingress qdisc drops whatever filters it had.
	if err := delIngress(link); err != nil {
		return err
	}
	if err := netlink.QdiscAdd(&netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: idx, Handle: ingressQ, Parent: netlink.HANDLE_INGRESS}}); err != nil {
		return fmt.Errorf("ingress qdisc: %w", err)
	}
	f := &netlink.MatchAll{
		FilterAttrs: netlink.FilterAttrs{LinkIndex: idx, Parent: ingressQ, Priority: 1, Protocol: unix.ETH_P_ALL},
		Actions:     []netlink.Action{netlink.NewMirredAction(ifb)},
	}
	if err := netlink.FilterAdd(f); err != nil {
		return fmt.Errorf("redirect filter: %w", err)
	}
	return nil
}

func hasRedirect(link netlink.Link, ifb int) (bool, error) {
	qs, err := netlink.QdiscList(link)
	if err != nil {
		return false, err
	}
	found := false
	for _, q := range qs {
		if q.Type() == "ingress" {
			found = true
		}
	}
	if !found {
		return false, nil
	}
	fs, err := netlink.FilterList(link, ingressQ)
	if err != nil {
		return false, err
	}
	if len(fs) != 1 {
		return false, nil
	}
	m, ok := fs[0].(*netlink.MatchAll)
	if !ok || len(m.Actions) != 1 {
		return false, nil
	}
	a, ok := m.Actions[0].(*netlink.MirredAction)
	return ok && a.Ifindex == ifb && a.MirredAction == netlink.TCA_EGRESS_REDIR, nil
}

func delIngress(link netlink.Link) error {
	qs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, q := range qs {
		if q.Type() == "ingress" {
			if err := netlink.QdiscDel(q); err != nil {
				return fmt.Errorf("remove ingress qdisc: %w", err)
			}
		}
	}
	return nil
}

// removeShaping undoes ensureHTB and ensureRedirect on a tunnel that is no
// longer shaped.
func removeShaping(link netlink.Link) error {
	qs, err := netlink.QdiscList(link)
	if errors.Is(err, unix.EOPNOTSUPP) {
		// A kernel without traffic control has nothing to remove.
		return nil
	}
	if err != nil {
		return err
	}
	for _, q := range qs {
		a := q.Attrs()
		if a.Parent == netlink.HANDLE_ROOT && q.Type() == "htb" && a.Handle == htbRoot {
			if err := netlink.QdiscDel(q); err != nil {
				return fmt.Errorf("remove root htb: %w", err)
			}
		}
	}
	return delIngress(link)
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ingressd/ingressd/internal/connector/client"
)

// printStatus prints the connector state: a summary of the best edge (as
// before multi-edge) followed by one line per edge.
func printStatus(out io.Writer, st *client.State, s *client.Status, now time.Time) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "Edge:\t%s\n", st.Primary().URL)
	fmt.Fprintf(w, "Tunnel:\t%s (subnets %s)\n", st.Tunnel(), strings.Join(st.Subnets(), ", "))
	fmt.Fprintf(w, "Mode:\t%s\n", st.Mode)
	if st.Mode == "tun" {
		m := "on"
		if !st.Masquerade {
			m = "off (LAN hosts must route replies back through this machine; turn it on unless this host is the LAN's router)"
		}
		fmt.Fprintf(w, "Masquerade:\t%s\n", m)
	}
	if s == nil {
		fmt.Fprintf(w, "State:\tnot running (no status file)\n")
		for i, e := range st.Edges {
			fmt.Fprintf(w, "Edge %d:\t%s site %s\n", i+1, edgeLabel(e.Node, e.URL, e.Config.Endpoint), e.Config.Address)
		}
		return w.Flush()
	}
	up := 0
	for _, e := range s.Edges {
		if e.Up(now) {
			up++
		}
	}
	state := "connecting"
	if s.Transport != "" {
		state = "up"
	}
	if len(s.Edges) > 1 {
		state += fmt.Sprintf(" (%d of %d edges up)", up, len(s.Edges))
	}
	if age := now.Sub(s.Time); age > 30*time.Second {
		state = fmt.Sprintf("stale (status %s old; is it running?)", age.Round(time.Second))
	}
	fmt.Fprintf(w, "State:\t%s\n", state)
	if s.LANFilterOff {
		fmt.Fprintf(w, "LAN filter:\tNOT ENFORCED: nftables could not be set up, so the allowlist has no effect on this host\n")
	}
	fmt.Fprintf(w, "Link:\t%s\n", s.Interface)
	fmt.Fprintf(w, "Transport:\t%s %s\n", s.Transport, s.Endpoint)
	fmt.Fprintf(w, "MTU:\t%d\n", s.MTU)
	fmt.Fprintf(w, "Last handshake:\t%s\n", ago(now, s.LastHandshake))
	fmt.Fprintf(w, "Traffic:\trx %d B, tx %d B\n", s.RxBytes, s.TxBytes)
	if s.PollError != "" {
		fmt.Fprintf(w, "Control channel:\terror: %s\n", s.PollError)
	} else if !s.LastPoll.IsZero() {
		fmt.Fprintf(w, "Control channel:\tok (last poll %s)\n", ago(now, s.LastPoll))
	}
	for i, e := range s.Edges {
		st := "down"
		if e.Up(now) {
			st = "up"
		} else if e.Transport == "" {
			st = "connecting"
		}
		ctl := "ok"
		switch {
		case e.PollError != "":
			ctl = "error: " + e.PollError
		case e.LastPoll.IsZero():
			ctl = "not yet"
		}
		learned := ""
		if e.Learned {
			learned = " (learned)"
		}
		fmt.Fprintf(w, "Edge %d:\t%s%s site %s: %s %s %s, handshake %s, control %s\n", i+1,
			edgeLabel(e.Node, e.URL, e.EdgeAddress), learned, e.Address, st, cmp.Or(e.Transport, "-"), e.Endpoint, ago(now, e.LastHandshake), ctl)
	}
	return w.Flush()
}

func edgeLabel(node, url, fallback string) string {
	if node != "" && url != "" {
		return node + " " + url
	}
	return cmp.Or(node, url, fallback)
}

func ago(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return now.Sub(t).Round(time.Second).String() + " ago"
}

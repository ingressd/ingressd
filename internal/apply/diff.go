// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/pmezard/go-difflib/difflib"

	"github.com/ingressd/ingressd/internal/render"
)

// Diff describes what applying next would change relative to prev (which
// may be nil). redact is applied to both sides so secrets never print.
// It returns "" when nothing would change.
func Diff(prev, next *render.Plan, redact func(string) string) string {
	var a, b planText
	if prev != nil {
		a = textOf(prev)
	}
	b = textOf(next)
	var out strings.Builder
	for _, s := range []struct{ name, a, b string }{
		{"caddy.json", a.caddy, b.caddy},
		{"nftables", a.nft, b.nft},
		{"network", a.network, b.network},
	} {
		if s.a == s.b {
			continue
		}
		d, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
			A:        difflib.SplitLines(redact(s.a)),
			B:        difflib.SplitLines(redact(s.b)),
			FromFile: s.name + " (applied)",
			ToFile:   s.name + " (new)",
			Context:  3,
		})
		out.WriteString(d)
	}
	return out.String()
}

type planText struct{ caddy, nft, network string }

func textOf(p *render.Plan) planText {
	var c bytes.Buffer
	if err := json.Indent(&c, p.Caddy, "", "  "); err != nil {
		c.Write(p.Caddy)
	}
	n, _ := json.MarshalIndent(p.Network, "", "  ")
	return planText{caddy: c.String() + "\n", nft: p.NFT, network: string(n) + "\n"}
}

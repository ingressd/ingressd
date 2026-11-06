// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// A connector learns about edges from edges, so one whose edges are all
// gone cannot find the rest of its site by itself: after rescueAfter
// without a live tunnel it asks the panel, every rescueEvery until a tunnel
// comes up.
const (
	rescueAfter   = 90 * time.Second
	rescueEvery   = time.Minute
	rescueTimeout = 15 * time.Second
)

// panelClient asks the panel for edges. An edge names the panel, so a reply
// from there is not followed anywhere else.
var panelClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// rescueDue tracks isolation and reports whether to ask the panel now.
func (s *session) rescueDue(up bool, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if up {
		s.isolated = time.Time{}
		return false
	}
	if s.isolated.IsZero() {
		s.isolated = now
	}
	if now.Sub(s.isolated) < rescueAfter || now.Sub(s.rescued) < rescueEvery {
		return false
	}
	s.rescued = now
	return true
}

// rescueTick runs from manage's ticker.
func (s *session) rescueTick(ctx context.Context, now time.Time) {
	s.mu.Lock()
	edges := make([]*edge, 0, len(s.edges))
	for _, e := range s.edges {
		edges = append(edges, e)
	}
	s.mu.Unlock()
	up := false
	for _, e := range edges {
		up = up || e.tunnelUp()
	}
	if s.rescueDue(up, now) {
		go func() {
			if err := s.rescue(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("could not get this site's edges from the panel", "err", err)
			}
		}()
	}
}

// rescue fetches the site's edges from the panel and adds the ones missing.
func (s *session) rescue(ctx context.Context) error {
	st := s.stateCopy()
	panel := ""
	for _, es := range st.Edges {
		if es.Config.PanelURL != "" {
			panel = es.Config.PanelURL
		}
	}
	if panel == "" {
		return errors.New("no panel known (no edge has told this connector its address)")
	}
	if u, err := url.Parse(panel); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("panel address %q is not an https URL", panel)
	}
	id, err := age.ParseX25519Identity(st.AgeIdentity)
	if err != nil {
		return fmt.Errorf("age identity: %w", err)
	}
	connector := s.priv.PublicKey().String()
	body, _ := json.Marshal(nodeproto.ConnectorEdgesRequest{Connector: connector})
	ctx, cancel := context.WithTimeout(ctx, rescueTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(panel, "/")+nodeproto.PathConnectorEdges, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := panelClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("panel answered %s", resp.Status)
	}
	var out nodeproto.ConnectorEdgesResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return err
	}
	signed, err := openEdges(out.Sealed, id)
	if err != nil {
		return err
	}
	return s.applyRescue(signed, connector)
}

func openEdges(sealed string, id *age.X25519Identity) (nodeproto.SignedEdges, error) {
	var out nodeproto.SignedEdges
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(sealed)), id)
	if err != nil {
		return out, fmt.Errorf("edge list: %w", err)
	}
	b, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return out, err
	}
	return out, json.Unmarshal(b, &out)
}

// applyRescue checks a signed edge list and merges it into the state.
func (s *session) applyRescue(e nodeproto.SignedEdges, connector string) error {
	if err := e.Verify(connector); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.OrgKey != "" && e.Key != s.st.OrgKey {
		return errors.New("edge list signed by another org key than the pinned one")
	}
	if e.Issued.Before(s.st.RescueIssued) {
		return errors.New("edge list is older than the last one accepted")
	}
	parent := s.st.Primary().Config
	added, moved := 0, 0
	for _, x := range e.Edges {
		sb, err := rescueSibling(x)
		if err != nil {
			s.log.Warn("skipping an edge from the panel", "edge", x.Endpoint, "err", err)
			continue
		}
		es := s.st.Edge(sb.EdgePublicKey)
		switch {
		case es == nil:
			s.st.Edges = append(s.st.Edges, EdgeState{URL: urlFromWS(sb.WSURL), Node: sb.Node, Learned: true, Config: siblingConfig(parent, sb)})
			added++
		case es.Config.Endpoint != sb.Endpoint:
			es.Config.Endpoint, es.Config.WSURL = sb.Endpoint, sb.WSURL
			s.restartEdge[sb.EdgePublicKey] = true
			moved++
		}
	}
	if s.st.OrgKey == "" {
		s.st.OrgKey = e.Key
	}
	s.st.RescueIssued = e.Issued
	if err := s.st.Save(s.r.StatePath); err != nil {
		s.log.Warn("save state", "err", err)
	}
	s.log.Info("edges from the panel", "listed", len(e.Edges), "added", added, "moved", moved)
	s.triggerRefresh()
	return nil
}

func rescueSibling(x nodeproto.RescueEdge) (proto.Sibling, error) {
	p, err := netip.ParsePrefix(x.Transit)
	if err != nil || !p.Addr().Is4() {
		return proto.Sibling{}, fmt.Errorf("transit %q", x.Transit)
	}
	if _, err := wgtypes.ParseKey(x.EdgePublicKey); err != nil || x.Endpoint == "" {
		return proto.Sibling{}, errors.New("edge key or endpoint missing")
	}
	edge := p.Masked().Addr().Next()
	return proto.Sibling{Node: x.Node, Endpoint: x.Endpoint, EdgePublicKey: x.EdgePublicKey,
		Address: netip.PrefixFrom(edge.Next(), p.Bits()).String(), EdgeAddress: edge.String(),
		WSURL: x.WSURL, Priority: x.Priority, PoP: x.PoP}, nil
}

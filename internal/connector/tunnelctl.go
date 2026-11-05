// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/pkg/config"
)

// tunnelPeerKey marks a request that arrived through a tunnel from the
// site's transit address (see TunnelControlHandler).
type tunnelPeerKey struct{}

// TunnelControlHandler serves the connector endpoints (poll, report,
// discovery) on proto.TunnelControlPort. Only requests from a connector
// tunnel's site address to that tunnel's edge address are answered, and
// they need no credential: WireGuard only lets the site's peer use the
// site address, and the managed firewall only admits the port on the
// tunnel interface. This lets a connector that enrolled on another node of
// a multi-PoP site talk to this node.
func (s *Server) TunnelControlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+proto.PollPath, s.poll)
	mux.HandleFunc("POST "+proto.ReportPath, s.report)
	mux.HandleFunc("POST "+proto.DiscoveryPath, s.discovery)
	mux.HandleFunc("GET "+proto.ReleasePathPrefix+"{asset}", s.serveRelease)
	mux.Handle(proto.LegacyMachinePrefix, proto.ServeLegacyPrefix(mux))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tunnel, ok := s.tunnelPeer(r)
		if !ok {
			http.Error(w, "forbidden: not from a connector tunnel's site address", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tunnelPeerKey{}, tunnel)))
	})
}

// tunnelPeer maps (local, remote) address to the connector tunnel whose
// edge and site transit addresses they are.
func (s *Server) tunnelPeer(r *http.Request) (string, bool) {
	la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return "", false
	}
	local, err := netip.ParseAddrPort(la.String())
	if err != nil {
		return "", false
	}
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}
	cfg, _, _ := s.snapshot()
	if cfg == nil {
		return "", false
	}
	return TunnelForPeer(cfg, local.Addr().Unmap(), remote.Addr().Unmap())
}

// TunnelForPeer returns the connector tunnel whose edge transit address is
// local and site transit address is remote.
func TunnelForPeer(cfg *config.Config, local, remote netip.Addr) (string, bool) {
	for name, t := range cfg.Tunnels {
		if t.Site != config.SiteConnector {
			continue
		}
		p, err := netip.ParsePrefix(t.Transit)
		if err != nil {
			continue
		}
		if render.EdgeAddr(p) == local && render.SiteAddr(p) == remote {
			return name, true
		}
	}
	return "", false
}

// edgeSecrets is implemented by tunnel.Keys: what IngressdKey verification
// needs.
type edgeSecrets interface {
	EdgePrivate(tunnel string) (string, error)
	SitePublic(tunnel string) (string, error)
}

// keyAuth verifies a IngressdKey header (proto.KeyAuth) against the edge's
// private key and the site key this node accepts for the tunnel.
func (s *Server) keyAuth(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	tunnel, ok := proto.ParseKeyAuth(h)
	if !ok {
		return "", false
	}
	cfg, keys, _ := s.snapshot()
	if cfg == nil {
		return "", false
	}
	if t, ok := cfg.Tunnels[tunnel]; !ok || t.Site != config.SiteConnector {
		return "", false
	}
	ks, ok := keys.(edgeSecrets)
	if !ok {
		return "", false
	}
	priv, err1 := ks.EdgePrivate(tunnel)
	pub, err2 := ks.SitePublic(tunnel)
	if err1 != nil || err2 != nil {
		return "", false
	}
	pk, err1 := base64.StdEncoding.DecodeString(priv)
	sk, err2 := base64.StdEncoding.DecodeString(pub)
	if err1 != nil || err2 != nil {
		return "", false
	}
	var body []byte
	if proto.KeyAuthVersion(h) == proto.KeyAuthV2 && r.Body != nil && r.Body != http.NoBody {
		// v2 covers the body: read it here and hand the handler a copy.
		b, err := io.ReadAll(io.LimitReader(r.Body, maxKeyAuthBody+1))
		if err != nil || len(b) > maxKeyAuthBody {
			return "", false
		}
		r.Body, body = io.NopCloser(bytes.NewReader(b)), b
	}
	now := s.now()
	ver, nonce, err := proto.CheckKeyAuthRequest(h, pk, sk, now, r.Method, r.URL.Path, body)
	if err == nil && ver == proto.KeyAuthV2 && !s.replay.add(tunnel+"/"+nonce, now) {
		err = errors.New("replayed (nonce already used)")
	}
	if err != nil {
		s.log().Debug("connector key auth rejected", "tunnel", tunnel, "version", ver, "err", err)
		return "", false
	}
	return tunnel, true
}

// maxKeyAuthBody caps a body read for v2 key auth (the largest connector
// request, a discovery report, is capped at 1 MiB too).
const maxKeyAuthBody = 1 << 20

// replayCache remembers the nonces of accepted v2 IngressdKey headers
// until their timestamps can no longer pass the skew check, so each header
// authorises one request.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time // nonce key -> when it may be forgotten
}

// maxReplayEntries bounds the cache (only headers with a valid MAC get in,
// so only enrolled sites can fill it).
const maxReplayEntries = 1 << 16

// add records key and reports whether it was new.
func (c *replayCache) add(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	if until, ok := c.seen[key]; ok && now.Before(until) {
		return false
	}
	if len(c.seen) >= maxReplayEntries {
		for k, until := range c.seen {
			if !now.Before(until) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= maxReplayEntries {
			return false
		}
	}
	// A timestamp is accepted up to KeyAuthSkew either side of now, so the
	// header stays valid for at most 2*KeyAuthSkew from here.
	c.seen[key] = now.Add(2 * proto.KeyAuthSkew)
	return true
}

// siblings converts a tunnel's configured siblings for the connector.
func siblings(t config.Tunnel) []proto.Sibling {
	var out []proto.Sibling
	for _, sb := range t.Siblings {
		p, err := netip.ParsePrefix(sb.Transit)
		if err != nil || sb.EdgePublicKey == "" || sb.Endpoint == "" {
			continue
		}
		out = append(out, proto.Sibling{
			Node:          sb.Node,
			Endpoint:      sb.Endpoint,
			EdgePublicKey: sb.EdgePublicKey,
			Address:       netip.PrefixFrom(render.SiteAddr(p), p.Bits()).String(),
			EdgeAddress:   render.EdgeAddr(p).String(),
			WSURL:         sb.WSURL,
			Priority:      sb.Priority,
			PoP:           sb.PoP,
		})
	}
	return out
}

// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/pkg/nodeproto"
	"github.com/ingressd/ingressd/test/fakepanel"
)

func TestHelloAdvertisesTrustCapabilities(t *testing.T) {
	h := newHarness(t)
	h.start()
	defer h.stop()
	caps := h.panel.State().Hello.Capabilities
	for _, c := range []string{nodeproto.CapabilitySnapshotV2, nodeproto.CapabilitySignedRequests} {
		if !slices.Contains(caps, c) {
			t.Errorf("hello capabilities %v lack %s", caps, c)
		}
	}
}

func TestSnapshotV2Enforced(t *testing.T) {
	h := newHarness(t)
	h.start()
	defer h.stop()
	if a, err := h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{}); err != nil || !a.OK {
		t.Fatalf("v2 snapshot: %+v %v", a, err)
	}
	rejected := func(name string, o fakepanel.SnapshotOptions, want string) {
		t.Helper()
		a, err := h.panel.SendSnapshot(h.ctx(), testConfig+"# "+name+"\n", o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if a.OK || !strings.Contains(a.Error, want) {
			t.Errorf("%s: applied = %+v, want rejection containing %q", name, a, want)
		}
	}
	// An old panel's (or a captured) v1 snapshot: no downgrade.
	rejected("legacy v1", fakepanel.SnapshotOptions{Legacy: true, Force: true}, "legacy")
	// Signed for another node of the same org.
	rejected("other node", fakepanel.SnapshotOptions{ForNode: "nod_other", Force: true}, "not this node")
	// Captured long ago and replayed (rollback).
	rejected("expired", fakepanel.SnapshotOptions{SignedAt: time.Now().Add(-time.Hour), Force: true}, "expired")
	rejected("future", fakepanel.SnapshotOptions{SignedAt: time.Now().Add(time.Hour)}, "future")

	// A forced snapshot applies once; the identical message replayed
	// within its validity window is refused.
	if a, _ := h.panel.SendSnapshot(h.ctx(), testConfig+"# forced\n", fakepanel.SnapshotOptions{Revision: 1, Force: true}); !a.OK {
		t.Fatalf("forced snapshot: %+v", a)
	}
	if a, _ := h.panel.SendSnapshot(h.ctx(), testConfig+"# newer\n", fakepanel.SnapshotOptions{Revision: 2}); !a.OK {
		t.Fatalf("revision 2: %+v", a)
	}
	h.panel.SendSnapshot(h.ctx(), testConfig+"# forced again\n", fakepanel.SnapshotOptions{Revision: 1, Force: true})
	a, err := h.panel.SendSnapshot(h.ctx(), "", fakepanel.SnapshotOptions{Replay: true})
	if err != nil {
		t.Fatal(err)
	}
	if a.OK || !strings.Contains(a.Error, "replayed") {
		t.Fatalf("replayed forced snapshot: %+v", a)
	}
}

func TestSignedRequestsEnforced(t *testing.T) {
	h := newHarness(t)
	h.start()
	defer h.stop()
	if a, _ := h.panel.SendSnapshot(h.ctx(), testConfig, fakepanel.SnapshotOptions{}); !a.OK {
		t.Fatalf("snapshot: %+v", a)
	}

	// Unsigned: refused, with an answer so the panel does not time out.
	env, err := h.panel.RequestUnsigned(h.ctx(), nodeproto.TypeSiteConfigRequest, nodeproto.SiteConfigRequest{Site: "home"})
	if err != nil {
		t.Fatal(err)
	}
	var sc nodeproto.SiteConfig
	if err := env.Decode(&sc); err != nil || sc.Config != "" || !strings.Contains(sc.Error, "unsigned") {
		t.Fatalf("unsigned site_config_request answered: %+v %v", sc, err)
	}
	env, err = h.panel.RequestUnsigned(h.ctx(), nodeproto.TypeConnectorTokenRequest, nodeproto.ConnectorTokenRequest{Site: "home"})
	if err != nil {
		t.Fatal(err)
	}
	var ct nodeproto.ConnectorToken
	if err := env.Decode(&ct); err != nil || ct.JoinString != "" || !strings.Contains(ct.Error, "unsigned") {
		t.Fatalf("unsigned connector_token_request answered: %+v %v", ct, err)
	}

	// Signed: handled (the answer is about the site, not the signature).
	env, err = h.panel.Request(h.ctx(), nodeproto.TypeSiteConfigRequest, nodeproto.SiteConfigRequest{Site: "nosuchsite"})
	if err != nil {
		t.Fatal(err)
	}
	sc = nodeproto.SiteConfig{}
	if err := env.Decode(&sc); err != nil || !strings.Contains(sc.Error, "unknown site") {
		t.Fatalf("signed site_config_request: %+v %v", sc, err)
	}

	// A captured signed request replayed verbatim is refused.
	b, err := h.panel.SignedEnvelope(nodeproto.TypeSiteConfigRequest, "replay-1", nodeproto.SiteConfigRequest{Site: "nosuchsite"})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := h.panel.SendRaw(h.ctx(), b); err != nil {
			t.Fatal(err)
		}
	}
	h.wait("replay rejected", func(s fakepanel.State) bool {
		return slices.ContainsFunc(s.Events, func(e nodeproto.Event) bool {
			return e.Kind == "request_rejected" && strings.Contains(e.Message, "replayed")
		})
	})

	// An unsigned detach is ignored: the node stays managed.
	if err := h.panel.SendUnsigned(h.ctx(), nodeproto.TypeDetach, "", nodeproto.Detach{Reason: "forged"}); err != nil {
		t.Fatal(err)
	}
	h.wait("detach rejected", func(s fakepanel.State) bool {
		return slices.ContainsFunc(s.Events, func(e nodeproto.Event) bool {
			return e.Kind == "request_rejected" && e.Fields["type"] == nodeproto.TypeDetach
		})
	})
	if !Managed(h.opts.StateDir) {
		t.Fatal("an unsigned detach detached the node")
	}
	// A signed one detaches it.
	if err := h.panel.Send(h.ctx(), nodeproto.TypeDetach, "", nodeproto.Detach{Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.agent.Detached():
	case <-time.After(10 * time.Second):
		t.Fatal("signed detach did not detach the node")
	}
}

func TestReplayCacheExpires(t *testing.T) {
	var c replayCache
	now := time.Now()
	if !c.add("a", now.Add(time.Minute), now) || c.add("a", now.Add(time.Minute), now) {
		t.Fatal("duplicate within the window not detected")
	}
	later := now.Add(time.Minute + nodeproto.MaxClockSkew + time.Second)
	if !c.add("b", later.Add(time.Minute), later) || len(c.seen) != 1 {
		t.Fatalf("expired entries not dropped: %v", c.seen)
	}
}

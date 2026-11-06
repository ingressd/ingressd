// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/smartdns"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

func signedSite(t *testing.T, key ed25519.PrivateKey, connector string, issued time.Time, cfg config.SmartDNSSite) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	env := nodeproto.SignedSmartDNS{Connector: connector, Issued: issued, Config: b}
	nodeproto.SignSmartDNS(&env, key)
	out, _ := json.Marshal(env)
	return out
}

func nodeExitSite() config.SmartDNSSite {
	return config.SmartDNSSite{
		Listen:   "127.0.0.1",
		Services: map[string]config.SmartDNSSiteService{"npo": {Domains: []string{"npo.nl"}, Exits: []string{"nl-vps"}}},
		Exits:    map[string]config.SmartDNSSiteExit{"nl-vps": {At: config.ExitAtNode, Node: "nod_ams", Country: "NL"}},
	}
}

func fakeListen(string, string) (net.Listener, error) { return nil, errors.New("not in tests") }
func fakeListenPacket(string, string) (net.PacketConn, error) {
	return nil, errors.New("not in tests")
}

func newTestController(t *testing.T) (*sdController, *session) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	k, _ := wgtypes.GeneratePrivateKey()
	st := &State{Mode: ModeNetstack, PrivateKey: k.String(), Edges: []EdgeState{{Node: "nod_ams", Config: proto.TunnelConfig{Tunnel: "home", EdgeAddress: "100.64.0.5"}}}}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	s := &session{r: &Runner{StatePath: path}, st: st, priv: k, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &sdController{statePath: path, log: s.log, vpns: map[string]*vpnExit{}, ctx: ctx}
	c.mgr = smartdns.New(smartdns.Options{Listen: fakeListen, ListenPacket: fakeListenPacket})
	id, _, err := ensureAgeIdentity(st)
	if err != nil {
		t.Fatal(err)
	}
	c.attach(s, id)
	return c, s
}

func setBlob(s *session, raw json.RawMessage) {
	s.mu.Lock()
	s.st.Edges[0].Config.SmartDNS = raw
	s.mu.Unlock()
}

func TestSmartDNSConfigTrust(t *testing.T) {
	c, s := newTestController(t)
	_, key, _ := ed25519.GenerateKey(nil)
	me := s.priv.PublicKey().String()
	_, other, _ := ed25519.GenerateKey(nil)
	t0 := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

	setBlob(s, signedSite(t, key, me, t0, nodeExitSite()))
	c.update()
	r := c.report()
	if r.Error != "" || r.Listen != "127.0.0.1" || !r.Issued.Equal(t0) || !strings.HasPrefix(r.AgeRecipient, "age1") {
		t.Fatalf("first config: %+v", r)
	}
	if len(r.Services) != 1 || r.Services[0].Name != "npo" {
		t.Errorf("services %+v", r.Services)
	}
	saved, err := LoadState(s.r.StatePath)
	if err != nil || saved.OrgKey == "" || !saved.SmartDNSIssued.Equal(t0) {
		t.Fatalf("state not pinned: %+v (%v)", saved, err)
	}

	// Another org's key, a tampered config, another site and an older
	// config are all refused; the config in effect stays.
	setBlob(s, signedSite(t, other, me, t0.Add(time.Minute), nodeExitSite()))
	c.update()
	if r := c.report(); !strings.Contains(r.Error, "another org key") || !r.Issued.Equal(t0) {
		t.Errorf("other key: %+v", r)
	}
	tampered := signedSite(t, key, me, t0.Add(time.Minute), nodeExitSite())
	tampered = bytes.Replace(tampered, []byte("npo.nl"), []byte("bank.example"), 1)
	setBlob(s, tampered)
	c.update()
	if r := c.report(); !strings.Contains(r.Error, "bad org signature") || r.Listen != "127.0.0.1" || len(r.Services) != 1 {
		t.Errorf("tampered config must leave the config in effect running: %+v", r)
	}
	setBlob(s, signedSite(t, key, "someone-else", t0.Add(time.Minute), nodeExitSite()))
	c.update()
	if r := c.report(); !strings.Contains(r.Error, `for connector "someone-else"`) {
		t.Errorf("other site: %+v", r)
	}
	// An edge offering an older config changes nothing, also after a restart.
	c.mu.Lock()
	c.applied = ""
	c.mu.Unlock()
	setBlob(s, signedSite(t, key, me, t0.Add(-time.Minute), nodeExitSite()))
	c.update()
	if r := c.report(); r.Error != "" || !r.Issued.Equal(t0) || r.Listen != "127.0.0.1" {
		t.Errorf("replay: %+v", r)
	}

	// An invalid config is refused with its validation error.
	bad := nodeExitSite()
	bad.Exits["nl-vps"] = config.SmartDNSSiteExit{At: config.ExitAtOperator, Country: "NL"}
	setBlob(s, signedSite(t, key, me, t0.Add(2*time.Minute), bad))
	c.update()
	if r := c.report(); !strings.Contains(r.Error, "operator exits are not offered") {
		t.Errorf("invalid: %+v", r)
	}

	// With no edge carrying a config, as with every edge down, Smart DNS
	// keeps running, also after a restart.
	setBlob(s, nil)
	c.update()
	if r := c.report(); r.Listen != "127.0.0.1" || len(r.Services) != 1 {
		t.Errorf("edges gone: %+v", r)
	}
	c.mu.Lock()
	c.applied, c.listen = "", ""
	c.mu.Unlock()
	c.update()
	if r := c.report(); r.Listen != "127.0.0.1" || len(r.Services) != 1 || r.Error != "" {
		t.Errorf("restart with no edges: %+v", r)
	}

	// Only a signed config without exits turns it off.
	setBlob(s, signedSite(t, key, me, t0.Add(3*time.Minute), config.SmartDNSSite{}))
	c.update()
	if r := c.report(); r.Listen != "" || len(r.Services) != 0 || r.Error != "" {
		t.Errorf("off: %+v", r)
	}
}

func TestSmartDNSNodeExitLookup(t *testing.T) {
	c, s := newTestController(t)
	if a, ok := c.nodeAddr("nod_ams"); ok {
		t.Errorf("node address %v before the edge runs", a)
	}
	e := &edge{s: s, cfg: s.st.Edges[0]}
	s.mu.Lock()
	s.edges = map[wgtypes.Key]*edge{{}: e}
	s.mu.Unlock()
	if a, ok := c.nodeAddr("nod_ams"); !ok || a.String() != "100.64.0.5" {
		t.Errorf("node address %v %v", a, ok)
	}
	if _, ok := c.nodeAddr("nod_other"); ok {
		t.Error("unknown node resolved")
	}
	if _, err := c.dialTunnel(context.Background(), "udp4", "100.64.0.5:53"); err == nil {
		t.Error("UDP to a node exit allowed")
	}
}

func TestSmartDNSDecryptVPN(t *testing.T) {
	c, _ := newTestController(t)
	enc := func(armored bool) string {
		var buf bytes.Buffer
		var w io.WriteCloser = &nopCloser{&buf}
		var aw io.WriteCloser
		if armored {
			aw = armor.NewWriter(&buf)
			w = aw
		}
		ew, err := age.Encrypt(w, c.age.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(ew, "[Interface]\nPrivateKey = x\n")
		_ = ew.Close()
		if aw != nil {
			_ = aw.Close()
		}
		if armored {
			return buf.String()
		}
		return b64(buf.Bytes())
	}
	for _, armored := range []bool{true, false} {
		got, err := c.decrypt(enc(armored))
		if err != nil || !strings.Contains(got, "PrivateKey = x") {
			t.Errorf("armored=%v: %q %v", armored, got, err)
		}
	}
	other, _ := age.GenerateX25519Identity()
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	ew, _ := age.Encrypt(aw, other.Recipient())
	_, _ = io.WriteString(ew, "secret")
	_ = ew.Close()
	_ = aw.Close()
	if _, err := c.decrypt(buf.String()); err == nil || !strings.Contains(err.Error(), "not encrypted to this connector") {
		t.Errorf("foreign ciphertext: %v", err)
	}
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestSmartDNSChangeIsReportedAtOnce(t *testing.T) {
	c, s := newTestController(t)
	e := &edge{s: s, cfg: s.st.Edges[0], kick: make(chan struct{}, 1)}
	s.mu.Lock()
	s.edges = map[wgtypes.Key]*edge{{}: e}
	s.mu.Unlock()
	kicked := func() bool {
		select {
		case <-e.kick:
			return true
		default:
			return false
		}
	}
	last := c.reportIfChanged("")
	if !kicked() {
		t.Fatal("first state not reported")
	}
	if last = c.reportIfChanged(last); kicked() {
		t.Fatal("reported without a change")
	}
	_, key, _ := ed25519.GenerateKey(nil)
	setBlob(s, signedSite(t, key, s.priv.PublicKey().String(), time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), nodeExitSite()))
	c.update()
	if c.reportIfChanged(last); !kicked() {
		t.Fatal("new config not reported")
	}
}

// A restart reads the config back from the state file, re-encoded.
func TestSmartDNSConfigSurvivesRestartFromDisk(t *testing.T) {
	c, s := newTestController(t)
	_, key, _ := ed25519.GenerateKey(nil)
	setBlob(s, signedSite(t, key, s.priv.PublicKey().String(), time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), nodeExitSite()))
	c.update()
	if err := s.st.Save(s.r.StatePath); err != nil {
		t.Fatal(err)
	}

	st, err := LoadState(s.r.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	st.Edges[0].Config.SmartDNS = nil // the edge is gone
	s2 := &session{r: s.r, st: st, priv: s.priv, log: s.log}
	c2 := &sdController{statePath: c.statePath, log: s.log, vpns: map[string]*vpnExit{}, ctx: c.ctx}
	c2.mgr = smartdns.New(smartdns.Options{Listen: fakeListen, ListenPacket: fakeListenPacket})
	id, _, err := ensureAgeIdentity(st)
	if err != nil {
		t.Fatal(err)
	}
	c2.attach(s2, id)
	if r := c2.report(); r.Error != "" || r.Listen != "127.0.0.1" || len(r.Services) != 1 {
		t.Fatalf("after a restart with the edge gone: %+v", r)
	}
}

func TestRescueAddsEdgesAndChecksTheList(t *testing.T) {
	_, s := newTestController(t)
	s.restartEdge = map[string]bool{}
	s.refresh = make(chan struct{}, 1)
	_, key, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	me := s.priv.PublicKey().String()
	nk, _ := wgtypes.GeneratePrivateKey()
	edgeKey := nk.PublicKey().String()
	t0 := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	list := func(k ed25519.PrivateKey, connector string, at time.Time) nodeproto.SignedEdges {
		e := nodeproto.SignedEdges{Connector: connector, Issued: at, Edges: []nodeproto.RescueEdge{
			{Node: "nod_new", Endpoint: "203.0.113.9:51830", EdgePublicKey: edgeKey, Transit: "100.112.0.8/30", WSURL: "wss://203.0.113.9/.ingressd/tunnel/t0"}}}
		nodeproto.SignEdges(&e, k)
		return e
	}
	if err := s.applyRescue(list(key, "someone-else", t0), me); err == nil {
		t.Fatal("list for another connector accepted")
	}
	if err := s.applyRescue(list(key, me, t0), me); err != nil {
		t.Fatal(err)
	}
	es := s.st.Edge(edgeKey)
	if es == nil || es.Node != "nod_new" || !es.Learned || es.Config.Address != "100.112.0.10/30" || es.Config.EdgeAddress != "100.112.0.9" {
		t.Fatalf("edge %+v", es)
	}
	if err := s.applyRescue(list(other, me, t0.Add(time.Minute)), me); err == nil {
		t.Fatal("list from another org key accepted")
	}
	if err := s.applyRescue(list(key, me, t0.Add(-time.Minute)), me); err == nil {
		t.Fatal("older list accepted")
	}
	tampered := list(key, me, t0.Add(time.Minute))
	tampered.Edges[0].Endpoint = "198.51.100.66:51820"
	if err := s.applyRescue(tampered, me); err == nil {
		t.Fatal("tampered list accepted")
	}
}

func TestRescueChecksTransitAddresses(t *testing.T) {
	_, s := newTestController(t)
	s.restartEdge = map[string]bool{}
	s.refresh = make(chan struct{}, 1)
	s.st.routes = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")} }
	_, key, _ := ed25519.GenerateKey(nil)
	me := s.priv.PublicKey().String()
	newKey := func() string {
		k, _ := wgtypes.GeneratePrivateKey()
		return k.PublicKey().String()
	}
	public, clash, good, known := newKey(), newKey(), newKey(), newKey()
	s.st.Edges = append(s.st.Edges, EdgeState{Config: proto.TunnelConfig{EdgePublicKey: known, Endpoint: "198.51.100.1:51830", Address: "203.0.113.22/30"}})
	e := nodeproto.SignedEdges{Connector: me, Issued: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), Edges: []nodeproto.RescueEdge{
		{Endpoint: "203.0.113.9:51830", EdgePublicKey: public, Transit: "203.0.113.8/30"},
		{Endpoint: "203.0.113.10:51830", EdgePublicKey: clash, Transit: "192.168.0.8/30"},
		{Endpoint: "203.0.113.11:51830", EdgePublicKey: good, Transit: "100.112.0.8/30"},
		{Endpoint: "203.0.113.12:51830", EdgePublicKey: known, Transit: "203.0.113.20/30"},
	}}
	nodeproto.SignEdges(&e, key)
	if err := s.applyRescue(e, me); err != nil {
		t.Fatal(err)
	}
	if s.st.Edge(public) != nil {
		t.Error("public transit added")
	}
	if s.st.Edge(clash) != nil {
		t.Error("transit over a local route added")
	}
	if s.st.Edge(good) == nil {
		t.Error("usable edge skipped")
	}
	// An edge already in use moves; its transit stays what it was.
	if es := s.st.Edge(known); es.Config.Endpoint != "203.0.113.12:51830" || es.Config.Address != "203.0.113.22/30" {
		t.Errorf("known edge %+v", es.Config)
	}
}

func TestRescueIsDueOnlyWhenIsolated(t *testing.T) {
	_, s := newTestController(t)
	t0 := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	if s.rescueDue(true, t0) || s.rescueDue(false, t0) || s.rescueDue(false, t0.Add(rescueAfter-time.Second)) {
		t.Fatal("asked too early")
	}
	if !s.rescueDue(false, t0.Add(rescueAfter)) {
		t.Fatal("not asked when isolated")
	}
	if s.rescueDue(false, t0.Add(rescueAfter+time.Second)) {
		t.Fatal("asked again at once")
	}
	if !s.rescueDue(false, t0.Add(rescueAfter+rescueEvery)) {
		t.Fatal("no retry")
	}
	if s.rescueDue(true, t0.Add(2*rescueAfter+rescueEvery)) || s.rescueDue(false, t0.Add(2*rescueAfter+rescueEvery+time.Second)) {
		t.Fatal("a live tunnel must reset the clock")
	}
}

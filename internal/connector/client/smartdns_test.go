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
	if r := c.report(); !strings.Contains(r.Error, "bad org signature") {
		t.Errorf("tampered: %+v", r)
	}
	setBlob(s, signedSite(t, key, "someone-else", t0.Add(time.Minute), nodeExitSite()))
	c.update()
	if r := c.report(); !strings.Contains(r.Error, `for connector "someone-else"`) {
		t.Errorf("other site: %+v", r)
	}
	c.mu.Lock()
	c.applied = "" // as after a restart: only the persisted issue time guards
	c.mu.Unlock()
	setBlob(s, signedSite(t, key, me, t0.Add(-time.Minute), nodeExitSite()))
	c.update()
	if r := c.report(); !strings.Contains(r.Error, "older than the one in effect") {
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

	// No edge carries a config: Smart DNS stops.
	setBlob(s, nil)
	c.update()
	if r := c.report(); r.Listen != "" || len(r.Services) != 0 {
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
		io.WriteString(ew, "[Interface]\nPrivateKey = x\n")
		ew.Close()
		if aw != nil {
			aw.Close()
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
	io.WriteString(ew, "secret")
	ew.Close()
	aw.Close()
	if _, err := c.decrypt(buf.String()); err == nil || !strings.Contains(err.Error(), "not encrypted to this connector") {
		t.Errorf("foreign ciphertext: %v", err)
	}
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// SPDX-License-Identifier: Apache-2.0

package wgconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const key = "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU="

func genKey(t *testing.T) string {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.String()
}

// sample loads a provider config from testdata with freshly generated keys
// in place of the {{PRIV}}, {{PUB}} and {{PSK}} placeholders (the samples
// are real provider layouts with keys and addresses redacted).
func sample(t *testing.T, name string) (string, map[string]string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{"PRIV": genKey(t), "PUB": genKey(t), "PSK": genKey(t)}
	s := string(b)
	for k, v := range keys {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s, keys
}

func TestParseProviderSamples(t *testing.T) {
	type want struct {
		addr, addr6, dns, endpoint string
		mtu, keepalive             int
		psk, full                  bool
	}
	for file, w := range map[string]want{
		"proton-gb-123.conf":         {addr: "10.2.0.2/32", dns: "10.2.0.1", endpoint: "203.0.113.45:51820", keepalive: 25, full: true},
		"mullvad-se-got-wg-001.conf": {addr: "10.64.12.34/32", addr6: "fc00:bbbb:bbbb:bb01::1:c22/128", dns: "10.64.0.1", endpoint: "203.0.113.70:51820", keepalive: 25, full: true},
		"ivpn-nl.conf":               {addr: "172.28.120.5/32", dns: "172.16.0.1", endpoint: "nl3.wg.example.net:2049", keepalive: 25, full: true},
		"airvpn-de.conf":             {addr: "10.150.12.80/32", addr6: "fd7d:76ee:e68f:a993:1a2b:3c4d:5e6f:7a8b/128", dns: "10.128.0.1", endpoint: "europe3.vpn.example.net:1637", mtu: 1320, keepalive: 15, psk: true, full: true},
		"windscribe-fr.conf":         {addr: "100.86.12.9/32", dns: "10.255.255.3", endpoint: "par-123-wg.example.net:443", keepalive: 25, psk: true, full: true},
	} {
		t.Run(file, func(t *testing.T) {
			text, keys := sample(t, file)
			c, err := Parse(text)
			if err != nil {
				t.Fatal(err)
			}
			addr6 := ""
			if c.Address6.IsValid() {
				addr6 = c.Address6.String()
			}
			dns := ""
			if len(c.DNS) > 0 {
				dns = c.DNS[0].String()
			}
			if c.PrivateKey != keys["PRIV"] || c.Peer.PublicKey != keys["PUB"] {
				t.Errorf("keys not parsed")
			}
			if (c.Peer.PresharedKey == keys["PSK"]) != w.psk {
				t.Errorf("psk = %q, want present=%v", c.Peer.PresharedKey, w.psk)
			}
			if c.Address.String() != w.addr || addr6 != w.addr6 || dns != w.dns || c.Peer.Endpoint != w.endpoint ||
				c.MTU != w.mtu || c.Peer.EffectiveKeepalive() != w.keepalive || c.FullTunnel() != w.full {
				t.Errorf("got addr=%s addr6=%s dns=%s endpoint=%s mtu=%d ka=%d full=%v", c.Address, addr6, dns, c.Peer.Endpoint, c.MTU, c.Peer.EffectiveKeepalive(), c.FullTunnel())
			}
		})
	}
}

func TestParseAirVPNDNS6(t *testing.T) {
	text, _ := sample(t, "airvpn-de.conf")
	c, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.DNS) != 1 || len(c.DNS6) != 1 || c.DNS6[0].String() != "fd7d:76ee:e68f:a993::1" {
		t.Errorf("dns %v dns6 %v", c.DNS, c.DNS6)
	}
}

func TestParseCRLFAndSplitTunnel(t *testing.T) {
	text := "\ufeff[Interface]\r\nPrivateKey = " + genKey(t) + "\r\nAddress = 10.2.0.2/32\r\n\r\n[Peer]\r\nPublicKey = " + genKey(t) +
		"\r\nAllowedIPs = 10.0.0.0/8\r\nEndpoint = 203.0.113.9:51820\r\nPersistentKeepalive = off\r\n"
	c, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if c.FullTunnel() || c.Peer.Keepalive != 0 || c.Peer.EffectiveKeepalive() != DefaultKeepalive || len(c.DNS) != 0 {
		t.Errorf("%+v", c)
	}
	half := strings.Replace(text, "10.0.0.0/8", "0.0.0.0/1, 128.0.0.0/1", 1)
	if c, err := Parse(half); err != nil || !c.FullTunnel() {
		t.Errorf("0/1 + 128/1 should be full tunnel: %v", err)
	}
}

func TestParseEndpointForms(t *testing.T) {
	base := "[Interface]\nPrivateKey = " + key + "\nAddress = 10.2.0.2\n[Peer]\nPublicKey = " + key + "\nEndpoint = %s\n"
	for ep, ok := range map[string]bool{
		"203.0.113.9:51820":     true,
		"vpn.example.net:443":   true,
		"[2001:db8::9]:51820":   true,
		"vpn.example.net":       false,
		"203.0.113.9:0":         false,
		"203.0.113.9:70000":     false,
		":51820":                false,
		"vpn.example.net:https": false,
	} {
		_, err := Parse(strings.Replace(base, "%s", ep, 1))
		if (err == nil) != ok {
			t.Errorf("endpoint %q: err=%v, want ok=%v", ep, err, ok)
		}
	}
}

func TestParseErrors(t *testing.T) {
	base := "[Interface]\nPrivateKey = " + key + "\nAddress = 10.2.0.2\n[Peer]\nPublicKey = " + key + "\nEndpoint = h:1\n"
	if _, err := Parse(base); err != nil {
		t.Fatalf("base: %v", err)
	}
	ovpn, _ := os.ReadFile(filepath.Join("testdata", "openvpn.ovpn"))
	v6, _ := sample(t, "generic-ipv6only.conf")
	for name, c := range map[string]struct{ text, want string }{
		"bad key":      {strings.Replace(base, "PrivateKey = "+key, "PrivateKey = nope", 1), "invalid [Interface] PrivateKey"},
		"no key":       {strings.Replace(base, "PrivateKey = "+key+"\n", "", 1), "missing [Interface] PrivateKey"},
		"ipv6 only":    {v6, "only IPv6"},
		"no address":   {strings.Replace(base, "Address = 10.2.0.2\n", "", 1), "missing [Interface] Address"},
		"no endpoint":  {strings.Replace(base, "Endpoint = h:1", "", 1), "missing [Peer] Endpoint"},
		"no peer":      {"[Interface]\nPrivateKey = " + key + "\nAddress = 10.2.0.2\n", "missing [Peer]"},
		"two peers":    {base + "[Peer]\nPublicKey = " + key + "\n", "exactly one [Peer]"},
		"garbage":      {base + "nonsense\n", "expected key = value"},
		"openvpn":      {string(ovpn), "OpenVPN"},
		"empty":        {"", "no [Interface]"},
		"no section":   {"PrivateKey = " + key + "\n", "outside a section"},
		"bad mtu":      {strings.Replace(base, "Address", "MTU = 100\nAddress", 1), "bad MTU"},
		"bad psk":      {base + "PresharedKey = x\n", "PresharedKey"},
		"bad allowed":  {base + "AllowedIPs = everything\n", "AllowedIPs"},
		"unknown sect": {base + "[Foo]\n", "unknown section"},
	} {
		_, err := Parse(c.text)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

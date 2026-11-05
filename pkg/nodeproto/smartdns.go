// SPDX-License-Identifier: Apache-2.0

package nodeproto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// CapabilityConnectorSmartDNS is listed by nodes that pass connector sites'
// signed Smart DNS configs through (tunnels.<t>.smartdns), serve
// smartdns.exit over the tunnel exit API and report connectors' Smart DNS
// status. Nodes without it get no Smart DNS config at all.
const CapabilityConnectorSmartDNS = "connector-smartdns"

// SignedSmartDNS is a connector site's Smart DNS config (config.SmartDNSSite
// as JSON) signed by the org key. Nodes, self-hosted or shared, only pass it
// on; the connector verifies it against the org key it pinned.
type SignedSmartDNS struct {
	// Connector is the WireGuard public key of the site's connector (the
	// same on every edge, whatever a node names the tunnel); the connector
	// refuses a config for another key.
	Connector string `json:"connector"`
	// Issued orders configs: the connector refuses one older than the
	// newest it accepted, so a node cannot replay an old config.
	Issued time.Time `json:"issued"`
	// Key is the org public key (base64 Ed25519). A connector with no
	// pinned key pins it on first use; otherwise it must match.
	Key       string          `json:"key"`
	Config    json.RawMessage `json:"config"`
	Signature string          `json:"signature"`
}

// SmartDNSSigningPayload is what the org key signs.
func SmartDNSSigningPayload(s SignedSmartDNS) []byte {
	h := sha256.New()
	writeField(h, "ingressd smartdns site v1")
	writeField(h, s.Connector)
	writeInt(h, s.Issued.UnixNano())
	writeField(h, s.Key)
	sum := sha256.Sum256(s.Config)
	h.Write(sum[:])
	return h.Sum(nil)
}

// SignSmartDNS fills in Key and Signature.
func SignSmartDNS(s *SignedSmartDNS, key ed25519.PrivateKey) {
	s.Key = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, SmartDNSSigningPayload(*s)))
}

// Verify checks the signature with the envelope's own key and the binding
// to the connector's public key; the caller compares Key with the key it
// pinned.
func (s SignedSmartDNS) Verify(connector string) error {
	if s.Connector == "" || s.Connector != connector {
		return fmt.Errorf("smart DNS config is for connector %q, not this one", s.Connector)
	}
	if s.Issued.IsZero() {
		return errors.New("smart DNS config has no issue time")
	}
	pub, err := parseOrgKey(s.Key)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(pub, SmartDNSSigningPayload(s), sig) {
		return errors.New("smart DNS config: bad org signature")
	}
	return nil
}

// ConnectorSmartDNS is what a connector reports about its Smart DNS: in its
// health reports to every edge, and from the edge to the panel in
// TunnelStatus.
type ConnectorSmartDNS struct {
	// Issued is the issue time of the config in effect (zero: none).
	Issued time.Time `json:"issued,omitempty"`
	// Error explains why the latest config was refused or cannot run.
	Error string `json:"error,omitempty"`
	// AgeRecipient is the connector's age public key: the panel encrypts
	// connector VPN configs to it in the browser.
	AgeRecipient string `json:"age_recipient,omitempty"`
	// Listen is the address the resolver and relay bind; Addresses are the
	// connector host's LAN IPv4 addresses, for the panel's picker.
	Listen    string   `json:"listen,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	// BindErrors are listeners that could not start, keyed "dns-udp",
	// "dns-tcp", "relay-tls", "relay-http".
	BindErrors map[string]string `json:"bind_errors,omitempty"`
	Exits      []ExitStatus      `json:"exits,omitempty"`
	Services   []ServiceStatus   `json:"services,omitempty"`
	// Recent are the newest resolver lookups, newest first.
	Recent []RecentLookup `json:"recent,omitempty"`
}

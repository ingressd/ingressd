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

// PathConnectorEdges is where a connector that lost every edge asks the
// panel for its site's current ones. Connectors only learn about edges from
// edges, so without this one whose last edge died stays stranded even when
// the panel has placed it elsewhere. It is part of the managed network: the
// panel answers only for orgs with access to it.
const PathConnectorEdges = "/api/public/connector/edges"

// ConnectorEdgesRequest names the connector by its WireGuard public key.
type ConnectorEdgesRequest struct {
	Connector string `json:"connector"`
}

// ConnectorEdgesResponse holds a SignedEdges as JSON, age-encrypted to the
// connector's recipient: the endpoint needs no credential, so a public key
// alone must reveal nothing about the network.
type ConnectorEdgesResponse struct {
	Sealed string `json:"sealed"`
}

// RescueEdge is one edge of the site.
type RescueEdge struct {
	Node          string `json:"node,omitempty"`
	Endpoint      string `json:"endpoint"`
	EdgePublicKey string `json:"edge_public_key"`
	// Transit is the attachment's network (edge .1, site .2).
	Transit  string `json:"transit"`
	WSURL    string `json:"ws_url,omitempty"`
	Priority int    `json:"priority,omitempty"`
	PoP      string `json:"pop,omitempty"`
}

// SignedEdges is a site's edge list signed by the org key, so a connector
// can only be pointed at edges its org chose.
type SignedEdges struct {
	Connector string       `json:"connector"`
	Issued    time.Time    `json:"issued"`
	Key       string       `json:"key"`
	Edges     []RescueEdge `json:"edges"`
	Signature string       `json:"signature"`
}

func edgesSigningPayload(s SignedEdges) []byte {
	h := sha256.New()
	writeField(h, "ingressd connector edges v1")
	writeField(h, s.Connector)
	writeInt(h, s.Issued.UnixNano())
	writeField(h, s.Key)
	b, _ := json.Marshal(s.Edges)
	sum := sha256.Sum256(b)
	h.Write(sum[:])
	return h.Sum(nil)
}

// SignEdges fills in Key and Signature.
func SignEdges(s *SignedEdges, key ed25519.PrivateKey) {
	s.Key = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, edgesSigningPayload(*s)))
}

// Verify checks the signature with the envelope's own key and the binding
// to connector; the caller compares Key with the key it pinned.
func (s SignedEdges) Verify(connector string) error {
	if s.Connector == "" || s.Connector != connector {
		return fmt.Errorf("edge list is for connector %q, not this one", s.Connector)
	}
	if s.Issued.IsZero() {
		return errors.New("edge list has no issue time")
	}
	pub, err := parseOrgKey(s.Key)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(pub, edgesSigningPayload(s), sig) {
		return errors.New("edge list: bad org signature")
	}
	return nil
}

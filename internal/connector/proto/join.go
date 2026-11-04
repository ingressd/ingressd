// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Join is the content of a join string: one opaque argument for
// `ingressd-connector enroll` that carries everything needed to enrol
// (see nodeproto.ConnectorToken.JoinString).
type Join struct {
	// URL is the edge's admin URL, e.g. https://edge.example.com.
	URL string `json:"u,omitempty"`
	// Token is the one-time enrolment token.
	Token string `json:"t"`
	// CA, when set, is the PEM of the CA the edge certificate chains to. The
	// connector then trusts only this CA for the edge (pinning).
	CA string `json:"ca,omitempty"`
	// Edges optionally lists several edges to try in order (multi-PoP):
	// {"e":[{"u":…,"ca":…}],"t":…}. DecodeJoin fills URL and CA from the
	// first one when they are empty.
	Edges []JoinEdge `json:"e,omitempty"`
}

// JoinEdge is one edge of a multi-edge join string.
type JoinEdge struct {
	URL string `json:"u"`
	CA  string `json:"ca,omitempty"`
}

// All returns every edge of the join string in order, the single-edge
// fields first.
func (j Join) All() []JoinEdge {
	var out []JoinEdge
	if j.URL != "" {
		out = append(out, JoinEdge{URL: j.URL, CA: j.CA})
	}
	for _, e := range j.Edges {
		if e.URL != j.URL {
			out = append(out, e)
		}
	}
	return out
}

// EncodeJoin returns the join string (unpadded base64url JSON). The JSON
// always starts with `{"`, which encodes to "ey", so a join string never
// starts with "-" and is safe as a command-line argument.
func EncodeJoin(j Join) (string, error) {
	if err := j.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(j)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeJoin parses a join string. Padding and surrounding whitespace are
// tolerated (copy-paste from chat apps and terminals).
func DecodeJoin(s string) (Join, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Join{}, fmt.Errorf("join string: not base64url: %w", err)
	}
	var j Join
	if err := json.Unmarshal(b, &j); err != nil {
		return Join{}, fmt.Errorf("join string: %w", err)
	}
	if j.URL == "" && len(j.Edges) > 0 {
		j.URL, j.CA = j.Edges[0].URL, j.Edges[0].CA
	}
	return j, j.Validate()
}

// Validate checks the required fields.
func (j Join) Validate() error {
	all := j.All()
	if len(all) == 0 || j.Token == "" {
		return errors.New("join string: edge URL and token are required")
	}
	for _, e := range all {
		u, err := url.Parse(e.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return fmt.Errorf("join string: edge URL must look like https://edge.example.com, got %q", e.URL)
		}
		if e.CA != "" && !strings.Contains(e.CA, "-----BEGIN CERTIFICATE-----") {
			return errors.New("join string: ca is not a PEM certificate")
		}
	}
	return nil
}

// LooksLikeJoin reports whether s could be a join string rather than a URL.
func LooksLikeJoin(s string) bool {
	return !strings.Contains(s, "://") && strings.HasPrefix(strings.TrimSpace(s), "ey")
}

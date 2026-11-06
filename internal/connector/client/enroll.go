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
	"os"
	"runtime"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/version"
)

// EnrollOptions are the settings given to `ingressd-connector enroll`.
type EnrollOptions struct {
	EdgeURL  string
	Token    string
	EdgeAddr string
	CAFile   string
	// CAPEM is an inline CA (from a join string), pinned like CAFile.
	CAPEM string
	// Alternates are further edges from a multi-edge join string, tried in
	// order when the first cannot be reached.
	Alternates  []proto.JoinEdge
	Insecure    bool
	NoDiscovery bool
	Mode        string
	Interface   string
	Masquerade  bool
	// OrgKey is pinned for the signed Smart DNS config (from the join string).
	OrgKey string
	// Allow, when not nil, is the allowlist to start with, in place of
	// pinning the networks in the tunnel config. AllowAnyNetwork lets it
	// hold 0.0.0.0/0 or ::/0.
	Allow           []string
	AllowAnyNetwork bool
}

// Enroll generates the site keypair locally, exchanges the one-time token
// for a credential and tunnel config, and writes the state file. The
// connector learns the site's other edges from that config once running.
func Enroll(ctx context.Context, statePath string, o EnrollOptions) (*State, error) {
	if o.Mode != ModeTUN && o.Mode != ModeNetstack {
		return nil, fmt.Errorf("mode must be tun or netstack, got %q", o.Mode)
	}
	// Before the one-time token is spent.
	allow, err := parseNetworks(o.Allow, o.AllowAnyNetwork)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "windows" {
		// %ProgramData% lets any user create the directory first.
		if err := SecureStateDir(statePath); err != nil {
			return nil, fmt.Errorf("state directory: %w", err)
		}
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	edges := append([]proto.JoinEdge{{URL: o.EdgeURL, CA: o.CAPEM}}, o.Alternates...)
	var errs []error
	for i, je := range edges {
		if i > 0 && je.URL == o.EdgeURL {
			continue
		}
		es := EdgeState{URL: strings.TrimRight(je.URL, "/"), CAPEM: je.CA, Insecure: o.Insecure}
		if i == 0 {
			es.Addr, es.CAFile = o.EdgeAddr, o.CAFile
		}
		token := je.T
		if token == "" {
			token = o.Token
		}
		er, err := enrollWith(ctx, es, token, key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		es.Credential, es.Config, es.LastSeen = er.Credential, er.Config, time.Now().UTC()
		es.Node = er.Config.Node
		st := &State{
			NoDiscovery: o.NoDiscovery,
			Mode:        o.Mode,
			Interface:   o.Interface,
			Masquerade:  o.Masquerade,
			PrivateKey:  key.String(),
			OrgKey:      o.OrgKey,
			EnrolledAt:  time.Now().UTC(),
			Edges:       []EdgeState{es},
		}
		// When this fails the first start pins instead.
		a, source := pinnedAllowlist(st), allowFromPin
		if o.Allow != nil {
			a, source = &Allowlist{Networks: allow, AnyNetwork: o.AllowAnyNetwork}, allowFromEnroll
		}
		st.AllowlistPinned = a.save(statePath, source) == nil
		return st, st.Save(statePath)
	}
	return nil, errors.Join(errs...)
}

func enrollWith(ctx context.Context, es EdgeState, token string, key wgtypes.Key) (*proto.EnrollResponse, error) {
	host, err := edgeHost(es.URL)
	if err != nil {
		return nil, err
	}
	tc, err := tlsConfig(host, es.CAFile, es.CAPEM, es.Insecure)
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	body, _ := json.Marshal(proto.EnrollRequest{
		Token:     token,
		PublicKey: key.PublicKey().String(),
		Hostname:  hostname,
		Version:   version.String(),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, es.URL+proto.EnrollPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient(tc, publicDialer(host, es.Addr), 90*time.Second).Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("enroll: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var er proto.EnrollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxConfigBody)).Decode(&er); err != nil {
		return nil, fmt.Errorf("enroll: bad response: %w", err)
	}
	return &er, nil
}

// ApplyJoin fills the edge URL(s), token and pinned CA from a join string.
func (o *EnrollOptions) ApplyJoin(joinString string) error {
	j, err := proto.DecodeJoin(joinString)
	if err != nil {
		return err
	}
	all := j.All()
	o.EdgeURL, o.Token = all[0].URL, j.Token
	if all[0].T != "" {
		o.Token = all[0].T
	}
	if o.CAFile == "" {
		o.CAPEM = all[0].CA
	}
	o.Alternates = all[1:]
	o.OrgKey = j.OrgKey
	return nil
}

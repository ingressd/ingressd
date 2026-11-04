// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/ingressd/ingressd/pkg/config"
)

// originTLS sets the reverse_proxy transport's TLS client config from the
// app's origin TLS mode (see PLAN §9.3):
//
//	off    → no TLS
//	full   → TLS without verification
//	strict → verify against the Origin CA issuer, system roots or a custom CA
//	mtls   → also present the edge's Origin CA client certificate
func originTLS(cfg *config.Config, app config.App, transport obj) error {
	t := cfg.EffectiveOriginTLS(app)
	if t.Origin == config.OriginTLSOff {
		return nil
	}
	rt := cfg.Certificates.OriginCA.Runtime
	if rt == nil {
		rt = &config.OriginTLSRuntime{}
	}
	tc := obj{}
	switch t.Origin {
	case config.OriginTLSFull:
		tc["insecure_skip_verify"] = true
	case config.OriginTLSStrict:
		var pemCAs string
		switch sec, custom := t.CustomCASecret(); {
		case t.VerifyWith == config.VerifyOriginCA:
			if rt.TrustPEM == "" {
				return errors.New("tls: origin CA is not initialized")
			}
			pemCAs = rt.TrustPEM
		case custom:
			if pemCAs = rt.CustomCAs[sec]; pemCAs == "" {
				return fmt.Errorf("tls.verify_with: custom CA secret %q is not loaded", sec)
			}
		}
		// verify_with public leaves "ca" unset: Caddy uses the system roots.
		if pemCAs != "" {
			ders, err := pemToBase64DER(pemCAs)
			if err != nil {
				return fmt.Errorf("tls.verify_with: %w", err)
			}
			tc["ca"] = obj{"provider": "inline", "trusted_ca_certs": ders}
		}
	}
	if sn := t.ServerName; sn != "" {
		tc["server_name"] = sn
	} else if sn := remappedServerName(cfg, app); sn != "" && t.Origin == config.OriginTLSStrict {
		// The edge dials a remapped address, but the certificate names the
		// origin's real one.
		tc["server_name"] = sn
	}
	if t.MTLS {
		if rt.ClientCertFile == "" || rt.ClientKeyFile == "" {
			return errors.New("tls.mtls: edge client certificate is not available")
		}
		tc["client_certificate_file"] = rt.ClientCertFile
		tc["client_certificate_key_file"] = rt.ClientKeyFile
	}
	transport["tls"] = tc
	return nil
}

// remappedServerName returns the origins' common real host when every
// active origin is a literal IP that the edge reaches via a remapped
// (virtual_prefix) address; otherwise "".
func remappedServerName(cfg *config.Config, app config.App) string {
	name := ""
	for _, o := range poolFor(cfg, app).Origins {
		if o.State != config.OriginActive {
			continue
		}
		u, err := url.Parse(o.Address)
		if err != nil {
			return ""
		}
		dial, _, err := dialAddress(cfg, o)
		if err != nil {
			return ""
		}
		dialHost, _, _ := net.SplitHostPort(dial)
		if dialHost == u.Hostname() || (name != "" && name != u.Hostname()) {
			return ""
		}
		name = u.Hostname()
	}
	return name
}

func pemToBase64DER(s string) ([]string, error) {
	var out []string
	b := []byte(s)
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, base64.StdEncoding.EncodeToString(blk.Bytes))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificates found")
	}
	return out, nil
}

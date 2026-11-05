// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

// Secret names holding the Access keys. They are generated on first apply.
const (
	// SessionKeySecret is a 32-byte master key (base64). Cookie encryption
	// keys and the service-token HMAC key are derived from it.
	SessionKeySecret = "access_session_key"
	// JWTKeySecret is an ECDSA P-256 private key (base64 PKCS#8) that signs
	// the Edge-Jwt-Assertion header.
	JWTKeySecret = "access_jwt_key"
)

// Enabled reports whether the config runs the login portal on this node
// (access.portal_host).
func Enabled(cfg *config.Config) bool {
	return cfg.Access != nil && cfg.Access.PortalHost != ""
}

// External reports whether sign-in happens on an external portal
// (access.portal_url, the panel's central portal on managed nodes). The
// node then only redeems callback codes.
func External(cfg *config.Config) bool {
	return cfg.Access != nil && cfg.Access.PortalURL != ""
}

// Needed reports whether the config signs anyone in: the login portal (here
// or external) or a login-to-play host.
func Needed(cfg *config.Config) bool {
	return Enabled(cfg) || External(cfg) || len(cfg.LoginToPlayHosts()) > 0 || realmsSignIn(cfg)
}

// realmsSignIn reports whether any realm has access settings (realms sign
// in on their external portals; the node redeems their callback codes).
func realmsSignIn(cfg *config.Config) bool {
	for _, r := range cfg.Realms {
		if r.Access != nil {
			return true
		}
	}
	return false
}

// OrgKeys reports whether the config supplies org-wide keys
// (access.session_key / access.jwt_key) instead of node-generated ones.
func OrgKeys(cfg *config.Config) bool {
	return cfg.Access != nil && cfg.Access.SessionKey != "" && cfg.Access.JWTKey != ""
}

// KeyRefs returns the secret references of the session and JWT keys: the
// org-wide ones from the config, else the node's own generated secrets.
func KeyRefs(cfg *config.Config) (session, jwt string) {
	if OrgKeys(cfg) {
		return cfg.Access.SessionKey, cfg.Access.JWTKey
	}
	return secrets.RefPrefix + SessionKeySecret, secrets.RefPrefix + JWTKeySecret
}

// LoadConfigKeys decodes the keys the config refers to (see KeyRefs).
func LoadConfigKeys(cfg *config.Config, res Resolver) (*Keys, error) {
	sref, jref := KeyRefs(cfg)
	return loadKeys(res, sref, jref)
}

// LoadRealmKeys decodes a realm's own keys (realms.<name>.access), scoped
// to the realm (see Keys.ForRealm). Realms never use the node's keys.
func LoadRealmKeys(cfg *config.Config, res Resolver, realm string) (*Keys, error) {
	a := cfg.RealmAccess(realm)
	if a == nil || a.SessionKey == "" || a.JWTKey == "" {
		return nil, fmt.Errorf("realm %q has no session_key and jwt_key", realm)
	}
	k, err := loadKeys(res, a.SessionKey, a.JWTKey)
	if err != nil {
		return nil, fmt.Errorf("realm %s: %w", realm, err)
	}
	return k.ForRealm(realm), nil
}

func loadKeys(res Resolver, sref, jref string) (*Keys, error) {
	sk, err := res.Resolve(sref)
	if err != nil {
		return nil, fmt.Errorf("access session key: %w", err)
	}
	jk, err := res.Resolve(jref)
	if err != nil {
		return nil, fmt.Errorf("access JWT key: %w", err)
	}
	return ParseKeys(sk, jk)
}

// EnsureKeys generates the Access keys if they are missing. It reports
// whether the store changed (and so needs saving). Configs with org-wide
// keys (managed nodes) or realms (each brings its own) need nothing
// generated.
func EnsureKeys(cfg *config.Config, st *secrets.Store) (bool, error) {
	if !Needed(cfg) || OrgKeys(cfg) || len(cfg.Realms) > 0 {
		return false, nil
	}
	changed := false
	if _, ok := st.Get(SessionKeySecret); !ok {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return false, err
		}
		if err := st.Set(SessionKeySecret, base64.StdEncoding.EncodeToString(k)); err != nil {
			return false, err
		}
		changed = true
	}
	if _, ok := st.Get(JWTKeySecret); !ok {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return changed, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return changed, err
		}
		if err := st.Set(JWTKeySecret, base64.StdEncoding.EncodeToString(der)); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// Getter reads secret values (implemented by *secrets.Store).
type Getter interface {
	Get(name string) (string, bool)
}

// LoadKeys decodes the Access keys from the secrets store.
func LoadKeys(st Getter) (*Keys, error) {
	s, ok := st.Get(SessionKeySecret)
	if !ok {
		return nil, fmt.Errorf("secret %s is missing (run ingressd apply to generate it)", SessionKeySecret)
	}
	j, ok := st.Get(JWTKeySecret)
	if !ok {
		return nil, fmt.Errorf("secret %s is missing (run ingressd apply to generate it)", JWTKeySecret)
	}
	return ParseKeys(s, j)
}

// verifyES256 checks a compact JWS signature (used by tests).
func verifyES256(pub *ecdsa.PublicKey, signingInput string, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	h := sha256.Sum256([]byte(signingInput))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, h[:], r, s)
}

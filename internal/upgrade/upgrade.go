// SPDX-License-Identifier: Apache-2.0

// Package upgrade replaces the installed ingressd binaries with a signed
// GitHub release and rolls back if the edge is unhealthy afterwards
// (PLAN §17.4).
//
// Release layout (assets of github.com/ingressd/ingressd/releases):
//
//	SHA256SUMS            "<sha256>  <asset>" per line
//	SHA256SUMS.minisig    minisign signature of SHA256SUMS (ReleasePublicKey)
//	ingressd_<os>_<arch>, ingressd-edge_<os>_<arch>, ...   raw binaries
package upgrade

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ingressd/ingressd/pkg/release"
)

// DefaultBaseURL is the GitHub releases URL of the project.
const DefaultBaseURL = "https://github.com/ingressd/ingressd/releases"

// ReleasePublicKey verifies release signatures: the built-in key, or the
// INGRESSD_RELEASE_PUBLIC_KEY override (see pkg/release).
var ReleasePublicKey = release.TrustedPublicKey()

const (
	SumsAsset = "SHA256SUMS"
	SigAsset  = "SHA256SUMS.minisig"
)

// DefaultBinaries are replaced by an upgrade.
var DefaultBinaries = []string{"ingressd", "ingressd-edge"}

// DefaultUnits are restarted after the binaries are swapped (edge first:
// the control plane re-applies to it at startup).
var DefaultUnits = []string{"ingressd-edge.service", "ingressd.service"}

// Options configure an upgrade.
type Options struct {
	BaseURL   string // default DefaultBaseURL
	Version   string // release tag ("v1.2.0"); empty = latest
	PublicKey string // default ReleasePublicKey
	BinDir    string // directory holding the binaries
	Binaries  []string
	OS, Arch  string
	Units     []string
	// Restart restarts units (default: systemctl restart). Not called when
	// Units is empty.
	Restart func(ctx context.Context, units []string) error
	// Doctor checks health after the swap (the caller runs the new
	// "ingressd doctor"); it is retried until HealthTimeout.
	Doctor        func(ctx context.Context) error
	HealthTimeout time.Duration
	Client        *http.Client
	Log           io.Writer
	// Current is the running version. A release older than it is a
	// downgrade, refused unless AllowDowngrade; a downgrade must also stay
	// at or above the latest release's minimum supported version.
	Current        string
	AllowDowngrade bool
}

// Result describes a completed upgrade.
type Result struct {
	Version  string // trusted comment of the signature (release name)
	Replaced []string
}

func (o *Options) defaults() {
	if o.BaseURL == "" {
		o.BaseURL = DefaultBaseURL
	}
	if o.PublicKey == "" {
		o.PublicKey = ReleasePublicKey
	}
	if len(o.Binaries) == 0 {
		o.Binaries = DefaultBinaries
	}
	if o.OS == "" {
		o.OS = runtime.GOOS
	}
	if o.Arch == "" {
		o.Arch = runtime.GOARCH
	}
	if o.Restart == nil {
		o.Restart = systemctlRestart
	}
	if o.HealthTimeout <= 0 {
		o.HealthTimeout = 60 * time.Second
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 5 * time.Minute}
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
}

// AssetName is the release asset for a binary.
func AssetName(bin, goos, arch string) string { return fmt.Sprintf("%s_%s_%s", bin, goos, arch) }

func (o *Options) url(asset string) string {
	base := strings.TrimSuffix(o.BaseURL, "/")
	if o.Version == "" {
		return base + "/latest/download/" + asset
	}
	return base + "/download/" + o.Version + "/" + asset
}

func (o *Options) get(ctx context.Context, asset string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.url(asset), nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", asset, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", asset, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("download %s: larger than %d bytes", asset, limit)
	}
	return b, nil
}

// ParseSums parses a SHA256SUMS file.
func ParseSums(b []byte) (map[string]string, error) {
	sums := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 || len(f[0]) != 64 {
			return nil, fmt.Errorf("malformed checksum line %q", sc.Text())
		}
		if _, err := hex.DecodeString(f[0]); err != nil {
			return nil, fmt.Errorf("malformed checksum line %q", sc.Text())
		}
		sums[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
	}
	return sums, sc.Err()
}

// Run downloads, verifies and installs a release, restarts the units and
// rolls everything back if Doctor keeps failing.
func Run(ctx context.Context, o Options) (*Result, error) {
	o.defaults()
	if release.IsPlaceholderKey(o.PublicKey) {
		return nil, release.ErrNoSigningKey
	}
	pk, err := ParsePublicKey(o.PublicKey)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(o.Log, "Downloading release %s\n", orLatest(o.Version))
	sums, err := o.get(ctx, SumsAsset, 1<<20)
	if err != nil {
		return nil, err
	}
	sig, err := o.get(ctx, SigAsset, 1<<16)
	if err != nil {
		return nil, err
	}
	trusted, err := pk.Verify(sums, sig)
	if err != nil {
		return nil, fmt.Errorf("release signature: %w", err)
	}
	fmt.Fprintf(o.Log, "Signature OK (%s)\n", trusted)
	table, err := ParseSums(sums)
	if err != nil {
		return nil, err
	}
	if err := o.checkVersion(ctx, trusted, table); err != nil {
		return nil, err
	}

	// Download everything before touching the installed binaries.
	type staged struct{ bin, path, tmp string }
	var stage []staged
	cleanup := func() {
		for _, s := range stage {
			os.Remove(s.tmp)
		}
	}
	for _, bin := range o.Binaries {
		asset := AssetName(bin, o.OS, o.Arch)
		want, ok := table[asset]
		if !ok {
			cleanup()
			return nil, fmt.Errorf("release has no %s", asset)
		}
		b, err := o.get(ctx, asset, 512<<20)
		if err != nil {
			cleanup()
			return nil, err
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			cleanup()
			return nil, fmt.Errorf("checksum mismatch for %s", asset)
		}
		path := filepath.Join(o.BinDir, bin)
		tmp := filepath.Join(o.BinDir, "."+bin+".new")
		if err := os.WriteFile(tmp, b, 0o755); err != nil {
			cleanup()
			return nil, err
		}
		stage = append(stage, staged{bin, path, tmp})
		fmt.Fprintf(o.Log, "Verified %s\n", asset)
	}

	// Swap: keep the current binary as <bin>.old (hard link), then
	// atomically rename the new one over it.
	var swapped []string
	rollback := func() error {
		var errs []error
		for _, p := range swapped {
			if err := os.Rename(p+".old", p); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	for _, s := range stage {
		_ = os.Remove(s.path + ".old")
		hadOld := true
		if err := os.Link(s.path, s.path+".old"); err != nil {
			if !os.IsNotExist(err) {
				if err := copyFile(s.path, s.path+".old"); err != nil {
					cleanup()
					return nil, errors.Join(err, rollback())
				}
			} else {
				hadOld = false
			}
		}
		if err := os.Rename(s.tmp, s.path); err != nil {
			cleanup()
			return nil, errors.Join(err, rollback())
		}
		if hadOld {
			swapped = append(swapped, s.path)
		}
	}
	fmt.Fprintf(o.Log, "Installed %s\n", strings.Join(o.Binaries, ", "))

	if len(o.Units) > 0 {
		if err := o.Restart(ctx, o.Units); err != nil {
			fmt.Fprintf(o.Log, "Restart failed (%v); rolling back\n", err)
			return nil, o.fail(ctx, fmt.Errorf("restart: %w", err), rollback)
		}
	}
	if o.Doctor != nil {
		deadline := time.Now().Add(o.HealthTimeout)
		for {
			err := o.Doctor(ctx)
			if err == nil {
				break
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				fmt.Fprintf(o.Log, "Health check failed (%v); rolling back\n", err)
				return nil, o.fail(ctx, fmt.Errorf("health check: %w", err), rollback)
			}
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
			}
		}
	}
	return &Result{Version: trusted, Replaced: o.Binaries}, nil
}

// checkVersion ties the verified checksums to the release asked for: the
// signature's trusted comment ("ingressd vX.Y.Z") names the release, which
// must be the requested one (a mirror or a tampered redirect cannot serve
// another validly signed release instead), must agree with the release's
// manifest when it has one, and must not be older than the running version
// unless a downgrade is allowed explicitly.
func (o *Options) checkVersion(ctx context.Context, trusted string, sums map[string]string) error {
	signed, ok := strings.CutPrefix(trusted, "ingressd ")
	// Staging builds carry a trailing note ("ingressd vX.Y.Z-dev.N (staging)");
	// the staging key, not the comment, is what keeps them off production.
	if i := strings.Index(signed, " ("); i > 0 && strings.HasSuffix(signed, ")") {
		signed = signed[:i]
	}
	if !ok || !release.Comparable(signed) {
		return fmt.Errorf("release signature: trusted comment %q does not name an ingressd release", trusted)
	}
	if o.Version != "" {
		if c, ok := release.CompareStrings(signed, o.Version); !ok || c != 0 {
			return fmt.Errorf("release signature is for %s, not the requested %s", signed, o.Version)
		}
	}
	if want, ok := sums[release.ManifestFile]; ok {
		b, err := o.get(ctx, release.ManifestFile, 1<<20)
		if err != nil {
			return err
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != want {
			return fmt.Errorf("checksum mismatch for %s", release.ManifestFile)
		}
		var m release.Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("%s: %w", release.ManifestFile, err)
		}
		if c, ok := release.CompareStrings(m.Version, signed); !ok || c != 0 {
			return fmt.Errorf("%s is for %s, but the signature for %s", release.ManifestFile, m.Version, signed)
		}
	}
	c, ok := release.CompareStrings(signed, o.Current)
	switch {
	case !ok:
		// A development build has no place in the version order: the
		// operator chose to replace it with this signed release.
		return nil
	case c >= 0:
		return nil
	case !o.AllowDowngrade:
		return fmt.Errorf("%s is older than the running %s; pass --allow-downgrade to install it anyway", signed, release.Clean(o.Current))
	}
	floor, err := o.latestMinSupported(ctx)
	if err != nil {
		return fmt.Errorf("downgrade: cannot read the minimum supported version from the latest release: %w", err)
	}
	if c, ok := release.CompareStrings(signed, floor); floor != "" && ok && c < 0 {
		return fmt.Errorf("%s is below the minimum supported version %s", signed, floor)
	}
	fmt.Fprintf(o.Log, "Downgrading from %s to %s\n", release.Clean(o.Current), signed)
	return nil
}

// latestMinSupported returns MinSupported of the latest release's signed
// manifest.
func (o *Options) latestMinSupported(ctx context.Context) (string, error) {
	latest := *o
	latest.Version = ""
	mb, err := latest.get(ctx, release.ManifestFile, 1<<20)
	if err != nil {
		return "", err
	}
	sig, err := latest.get(ctx, release.ManifestSigFile, 1<<16)
	if err != nil {
		return "", err
	}
	m, err := release.VerifyManifest(o.PublicKey, mb, sig)
	if err != nil {
		return "", err
	}
	return m.MinSupported, nil
}

func (o *Options) fail(ctx context.Context, cause error, rollback func() error) error {
	if err := rollback(); err != nil {
		return fmt.Errorf("%w; ROLLBACK FAILED: %v (previous binaries are *.old in %s)", cause, err, o.BinDir)
	}
	if len(o.Units) > 0 {
		if err := o.Restart(ctx, o.Units); err != nil {
			return fmt.Errorf("%w; rolled back, but restarting failed: %v", cause, err)
		}
	}
	return fmt.Errorf("upgrade rolled back: %w", cause)
}

func orLatest(v string) string {
	if v == "" {
		return "latest"
	}
	return v
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

func systemctlRestart(ctx context.Context, units []string) error {
	out, err := exec.CommandContext(ctx, "systemctl", append([]string{"restart"}, units...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

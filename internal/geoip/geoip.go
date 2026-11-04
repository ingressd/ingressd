// SPDX-License-Identifier: Apache-2.0

// Package geoip downloads and locates MaxMind GeoLite2 databases, the
// built-in equivalent of geoipupdate.
//
// Databases are stored as <dir>/<edition>-<timestamp>.mmdb so that every
// update changes the path in the rendered Caddy config, which makes apply
// reload the matcher with the new file. The two newest copies are kept.
package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// DefaultBaseURL is MaxMind's database download endpoint.
const DefaultBaseURL = "https://download.maxmind.com/geoip/databases"

// maxDBSize bounds a downloaded archive (GeoLite2-City is ~70 MB).
const maxDBSize = 512 << 20

// mmdbMarker starts the metadata section of every MaxMind DB file.
var mmdbMarker = []byte("\xab\xcd\xefMaxMind.com")

type Updater struct {
	Dir        string
	AccountID  string
	LicenseKey string
	Editions   []string
	// MaxAge skips editions whose newest local copy is younger (0 = always).
	MaxAge  time.Duration
	BaseURL string // default DefaultBaseURL
	Client  *http.Client
	now     func() time.Time
}

// Result describes one edition after an update.
type Result struct {
	Edition string
	Path    string
	Updated bool
}

// Update downloads every edition that is missing or older than MaxAge.
func (u *Updater) Update(ctx context.Context) ([]Result, error) {
	if u.AccountID == "" || u.LicenseKey == "" {
		return nil, errors.New("geoip: MaxMind account ID and license key are required")
	}
	if err := os.MkdirAll(u.Dir, 0o755); err != nil {
		return nil, err
	}
	now := time.Now
	if u.now != nil {
		now = u.now
	}
	var res []Result
	var errs []error
	for _, ed := range u.Editions {
		cur := Find(u.Dir, ed)
		if cur != "" && u.MaxAge > 0 {
			if fi, err := os.Stat(cur); err == nil && now().Sub(fi.ModTime()) < u.MaxAge {
				res = append(res, Result{Edition: ed, Path: cur})
				continue
			}
		}
		p, err := u.download(ctx, ed, now())
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ed, err))
			res = append(res, Result{Edition: ed, Path: cur})
			continue
		}
		prune(u.Dir, ed, 2)
		res = append(res, Result{Edition: ed, Path: p, Updated: true})
	}
	return res, errors.Join(errs...)
}

func (u *Updater) download(ctx context.Context, edition string, now time.Time) (string, error) {
	base := u.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+edition+"/download?suffix=tar.gz", nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(u.AccountID, u.LicenseKey)
	client := u.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("download: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	db, err := extractMMDB(io.LimitReader(resp.Body, maxDBSize))
	if err != nil {
		return "", err
	}
	dst := filepath.Join(u.Dir, fmt.Sprintf("%s-%s.mmdb", edition, now.UTC().Format("20060102T150405")))
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, db, 0o644); err != nil {
		return "", err
	}
	return dst, os.Rename(tmp, dst)
}

// extractMMDB returns the .mmdb file from a MaxMind tar.gz archive.
func extractMMDB(r io.Reader) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("archive has no .mmdb file")
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".mmdb") {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if !bytes.Contains(b[max(0, len(b)-128*1024):], mmdbMarker) {
			return nil, errors.New("downloaded file is not a MaxMind database")
		}
		return b, nil
	}
}

func versions(dir, edition string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, edition+"-*.mmdb"))
	slices.Sort(m) // timestamps sort lexically
	return m
}

// Find returns the newest database for edition in dir, or "".
func Find(dir, edition string) string {
	v := versions(dir, edition)
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

func prune(dir, edition string, keep int) {
	v := versions(dir, edition)
	for i := 0; i < len(v)-keep; i++ {
		_ = os.Remove(v[i])
	}
}

// CountryDB returns the newest country database in dir (GeoIP2 preferred).
func CountryDB(dir string) string {
	if p := Find(dir, "GeoIP2-Country"); p != "" {
		return p
	}
	return Find(dir, "GeoLite2-Country")
}

// ASNDB returns the newest ASN database in dir.
func ASNDB(dir string) string { return Find(dir, "GeoLite2-ASN") }

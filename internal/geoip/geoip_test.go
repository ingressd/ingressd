// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func archive(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write(body)
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestUpdate(t *testing.T) {
	db := append([]byte("fake-db"), mmdbMarker...)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if u, p, ok := r.BasicAuth(); !ok || u != "42" || p != "key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/GeoLite2-Country/download" || r.URL.Query().Get("suffix") != "tar.gz" {
			http.NotFound(w, r)
			return
		}
		w.Write(archive(t, "GeoLite2-Country_20261101/GeoLite2-Country.mmdb", db))
	}))
	defer srv.Close()

	dir := t.TempDir()
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	u := &Updater{Dir: dir, AccountID: "42", LicenseKey: "key", Editions: []string{"GeoLite2-Country"},
		BaseURL: srv.URL, MaxAge: 24 * time.Hour, now: func() time.Time { return now }}
	res, err := u.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "GeoLite2-Country-20261102T100000.mmdb")
	if len(res) != 1 || !res[0].Updated || res[0].Path != want {
		t.Fatalf("result = %+v", res)
	}
	if b, _ := os.ReadFile(want); !bytes.Equal(b, db) {
		t.Fatal("database content mismatch")
	}
	if CountryDB(dir) != want {
		t.Fatalf("CountryDB = %q", CountryDB(dir))
	}

	// Fresh copy: skipped.
	if res, _ := u.Update(context.Background()); res[0].Updated || hits != 1 {
		t.Fatalf("expected skip, got %+v (hits %d)", res, hits)
	}

	// Old copies are pruned, keeping two.
	for i := 1; i <= 3; i++ {
		now = now.Add(48 * time.Hour)
		os.Chtimes(Find(dir, "GeoLite2-Country"), now.Add(-48*time.Hour), now.Add(-48*time.Hour))
		if _, err := u.Update(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if v := versions(dir, "GeoLite2-Country"); len(v) != 2 {
		t.Fatalf("versions = %v, want 2", v)
	}

	u.LicenseKey = "wrong"
	u.MaxAge = 0
	if _, err := u.Update(context.Background()); err == nil {
		t.Fatal("expected error for bad credentials")
	}
}

func TestUpdateNeedsCredentials(t *testing.T) {
	if _, err := (&Updater{Dir: t.TempDir()}).Update(context.Background()); err == nil {
		t.Fatal("expected error without credentials")
	}
}

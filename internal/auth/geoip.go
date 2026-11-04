// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/geoip"
	"github.com/oschwald/maxminddb-golang"
)

// GeoIP looks up countries in the newest MaxMind country database in Dir
// (the one internal/geoip downloads and render hands to the edge, so the
// portal and edge_auth agree on countries), else in Path. Without a file
// every lookup returns "" and country selectors never match. The reader
// picks up a new file when its name or modification time changes.
type GeoIP struct {
	Dir  string
	Path string

	mu      sync.Mutex
	db      *maxminddb.Reader
	path    string
	modTime time.Time
	checked time.Time
}

// GeoIPPath is the legacy fixed name of the country database.
func GeoIPPath(stateDir string) string {
	return filepath.Join(stateDir, "geoip", "GeoLite2-Country.mmdb")
}

// NewGeoIP reads the country database of a state directory.
func NewGeoIP(stateDir string) *GeoIP {
	return &GeoIP{Dir: filepath.Join(stateDir, "geoip"), Path: GeoIPPath(stateDir)}
}

// Country returns the ISO country code for ip, or "".
func (g *GeoIP) Country(ip netip.Addr) string {
	if g == nil || !ip.IsValid() {
		return ""
	}
	db := g.reader()
	if db == nil {
		return ""
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := db.Lookup(net.IP(ip.Unmap().AsSlice()), &rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}

func (g *GeoIP) reader() *maxminddb.Reader {
	g.mu.Lock()
	defer g.mu.Unlock()
	if time.Since(g.checked) < time.Minute && !g.checked.IsZero() {
		return g.db
	}
	g.checked = time.Now()
	path := g.Path
	if g.Dir != "" {
		if p := geoip.CountryDB(g.Dir); p != "" {
			path = p
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		g.db = nil
		return nil
	}
	if g.db != nil && path == g.path && fi.ModTime().Equal(g.modTime) {
		return g.db
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return g.db
	}
	// The old reader is not closed: a lookup may still be using it. The
	// database changes rarely, so the leak is negligible.
	g.db, g.path, g.modTime = db, path, fi.ModTime()
	return g.db
}

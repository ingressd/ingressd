// SPDX-License-Identifier: Apache-2.0

package crawler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// On-disk layout of an app's snapshots (read by edge/modules/edgefallback,
// which keeps its own copy of the Manifest type; keep them in sync):
//
//	<state-dir>/snapshots/<app>/
//	  latest -> <id>               symlink, replaced atomically
//	  <id>/manifest.json           Manifest
//	  <id>/files/<hash>            response bodies
//
// IDs are UTC timestamps (20061102T150405Z), so they sort by age.

const (
	ManifestFile = "manifest.json"
	FilesDir     = "files"
	LatestLink   = "latest"
	idLayout     = "20060102T150405Z"
)

var idRe = regexp.MustCompile(`^\d{8}T\d{6}Z(-\d+)?$`)

// Manifest indexes one snapshot.
type Manifest struct {
	ID        string           `json:"id"`
	App       string           `json:"app"`
	Host      string           `json:"host"`
	Created   time.Time        `json:"created"`
	Pages     int              `json:"pages"` // stored entries
	Bytes     int64            `json:"bytes"`
	Truncated bool             `json:"truncated,omitempty"` // a max_pages/max_bytes limit was hit
	Entries   map[string]Entry `json:"entries"`             // by request path (+ "?query")
}

// Entry is one stored response: a body file, or a redirect.
type Entry struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	File        string `json:"file,omitempty"` // relative to the snapshot dir
	Location    string `json:"location,omitempty"`
}

// Info summarises a snapshot for listings.
type Info struct {
	ID        string
	Created   time.Time
	Pages     int
	Bytes     int64
	Truncated bool
	Latest    bool
}

// List returns an app's snapshots, oldest first.
func List(dir string) ([]Info, error) {
	ids, err := snapshotIDs(dir)
	if err != nil {
		return nil, err
	}
	latest, _ := os.Readlink(filepath.Join(dir, LatestLink))
	var out []Info
	for _, id := range ids {
		m, err := ReadManifest(filepath.Join(dir, id))
		if err != nil {
			continue
		}
		out = append(out, Info{ID: id, Created: m.Created, Pages: m.Pages, Bytes: m.Bytes, Truncated: m.Truncated, Latest: id == latest})
	}
	return out, nil
}

// ReadManifest reads the manifest of the snapshot in dir.
func ReadManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return &m, nil
}

func snapshotIDs(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range ents {
		if e.IsDir() && idRe.MatchString(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// newID returns a fresh snapshot ID for t, unique within dir.
func newID(dir string, t time.Time) string {
	base := t.UTC().Format(idLayout)
	id := base
	for i := 2; ; i++ {
		if _, err := os.Stat(filepath.Join(dir, id)); errors.Is(err, fs.ErrNotExist) {
			return id
		}
		id = base + "-" + strconv.Itoa(i)
	}
}

// publish moves a finished snapshot from tmp to dir/id and points latest at
// it atomically (symlink + rename), then prunes all but the newest keep.
func publish(dir, tmp, id string, keep int) error {
	if err := os.Rename(tmp, filepath.Join(dir, id)); err != nil {
		return err
	}
	link := filepath.Join(dir, "."+LatestLink+".tmp")
	_ = os.Remove(link)
	if err := os.Symlink(id, link); err != nil {
		return err
	}
	if err := os.Rename(link, filepath.Join(dir, LatestLink)); err != nil {
		return err
	}
	return prune(dir, keep)
}

func prune(dir string, keep int) error {
	ids, err := snapshotIDs(dir)
	if err != nil {
		return err
	}
	latest, _ := os.Readlink(filepath.Join(dir, LatestLink))
	var errs []error
	for len(ids) > keep {
		if ids[0] != latest {
			errs = append(errs, os.RemoveAll(filepath.Join(dir, ids[0])))
		}
		ids = ids[1:]
	}
	return errors.Join(errs...)
}

// lock takes a per-app lock file so concurrent crawls (CLI and scheduler)
// do not interleave. Locks older than an hour are considered abandoned.
func lock(dir string) (unlock func(), err error) {
	path := filepath.Join(dir, ".lock")
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if fi, serr := os.Stat(path); serr == nil && time.Since(fi.ModTime()) > time.Hour {
			os.Remove(path)
			continue
		}
		break
	}
	return nil, fmt.Errorf("another snapshot of this app is in progress (%s)", path)
}

// cleanTmp removes leftovers of interrupted crawls.
func cleanTmp(dir string) {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), ".tmp-") {
			os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}

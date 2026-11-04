// SPDX-License-Identifier: Apache-2.0

package upgrade

// Private state directories. The connector's state directory holds the
// site's WireGuard key and edge credentials, and its upgrade/ work
// directory holds the plan the (privileged) helper carries out: the plan
// names the binaries to swap in and, in exec mode, the command to run. So
// the directory must be writable only by the service's account and
// administrators, files are written through fresh temporary files (a file
// someone pre-created is never written into or renamed into place), and
// the helper refuses a plan that a less privileged user could have written
// (openTrusted).
//
// On Unix this is mode 0700/0600 and the file owner. On Windows the modes
// mean nothing: %ProgramData% lets every user create files and read what
// they did not write, so the directory gets a protected DACL granting only
// SYSTEM, Administrators and the account running the process
// (secure_windows.go).

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// errUntrusted marks a file the helper refuses to act on.
var errUntrusted = errors.New("untrusted file")

// staleTemp is how old a leftover temporary file must be before SecureDir
// removes it (younger ones may belong to a write in progress).
const staleTemp = time.Minute

// WriteFileAtomic writes data to path (mode 0600) through a new temporary
// file in the same directory, created exclusively under a random name, and
// renames it into place.
func WriteFileAtomic(path string, data []byte) error {
	dir, base := filepath.Split(path)
	f, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0o600)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// EnsureDir creates dir (and its parents) when it does not exist, private
// to this account and administrators. An existing directory is left alone
// (SecureDir repairs one).
func EnsureDir(dir string) error {
	if _, err := os.Lstat(dir); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return restrict(dir, true)
}

// SecureDir creates dir if needed and makes it, and everything below it,
// private to this account and administrators (see restrict). Junctions, links
// and other reparse points below dir (Windows), and stale temporary files,
// are removed. It is meant to run on every start, so an existing install is
// repaired.
func SecureDir(dir string) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		fi, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		if !linksTrusted {
			return fmt.Errorf("%s is a link or junction, not a directory", dir)
		}
		if fi, err = os.Stat(dir); err != nil {
			return err
		}
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if err := restrict(dir, true); err != nil {
		return fmt.Errorf("restrict %s: %w", dir, err)
	}
	return secureEntries(dir)
}

func secureEntries(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		switch t := e.Type(); {
		case t&fs.ModeSymlink != 0 || t&fs.ModeIrregular != 0:
			if linksTrusted {
				continue
			}
			// Nothing here is a link or junction; someone else put it there.
			if err := os.Remove(p); err != nil {
				errs = append(errs, err)
			}
		case e.IsDir():
			if err := restrict(p, true); err != nil {
				errs = append(errs, fmt.Errorf("restrict %s: %w", p, err))
				continue
			}
			if err := secureEntries(p); err != nil {
				errs = append(errs, err)
			}
		case strings.HasSuffix(e.Name(), ".tmp"):
			if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > staleTemp {
				_ = os.Remove(p)
			}
		case t.IsRegular():
			if err := restrict(p, false); err != nil {
				errs = append(errs, fmt.Errorf("restrict %s: %w", p, err))
			}
		}
	}
	return errors.Join(errs...)
}

// ReadTrusted reads a file the helper acts on, refusing one that is not a
// regular file or that a less privileged user could have written (see
// openTrusted).
func ReadTrusted(path string) ([]byte, error) {
	f, err := openTrusted(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// SPDX-License-Identifier: Apache-2.0

// Package secrets keeps named secrets in a single age-encrypted file
// (secrets.age). Config values of the form secret://name refer to them.
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"filippo.io/age"
)

// RefPrefix marks a config value as a reference to a secret.
const RefPrefix = "secret://"

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Store is the decrypted contents of a secrets file.
type Store struct {
	path       string
	recipients []age.Recipient
	identity   age.Identity
	values     map[string]string
}

// GenerateIdentity writes a new age X25519 identity to path (mode 0600).
// It refuses to overwrite an existing file.
func GenerateIdentity(path string) error {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "# ingressd secrets key — back this up separately from the config\n# public key: %s\n%s\n", id.Recipient(), id)
	return err
}

// LoadIdentity reads an X25519 identity file.
func LoadIdentity(path string) (*age.X25519Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read secrets key: %w", err)
	}
	ids, err := age.ParseIdentities(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("parse secrets key: %w", err)
	}
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			return x, nil
		}
	}
	return nil, errors.New("secrets key file contains no X25519 identity")
}

// Open decrypts the secrets file at path. A missing file yields an empty
// store. Extra recipients (e.g. an offline recovery key) are added on Save.
func Open(path string, id *age.X25519Identity, extra ...age.Recipient) (*Store, error) {
	s := &Store{
		path:       path,
		identity:   id,
		recipients: append([]age.Recipient{id.Recipient()}, extra...),
		values:     map[string]string{},
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, id)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", path, err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.values); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return s, nil
}

// NewMemory returns an unsaved, in-memory store (for tests and dry runs).
func NewMemory(values map[string]string) *Store {
	s := &Store{values: map[string]string{}}
	maps.Copy(s.values, values)
	return s
}

func ValidName(name string) bool { return nameRe.MatchString(name) }

func (s *Store) Get(name string) (string, bool) {
	v, ok := s.values[name]
	return v, ok
}

func (s *Store) Set(name, value string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid secret name %q (use lowercase letters, digits, _ and -)", name)
	}
	s.values[name] = value
	return nil
}

func (s *Store) Delete(name string) { delete(s.values, name) }

// Names returns the secret names, sorted. Values are never listed.
func (s *Store) Names() []string { return slices.Sorted(maps.Keys(s.values)) }

// Resolve returns v unchanged unless it is a secret://name reference, in
// which case it returns the secret's value.
func (s *Store) Resolve(v string) (string, error) {
	name, ok := strings.CutPrefix(v, RefPrefix)
	if !ok {
		return v, nil
	}
	val, ok := s.values[name]
	if !ok {
		return "", fmt.Errorf("secret %q is not set (ingressd secret set %s)", name, name)
	}
	return val, nil
}

// Redact replaces every secret value found in text with «secret:name».
func (s *Store) Redact(text string) string {
	for _, name := range s.Names() {
		if v := s.values[name]; len(v) >= 6 {
			text = strings.ReplaceAll(text, v, "«secret:"+name+"»")
		}
	}
	return text
}

// Save re-encrypts the store to its file atomically.
func (s *Store) Save() error {
	if s.path == "" {
		return errors.New("in-memory secrets store cannot be saved")
	}
	b, err := json.Marshal(s.values)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, s.recipients...)
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// SPDX-License-Identifier: Apache-2.0

// Package envcompat reads INGRESSD_* environment variables, falling back to
// the pre-rename names (see legacyPrefix) with a one-time deprecation warning.
package envcompat

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Prefix starts every current variable name.
const Prefix = "INGRESSD_"

const legacyPrefix = "HOMEEDGE_" // legacy homeedge name, remove after 2027-01

var warned sync.Map

// Legacy returns the pre-rename name of an INGRESSD_* variable ("" for any
// other name).
func Legacy(name string) string {
	rest, ok := strings.CutPrefix(name, Prefix)
	if !ok {
		return ""
	}
	return legacyPrefix + rest
}

// Lookup returns the value of name (which must start with INGRESSD_). When
// it is unset and the legacy name is set, the legacy value is returned and
// a deprecation warning is logged once per variable.
func Lookup(name string) (string, bool) {
	if v, ok := os.LookupEnv(name); ok {
		return v, true
	}
	old := Legacy(name)
	if old == "" {
		return "", false
	}
	v, ok := os.LookupEnv(old)
	if ok {
		if _, done := warned.LoadOrStore(old, true); !done {
			slog.Warn("deprecated environment variable: rename it", "old", old, "new", name)
		}
	}
	return v, ok
}

// Get is Lookup without the found flag.
func Get(name string) string {
	v, _ := Lookup(name)
	return v
}

// SPDX-License-Identifier: Apache-2.0

// Package release describes ingressd releases: semantic versions, the
// signed release manifest (release.json), minisign signatures and the
// release signing key. It has no dependencies on the rest of the code base
// so the panel, the node and the connector share it.
package release

import (
	"strconv"
	"strings"
)

// Version is a parsed semantic version (vMAJOR.MINOR.PATCH[-PRE]).
type Version struct {
	Major, Minor, Patch int
	Pre                 string // pre-release ("rc.1"), "" for a final release
}

// String formats v as "v1.2.3" or "v1.2.3-rc.1".
func (v Version) String() string {
	s := "v" + strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Clean strips what builds append to the version (" (commit)" from
// version.String(), "+build" metadata) and surrounding space.
func Clean(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	return s
}

// Parse parses a release version. It accepts an optional "v", a
// pre-release suffix and anything Clean strips. Development builds ("dev",
// "git describe" output between tags such as "v1.2.3-4-gabc1234", or
// "-dirty" trees) are not releases and are reported as !ok: they cannot be
// compared with releases.
func Parse(s string) (Version, bool) {
	s = strings.TrimPrefix(Clean(s), "v")
	core, pre, hasPre := strings.Cut(s, "-")
	if hasPre && pre == "" {
		return Version{}, false
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	var n [3]int
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return Version{}, false
		}
		x, err := strconv.Atoi(p)
		if err != nil || x < 0 {
			return Version{}, false
		}
		n[i] = x
	}
	if pre != "" && (devSuffix(pre) || !validPre(pre)) {
		return Version{}, false
	}
	return Version{Major: n[0], Minor: n[1], Patch: n[2], Pre: pre}, true
}

// devSuffix recognises "git describe" (N-gHASH) and dirty-tree suffixes.
func devSuffix(pre string) bool {
	if strings.HasSuffix(pre, "dirty") {
		return true
	}
	f := strings.Split(pre, "-")
	if len(f) >= 2 {
		if _, err := strconv.Atoi(f[0]); err == nil && strings.HasPrefix(f[1], "g") && len(f[1]) >= 5 && isHex(f[1][1:]) {
			return true
		}
	}
	return isHex(pre) && len(pre) >= 7 && !isDigits(pre) // bare commit hash
}

func validPre(pre string) bool {
	for _, id := range strings.Split(pre, ".") {
		if id == "" {
			return false
		}
		for _, r := range id {
			if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' {
				return false
			}
		}
	}
	return true
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// DevBuild reports whether s is a development build's version: "dev"
// (no version stamped), "git describe" output between tags, a dirty tree
// or a bare commit hash. Such a version is not comparable, but unlike a
// malformed one it is expected.
func DevBuild(s string) bool {
	s = strings.TrimPrefix(Clean(s), "v")
	if s == "dev" || (devSuffix(s) && !strings.Contains(s, ".")) {
		return true
	}
	core, pre, ok := strings.Cut(s, "-")
	if !ok {
		return false
	}
	f := strings.Split(pre, "-") // "rc.1-4-gabc1234": the describe part is last
	n := len(f)
	describe := n >= 2 && isDigits(f[n-2]) && strings.HasPrefix(f[n-1], "g") && len(f[n-1]) >= 5 && isHex(f[n-1][1:])
	if !describe && !strings.HasSuffix(pre, "dirty") {
		return false
	}
	_, ok = Parse(core)
	return ok
}

// Comparable reports whether s is a release version (not a dev build).
func Comparable(s string) bool {
	_, ok := Parse(s)
	return ok
}

// Compare returns -1, 0 or +1 as a is older than, equal to or newer than b
// (semantic versioning precedence: a pre-release sorts before its release).
func Compare(a, b Version) int {
	for _, d := range [3]int{a.Major - b.Major, a.Minor - b.Minor, a.Patch - b.Patch} {
		if d != 0 {
			return sign(d)
		}
	}
	switch {
	case a.Pre == b.Pre:
		return 0
	case a.Pre == "":
		return 1
	case b.Pre == "":
		return -1
	}
	ai, bi := strings.Split(a.Pre, "."), strings.Split(b.Pre, ".")
	for i := 0; i < len(ai) && i < len(bi); i++ {
		if ai[i] == bi[i] {
			continue
		}
		an, aerr := strconv.Atoi(ai[i])
		bn, berr := strconv.Atoi(bi[i])
		switch {
		case aerr == nil && berr == nil:
			return sign(an - bn)
		case aerr == nil: // numeric identifiers sort first
			return -1
		case berr == nil:
			return 1
		}
		return strings.Compare(ai[i], bi[i])
	}
	return sign(len(ai) - len(bi))
}

func sign(d int) int {
	switch {
	case d < 0:
		return -1
	case d > 0:
		return 1
	}
	return 0
}

// CompareStrings compares two version strings. ok is false when either is
// not a release version (a dev build): such versions are "unknown", never
// "outdated".
func CompareStrings(a, b string) (cmp int, ok bool) {
	va, oka := Parse(a)
	vb, okb := Parse(b)
	if !oka || !okb {
		return 0, false
	}
	return Compare(va, vb), true
}

// Older reports whether current is a release older than latest. A dev
// build is never older (it cannot be compared).
func Older(current, latest string) bool {
	c, ok := CompareStrings(current, latest)
	return ok && c < 0
}

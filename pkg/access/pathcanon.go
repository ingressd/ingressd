// SPDX-License-Identifier: Apache-2.0

// This file is shared verbatim with edge/modules/edgeauth/pathcanon.go (only
// the package clause differs) so the portal and edge_auth can never pick a
// different path rule for the same request. TestPathCanonInSync in
// pkg/access fails when the copies drift; edit both together.

package access

import (
	"errors"
	"path"
	"strings"
)

// ErrAmbiguousPath is returned by CanonicalPath for request paths that an
// origin could read differently from the access rules: backslashes, ";"
// path parameters, NUL bytes, encoded slashes or backslashes, double
// percent-encoding and malformed escapes.
var ErrAmbiguousPath = errors.New("ambiguous request path")

// CanonicalPath turns an escaped request path (url.URL.EscapedPath) into the
// form path rules are matched against: percent-escapes decoded, dot
// segments and duplicate slashes resolved, ASCII letters lowercased, and a
// trailing slash kept. /ADMIN/x, /%61dmin/x, /x/%2e%2e/admin/x and
// /admin//x all canonicalise to /admin/x. The result is only for matching;
// requests are forwarded unchanged.
func CanonicalPath(escaped string) (string, error) {
	var b strings.Builder
	b.Grow(len(escaped) + 1)
	if !strings.HasPrefix(escaped, "/") {
		b.WriteByte('/')
	}
	for i := 0; i < len(escaped); i++ {
		c := escaped[i]
		if c == '%' {
			if i+2 >= len(escaped) || !isHex(escaped[i+1]) || !isHex(escaped[i+2]) {
				return "", ErrAmbiguousPath
			}
			c = unHex(escaped[i+1])<<4 | unHex(escaped[i+2])
			i += 2
			switch c {
			case '/', '\\':
				return "", ErrAmbiguousPath // an encoded separator
			case '%':
				if i+2 < len(escaped) && isHex(escaped[i+1]) && isHex(escaped[i+2]) {
					return "", ErrAmbiguousPath // double encoding (%252e)
				}
			}
		}
		switch c {
		case 0, '\\', ';':
			return "", ErrAmbiguousPath
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	p := b.String()
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c, nil
}

// PathRuleMatch reports whether a canonical request path (CanonicalPath)
// matches a path rule: an exact path, or a prefix ending in "*". Matching
// is case-insensitive. /admin/* does not match /admin itself.
func PathRuleMatch(pattern, canonical string) bool {
	prefix, wildcard := strings.CutSuffix(pattern, "*")
	p, err := CanonicalPath(prefix)
	if err != nil {
		return false
	}
	if wildcard {
		return strings.HasPrefix(canonical, p)
	}
	return canonical == p
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unHex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

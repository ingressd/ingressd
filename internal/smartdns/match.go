// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"strings"

	"github.com/ingressd/ingressd/pkg/config"
)

// route is where a service's names go: its exits in order of preference.
type route struct {
	Service string
	Exits   []string
}

// matcher maps names to services by longest domain suffix.
type matcher map[string]route

func newMatcher(s *config.SmartDNS) matcher {
	m := matcher{}
	if s == nil {
		return m
	}
	for name, svc := range s.Services {
		if !svc.IsEnabled() {
			continue
		}
		r := route{Service: name, Exits: svc.ExitList()}
		for _, d := range svc.Domains {
			m[normalize(d)] = r
		}
	}
	return m
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// match returns the route for the longest service domain that name equals
// or lies under ("tv.stream.example" matches "stream.example", while
// "notstream.example" does not).
func (m matcher) match(name string) (route, bool) {
	name = normalize(name)
	for name != "" {
		if r, ok := m[name]; ok {
			return r, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			break
		}
		name = name[i+1:]
	}
	return route{}, false
}

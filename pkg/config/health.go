// SPDX-License-Identifier: Apache-2.0

package config

import "regexp"

// validateHealthHTTP checks the HTTP-only health check fields (Phase 6).
func validateHealthHTTP(v *validator, p string, h *HealthCheck) {
	if h.Type != HealthHTTP {
		return
	}
	if h.Method != "GET" && h.Method != "HEAD" {
		v.add(p+".method", "must be GET or HEAD, got %q", h.Method)
	}
	if h.ExpectBody != "" {
		if _, err := regexp.Compile(h.ExpectBody); err != nil {
			v.add(p+".expect_body", "invalid regular expression: %v", err)
		}
	}
}

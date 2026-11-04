// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestHealthHTTPValidation(t *testing.T) {
	for _, tc := range []struct{ health, wantErr string }{
		{"{}", ""},
		{"{ method: HEAD, expect_body: 'ok|ready' }", ""},
		{"{ method: POST }", "pools.web.health.method"},
		{"{ expect_body: '(' }", "pools.web.health.expect_body"},
		{"{ type: tcp }", ""},
	} {
		c := mustParse(t, strings.Replace(baseYAML, "    origins:", "    health: "+tc.health+"\n    origins:", 1))
		err := c.Validate()
		if tc.wantErr == "" && err != nil {
			t.Errorf("%s: %v", tc.health, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: got %v, want %s", tc.health, err, tc.wantErr)
		}
	}
	c := mustParse(t, strings.Replace(baseYAML, "    origins:", "    health: {}\n    origins:", 1))
	if m := c.Pools["web"].Health.Method; m != "GET" {
		t.Errorf("default method = %q", m)
	}
}

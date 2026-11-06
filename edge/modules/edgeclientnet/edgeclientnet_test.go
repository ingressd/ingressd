// SPDX-License-Identifier: Apache-2.0

package edgeclientnet

import "testing"

func TestClientNet(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":          "203.0.113.9",
		"::ffff:203.0.113.9":   "203.0.113.9",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"fe80::1%eth0":         "fe80::/64",
		"not an address":       "not an address",
		"":                     "",
	} {
		if got := clientNet(in); got != want {
			t.Errorf("clientNet(%q) = %q, want %q", in, got, want)
		}
	}
}

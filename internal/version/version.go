// SPDX-License-Identifier: Apache-2.0

// Package version holds build metadata, set at link time via -ldflags.
package version

var (
	Version = "dev"
	Commit  = "none"
)

// String returns a human-readable version, e.g. "v0.1.0 (abc1234)".
func String() string {
	return Version + " (" + Commit + ")"
}

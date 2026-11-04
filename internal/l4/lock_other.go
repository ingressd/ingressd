// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package l4

// lockFile is a no-op where flock is unavailable (the edge runs on Linux).
func lockFile(string) (func(), error) { return func() {}, nil }

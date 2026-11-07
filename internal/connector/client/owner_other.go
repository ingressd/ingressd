// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package client

// matchOwner has nothing to do here: the state directory's ACL applies.
func matchOwner(string, string) error { return nil }

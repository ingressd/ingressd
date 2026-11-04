// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package pki

func copyOwner(ref, dst string) error { return nil }

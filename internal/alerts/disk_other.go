// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package alerts

import "errors"

// DiskUsage is only implemented on Unix.
func DiskUsage(string) (Disk, error) { return Disk{}, errors.New("not supported on this platform") }

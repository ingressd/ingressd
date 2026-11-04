// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package connector

import "sync"

var lockMu sync.Mutex

// lockFile serialises updates within the process (the edge runs on Linux;
// this keeps the package building elsewhere).
func lockFile(string) (func(), error) {
	lockMu.Lock()
	return lockMu.Unlock, nil
}

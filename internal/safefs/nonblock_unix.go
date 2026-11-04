// SPDX-License-Identifier: Apache-2.0

//go:build unix

package safefs

import "syscall"

// oNonblock keeps opening a FIFO from blocking; regular files ignore it.
const oNonblock = syscall.O_NONBLOCK

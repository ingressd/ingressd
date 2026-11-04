// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package upgrade

func isWindowsService() bool { return false }

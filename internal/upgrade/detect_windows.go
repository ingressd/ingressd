// SPDX-License-Identifier: Apache-2.0

package upgrade

import "golang.org/x/sys/windows/svc"

func isWindowsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

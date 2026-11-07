// SPDX-License-Identifier: Apache-2.0

//go:build unix

package client

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

func TestAllowAsRootKeepsTheStateFilesOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	_, path := siteState(t, proto.TunnelConfig{Subnets: []string{"192.168.1.0/24"}})
	const uid, gid = 65534, 65533
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := AllowAdd(path, []string{"198.51.100.0/24"}, false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(AllowlistPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != uid || st.Gid != gid || fi.Mode().Perm() != 0o600 {
		t.Errorf("owner %d:%d mode %v", st.Uid, st.Gid, fi.Mode())
	}
	left, err := filepath.Glob(AllowlistPath(path) + ".*")
	if err != nil || len(left) != 0 {
		t.Errorf("left behind: %v, %v", left, err)
	}
}

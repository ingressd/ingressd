// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/pkg/release"
)

func TestUpdateVersionCheck(t *testing.T) {
	u := &updater{work: t.TempDir()}
	m := func(v, floor string) *release.Manifest {
		return &release.Manifest{Version: v, Channel: "stable", MinSupported: floor}
	}
	for _, tc := range []struct {
		name          string
		m             *release.Manifest
		notice, run   string
		want, wantErr string // wantErr: substring; want "current" = errCurrent
	}{
		{name: "upgrade", m: m("v1.2.0", ""), notice: "v1.2.0", run: "v1.1.0"},
		{name: "same", m: m("v1.1.0", ""), run: "v1.1.0", want: "current"},
		{name: "older", m: m("v1.0.0", ""), run: "v1.1.0 (abc1234)", want: "current"},
		{name: "notice mismatch", m: m("v1.2.0", ""), notice: "v9.0.0", run: "v1.1.0", wantErr: "does not match"},
		{name: "dev build takes a signed release", m: m("v1.2.0", ""), run: "dev"},
		{name: "describe build", m: m("v1.2.0", ""), run: "v1.1.0-3-gabc1234"},
		{name: "malformed running version", m: m("v1.2.0", ""), run: "1.1", wantErr: "cannot compare"},
		// Raises the floor to v1.5.0 ...
		{name: "floor seen", m: m("v1.6.0", "v1.5.0"), run: "v1.4.0"},
		// ... which then holds for later notices, even without one.
		{name: "below floor", m: m("v1.4.5", ""), run: "dev", wantErr: "minimum supported version v1.5.0"},
		{name: "lower floor ignored", m: m("v1.4.5", "v1.0.0"), run: "v1.4.0", wantErr: "minimum supported version v1.5.0"},
	} {
		err := u.checkVersion(tc.m, tc.notice, tc.run)
		switch {
		case tc.want == "current":
			if !errors.Is(err, errCurrent) {
				t.Errorf("%s: err = %v, want current", tc.name, err)
			}
		case tc.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
			}
		case err != nil:
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

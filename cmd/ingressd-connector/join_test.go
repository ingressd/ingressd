// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestReadJoin(t *testing.T) {
	if s, err := readJoin(strings.NewReader("\n  ingressd1:abc  \nignored\n")); err != nil || s != "ingressd1:abc" {
		t.Fatalf("readJoin = %q, %v", s, err)
	}
	if _, err := readJoin(strings.NewReader("\n\n")); err == nil {
		t.Fatal("empty input accepted")
	}
}

// "enroll -" reads the join string from stdin (the installer keeps it out
// of argv); a malformed one fails before any network access.
func TestEnrollReadsJoinFromStdin(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetIn(strings.NewReader("not-a-join-string\n"))
	cmd.SetArgs([]string{"--state", t.TempDir() + "/c.json", "enroll", "-"})
	cmd.SetOut(new(strings.Builder))
	cmd.SetErr(new(strings.Builder))
	err := cmd.Execute()
	if err == nil || strings.Contains(err.Error(), "standard input") {
		t.Fatalf("enroll - = %v, want the join string parse error", err)
	}
}

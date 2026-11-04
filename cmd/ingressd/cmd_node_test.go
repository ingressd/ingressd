// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/nodeagent"
)

func TestEnrollTokenSources(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("tok-stdin\n"))
	if tok, err := enrollToken(cmd, "", "-"); err != nil || tok != "tok-stdin" {
		t.Fatalf("stdin: %q %v", tok, err)
	}
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("  tok-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, err := enrollToken(cmd, "", file); err != nil || tok != "tok-file" {
		t.Fatalf("file: %q %v", tok, err)
	}
	t.Setenv(nodeagent.EnrollTokenEnv, "tok-env")
	if tok, err := enrollToken(cmd, "", ""); err != nil || tok != "tok-env" {
		t.Fatalf("env: %q %v", tok, err)
	}
	if tok, err := enrollToken(cmd, "tok-flag", ""); err != nil || tok != "tok-flag" {
		t.Fatalf("flag: %q %v", tok, err)
	}
	t.Setenv(nodeagent.EnrollTokenEnv, "")
	if _, err := enrollToken(cmd, "", ""); err == nil {
		t.Fatal("no token accepted")
	}
	cmd.SetIn(strings.NewReader("\n"))
	if _, err := enrollToken(cmd, "", "-"); err == nil {
		t.Fatal("empty stdin accepted")
	}
}

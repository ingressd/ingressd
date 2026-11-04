// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/pkg/release"
)

// newVerifySumsCmd checks a release's SHA256SUMS signature with the built-in
// release key. deploy/install-node.sh uses it when the minisign CLI is not
// installed: preferably through the already installed binary, else through
// the freshly downloaded one (which only proves as much as the download
// channel, see the installer).
func newVerifySumsCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "verify-sums <SHA256SUMS> <SHA256SUMS.minisig>",
		Short:  "Verify a release's SHA256SUMS signature (used by the installer)",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return verifySums(cmd, args[0], args[1])
		},
	}
}

func verifySums(cmd *cobra.Command, sumsPath, sigPath string) error {
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	trusted, err := release.VerifySums(sums, sig)
	if err != nil {
		return fmt.Errorf("%s: %w", sumsPath, err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "signature OK (%s)\n", trusted)
	return nil
}

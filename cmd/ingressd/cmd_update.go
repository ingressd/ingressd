// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/upgrade"
)

// newUpgradeHelperCmd is the detached helper of a panel-driven update
// (internal/upgrade managed.go): started by the node agent, it swaps the
// binaries, restarts the node and rolls back if the new version does not
// report healthy.
func newUpgradeHelperCmd() *cobra.Command {
	var plan string
	cmd := &cobra.Command{
		Use:    "upgrade-helper",
		Short:  "Carry out a staged update (started by the node agent)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// SIGTERM must not stop the helper half-way: the restart it
			// performs may signal the whole service.
			signal.Ignore(syscall.SIGHUP, syscall.SIGTERM)
			return upgrade.RunHelper(context.Background(), plan)
		},
	}
	cmd.Flags().StringVar(&plan, "plan", "", "plan file")
	_ = cmd.MarkFlagRequired("plan")
	return cmd
}

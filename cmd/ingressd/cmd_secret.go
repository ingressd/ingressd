// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func newSecretCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "secret", Short: "Manage secrets referenced as secret://name"}

	var value, fromFile string
	set := &cobra.Command{
		Use:   "set <name>",
		Short: "Set a secret (value from --value or the first line of stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := e.openSecrets()
			if err != nil {
				return err
			}
			v := value
			if fromFile != "" { // multi-line values such as PEM CA certificates
				b, err := os.ReadFile(fromFile)
				if err != nil {
					return err
				}
				v = string(b)
			}
			if v == "" {
				line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				if err != nil && line == "" {
					return fmt.Errorf("no value given on stdin")
				}
				v = strings.TrimRight(line, "\r\n")
			}
			if err := st.Set(args[0], v); err != nil {
				return err
			}
			if err := st.Save(); err != nil {
				return err
			}
			_, err = e.repo().Commit(os.Getenv("USER"), "Set secret "+args[0], "secrets.age")
			return err
		},
	}
	set.Flags().StringVar(&value, "value", "", "secret value (prefer stdin so it stays out of shell history)")
	set.Flags().StringVar(&fromFile, "from-file", "", "read the whole value from a file (e.g. a PEM CA bundle)")

	rm := &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			st, err := e.openSecrets()
			if err != nil {
				return err
			}
			st.Delete(args[0])
			if err := st.Save(); err != nil {
				return err
			}
			_, err = e.repo().Commit(os.Getenv("USER"), "Delete secret "+args[0], "secrets.age")
			return err
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List secret names (values are never shown)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := e.openSecrets()
			if err != nil {
				return err
			}
			for _, n := range st.Names() {
				fmt.Fprintln(cmd.OutOrStdout(), n)
			}
			return nil
		},
	}

	cmd.AddCommand(set, rm, list)
	return cmd
}

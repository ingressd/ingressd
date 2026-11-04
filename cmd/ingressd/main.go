// SPDX-License-Identifier: Apache-2.0

// Command ingressd is the ingressd control plane and admin CLI.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/apply"
	"github.com/ingressd/ingressd/internal/gitstore"
	"github.com/ingressd/ingressd/internal/pki"
	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/version"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/envcompat"
)

func main() {
	renamedHint(os.Args[0])
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// env holds the filesystem layout, overridable by flags (tests use temp dirs).
type env struct {
	configDir string
	keyPath   string
	stateDir  string
	runDir    string
}

func (e *env) configPath() string    { return filepath.Join(e.configDir, "config.yaml") }
func (e *env) secretsPath() string   { return filepath.Join(e.configDir, "secrets.age") }
func (e *env) adminSocket() string   { return filepath.Join(e.runDir, "caddy-admin.sock") }
func (e *env) controlSocket() string { return filepath.Join(e.runDir, "control.sock") }
func (e *env) repo() gitstore.Repo   { return gitstore.Repo{Dir: e.configDir} }

func (e *env) loadConfig() (*config.Config, error) {
	cfg, err := config.Load(e.configPath())
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s is invalid:\n%w", e.configPath(), err)
	}
	return cfg, nil
}

func (e *env) openSecrets() (*secrets.Store, error) {
	id, err := secrets.LoadIdentity(e.keyPath)
	if err != nil {
		return nil, err
	}
	return secrets.Open(e.secretsPath(), id)
}

func (e *env) renderOptions() render.Options {
	return render.Options{
		AdminListen:     "unix/" + e.adminSocket(),
		StorageDir:      filepath.Join(e.stateDir, "caddy"),
		StorageSocket:   e.managedStorageSocket(),
		StateDir:        e.stateDir,
		ControlSocket:   e.controlSocket(),
		AccessLogSocket: e.accessLogSocket(),
		MachineHost:     e.machineHost(),
		Security:        securityOptions(e),
		ExtraInputTCP:   envPorts("INGRESSD_FIREWALL_ALLOW_TCP"),
		ExtraInputUDP:   envPorts("INGRESSD_FIREWALL_ALLOW_UDP"),
	}
}

// envPorts parses a comma-separated port list from the environment,
// skipping entries that are not valid ports.
func envPorts(name string) []int {
	var ports []int
	for _, f := range strings.Split(envcompat.Get(name), ",") {
		if p, err := strconv.Atoi(strings.TrimSpace(f)); err == nil && p > 0 && p < 65536 {
			ports = append(ports, p)
		}
	}
	return ports
}

func (e *env) engine() *apply.Engine {
	caddy := apply.NewCaddy(e.adminSocket())
	return &apply.Engine{
		StatePath: filepath.Join(e.stateDir, "last-applied.json"),
		Backends:  apply.Backends{Net: apply.Net, NFT: e.nftApply, Caddy: caddy.Load},
	}
}

// commit records the config (and secrets, if present) in git.
func (e *env) commit(author, msg string) (string, error) {
	paths := []string{"config.yaml"}
	if _, err := os.Stat(e.secretsPath()); err == nil {
		paths = append(paths, "secrets.age")
	}
	if _, err := os.Stat(filepath.Join(e.configDir, pki.InventoryFile)); err == nil {
		paths = append(paths, pki.InventoryFile)
	}
	return e.repo().Commit(author, msg, paths...)
}

func newRootCmd() *cobra.Command {
	e := &env{}
	root := &cobra.Command{
		Use:          "ingressd",
		Short:        "Self-hosted edge: tunnels, reverse proxy, access control and WAF",
		SilenceUsage: true,
	}
	f := root.PersistentFlags()
	f.StringVar(&e.configDir, "config-dir", "/etc/ingressd", "directory holding config.yaml and secrets.age (a git repository)")
	f.StringVar(&e.keyPath, "key", "/etc/ingressd-keys/age.key", "age identity that decrypts secrets.age")
	f.StringVar(&e.stateDir, "state-dir", "/var/lib/ingressd", "runtime state (certificates, last applied plan)")
	f.StringVar(&e.runDir, "run-dir", "/run/ingressd", "sockets shared with ingressd-edge")

	root.AddCommand(
		newVersionCmd(),
		newInitCmd(e),
		newValidateCmd(e),
		newDiffCmd(e),
		newApplyCmd(e),
		newHistoryCmd(e),
		newRollbackCmd(e),
		newSecretCmd(e),
		newTunnelCmd(e),
		newServeCmd(e),
		newDoctorCmd(e),
		newCertCmd(e),
		newL4Cmd(e),
		newPoolCmd(e),
		newWAFCmd(e),
		newGeoIPCmd(e),
		newSnapshotCmd(e),
		newCacheCmd(e),
		newAccessCmd(e), newSessionsCmd(e),
		newSmartDNSCmd(e),
		newNodeCmd(e), newImportCmd(e),
		newUpgradeHelperCmd(), newVerifySumsCmd(),
	)
	root.AddCommand(opsCommands(e)...)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "ingressd", version.String())
		},
	}
}

// renamedHint tells someone who started the binary under its pre-rename
// name (an old script or a copied file) what it is called now.
func renamedHint(arg0 string) {
	base := strings.TrimSuffix(filepath.Base(arg0), ".exe")
	if strings.HasPrefix(base, "homeedge") { // legacy homeedge name, remove after 2027-01
		fmt.Fprintf(os.Stderr, "note: homeedge was renamed to ingressd; run %s instead of %s\n", "ingressd", base) // legacy homeedge name, remove after 2027-01
	}
}

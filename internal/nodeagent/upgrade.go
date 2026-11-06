// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/upgrade"
	"github.com/ingressd/ingressd/internal/version"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
	"github.com/ingressd/ingressd/pkg/release"
)

// Remote updates (nodeproto upgrade_request / connector_update, see
// internal/upgrade managed.go for the helper that swaps and rolls back).

// UpgradeOptions configure remote updates; zero values use the defaults
// for an installed node.
type UpgradeOptions struct {
	// WorkDir default <state-dir>/upgrade.
	WorkDir string
	// Binaries default ingressd and ingressd-edge next to the running
	// executable.
	Binaries []upgrade.Binary
	// Install default upgrade.DetectInstall.
	Install string
	// PublicKey verifies manifests (default release.TrustedPublicKey()).
	PublicKey string
	// Restart says how the helper restarts the node (default: the systemd
	// units under systemd, else restart this process as it was started).
	Restart func() upgrade.Restart
	// Helper returns the command that runs the helper for a plan file
	// (default: this executable, "upgrade-helper --plan <file>").
	Helper func(planPath string) (exe string, args []string)
	// HealthTimeout for the new version (default upgrade.DefaultHealthTimeout).
	HealthTimeout time.Duration
	// Version overrides the running version (tests).
	Version string
}

func (a *Agent) upgradeDefaults() {
	u := &a.o.Upgrade
	if u.WorkDir == "" {
		u.WorkDir = filepath.Join(a.o.StateDir, "upgrade")
	}
	if u.Install == "" {
		u.Install = upgrade.DetectInstall("")
	}
	if u.PublicKey == "" {
		u.PublicKey = release.TrustedPublicKey()
	}
	if u.Version == "" {
		u.Version = version.Version
	}
	exe, err := os.Executable()
	if err == nil {
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
	}
	if len(u.Binaries) == 0 && exe != "" {
		dir := filepath.Dir(exe)
		u.Binaries = []upgrade.Binary{
			{Name: "ingressd", Path: exe, CheckVersion: true},
			{Name: "ingressd-edge", Path: filepath.Join(dir, "ingressd-edge")},
		}
	}
	if u.Restart == nil {
		install := u.Install
		u.Restart = func() upgrade.Restart {
			mode := upgrade.RestartMode(install)
			if m := os.Getenv("INGRESSD_UPGRADE_RESTART"); m != "" { // testing: "exec"
				mode = m
			}
			if mode == upgrade.RestartSystemd {
				return upgrade.Restart{Mode: upgrade.RestartSystemd, Units: upgrade.DefaultUnits}
			}
			return upgrade.ExecRestart()
		}
	}
	if u.Helper == nil {
		u.Helper = func(plan string) (string, []string) { return exe, []string{"upgrade-helper", "--plan", plan} }
	}
}

func (a *Agent) currentVersion() string { return release.Clean(a.o.Upgrade.Version) }

func (a *Agent) upgradeProgress(s *session, id, stage, msg string) {
	_ = a.sendOn(s, nodeproto.TypeUpgradeProgress, id, nodeproto.UpgradeProgress{
		ID: id, Stage: stage, Message: msg, Version: a.currentVersion(), Time: time.Now().UTC(),
	})
}

// minSupportedFile keeps the highest min_supported seen in any verified
// manifest: the node never installs anything below it.
const minSupportedFile = "min-supported"

func (a *Agent) minSupported(ms ...*release.Manifest) string {
	path := filepath.Join(a.o.Upgrade.WorkDir, minSupportedFile)
	b, _ := os.ReadFile(path)
	floor := strings.TrimSpace(string(b))
	if _, ok := release.Parse(floor); !ok {
		floor = ""
	}
	changed := false
	for _, m := range ms {
		if m == nil || m.MinSupported == "" {
			continue
		}
		if c, ok := release.CompareStrings(m.MinSupported, floor); floor == "" || (ok && c > 0) {
			floor, changed = m.MinSupported, true
		}
	}
	if changed {
		_ = os.MkdirAll(a.o.Upgrade.WorkDir, 0o700)
		_ = writeFileAtomic(path, []byte(floor+"\n"), 0o600)
	}
	return floor
}

// checkUpgrade decides whether the node may install the request.
func (a *Agent) checkUpgrade(req nodeproto.UpgradeRequest) (*release.Manifest, error) {
	u := a.o.Upgrade
	if u.Install == release.InstallDocker {
		return nil, fmt.Errorf("this node runs in a container: update it by pulling ghcr.io/ingressd/ingressd-node:%s", strings.TrimPrefix(req.Version, "v"))
	}
	m, err := release.VerifyManifest(u.PublicKey, []byte(req.Manifest), []byte(req.Signature))
	if err != nil {
		return nil, err
	}
	if release.Clean(req.Version) != m.Version {
		return nil, fmt.Errorf("requested version %s does not match the signed manifest (%s)", req.Version, m.Version)
	}
	var latest *release.Manifest
	if req.LatestManifest != "" {
		if latest, err = release.VerifyManifest(u.PublicKey, []byte(req.LatestManifest), []byte(req.LatestSignature)); err != nil {
			return nil, fmt.Errorf("latest manifest: %w", err)
		}
	}
	if floor := a.minSupported(m, latest); floor != "" {
		if c, ok := release.CompareStrings(m.Version, floor); ok && c < 0 {
			return nil, fmt.Errorf("%s is below the minimum supported version %s", m.Version, floor)
		}
	}
	cur := a.currentVersion()
	if c, ok := release.CompareStrings(m.Version, cur); ok {
		switch {
		case c == 0:
			return nil, fmt.Errorf("already running %s", cur)
		case c < 0 && !req.Force:
			return nil, fmt.Errorf("%s is older than the running %s (a downgrade must be forced)", m.Version, cur)
		case c < 0 && m.Channel != release.ChannelStable:
			return nil, fmt.Errorf("%s is on the %s channel: only stable releases can be rolled back to", m.Version, m.Channel)
		}
	}
	if upgrade.Pending(u.WorkDir) != nil {
		return nil, errors.New("an update is already in progress")
	}
	return m, nil
}

// handleUpgrade runs one upgrade_request up to the helper's start; the
// result comes from the helper (reported by whichever process runs next).
func (a *Agent) handleUpgrade(s *session, id string, req nodeproto.UpgradeRequest) {
	if req.ID == "" {
		req.ID = id
	}
	if req.ID == "" {
		req.ID = upgrade.NewID()
	}
	if !a.upgrading.CompareAndSwap(false, true) {
		a.upgradeFailed(s, req, errors.New("an update is already in progress"))
		return
	}
	defer a.upgrading.Store(false)
	u := a.o.Upgrade
	m, err := a.checkUpgrade(req)
	if err != nil {
		a.upgradeFailed(s, req, err)
		return
	}
	a.log.Info("update requested", "from", a.currentVersion(), "to", m.Version, "id", req.ID)
	a.upgradeProgress(s, req.ID, nodeproto.UpgradeStageAccepted, "updating "+a.currentVersion()+" to "+m.Version)
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Minute)
	defer cancel()
	plan, err := upgrade.Stage(ctx, upgrade.StageOptions{
		Manifest: m, Sources: req.Sources, Binaries: u.Binaries, OS: runtime.GOOS, Arch: runtime.GOARCH,
		WorkDir: u.WorkDir, From: a.currentVersion(),
		Progress: func(msg string) { a.upgradeProgress(s, req.ID, nodeproto.UpgradeStageDownloading, msg) },
	})
	if err != nil {
		a.upgradeFailed(s, req, err)
		return
	}
	a.upgradeProgress(s, req.ID, nodeproto.UpgradeStageVerified, "release verified; installing")
	plan.ID, plan.Restart = req.ID, u.Restart()
	if u.HealthTimeout > 0 {
		plan.HealthTimeout = u.HealthTimeout
	}
	path, err := plan.Save()
	if err == nil {
		exe, args := u.Helper(path)
		a.upgradeProgress(s, req.ID, nodeproto.UpgradeStageRestarting, "restarting into "+m.Version)
		if err = upgrade.Spawn(plan, exe, args...); err != nil {
			_ = os.Remove(path)
		}
	}
	if err != nil {
		plan.Discard()
		a.upgradeFailed(s, req, fmt.Errorf("start the update: %w", err))
	}
}

func (a *Agent) upgradeFailed(s *session, req nodeproto.UpgradeRequest, err error) {
	a.log.Warn("update refused or failed", "to", req.Version, "err", err)
	_ = a.sendOn(s, nodeproto.TypeUpgradeResult, req.ID, nodeproto.UpgradeResult{
		ID: req.ID, From: a.currentVersion(), To: release.Clean(req.Version), Reason: err.Error(), Time: time.Now().UTC(),
	})
}

// upgradeTick runs with every status: once this process is connected and
// healthy it confirms a pending update to its version (beacon), and it
// reports finished updates.
func (a *Agent) upgradeTick(s *session, st nodeproto.Status) {
	work := a.o.Upgrade.WorkDir
	if st.Health != nodeproto.HealthDown {
		if p := upgrade.Pending(work); p != nil && upgrade.WriteBeacon(work, a.currentVersion()) {
			a.log.Info("update: this version is healthy", "version", a.currentVersion(), "id", p.ID)
			a.upgradeProgress(s, p.ID, nodeproto.UpgradeStageHealthCheck, a.currentVersion()+" is up and connected")
		}
	}
	if o := upgrade.TakeResult(work); o != nil {
		res := nodeproto.UpgradeResult{ID: o.ID, OK: o.OK, From: o.From, To: o.To, RolledBack: o.RolledBack, Reason: o.Reason, Time: o.Time}
		if err := a.sendOn(s, nodeproto.TypeUpgradeResult, o.ID, res); err != nil {
			_ = upgrade.WriteResult(work, *o) // report it on the next connection
		} else {
			a.log.Info("update finished", "ok", o.OK, "from", o.From, "to", o.To, "rolled_back", o.RolledBack, "reason", o.Reason)
		}
	}
}

// handleConnectorUpdate verifies a release notice for a site's connector
// and hands it to the connector server.
func (a *Agent) handleConnectorUpdate(s *session, id string, req nodeproto.ConnectorUpdate) {
	fail := func(err error) {
		_ = a.sendOn(s, nodeproto.TypeEvent, id, nodeproto.Event{
			Kind: "connector_update_failed", Severity: "warning", Message: err.Error(),
			Fields: map[string]string{"site": req.Site, "version": req.Version}, Time: time.Now().UTC(),
		})
	}
	if a.o.Connectors == nil {
		fail(errors.New("connectors are not served on this node"))
		return
	}
	m, err := release.VerifyManifest(a.o.Upgrade.PublicKey, []byte(req.Manifest), []byte(req.Signature))
	if err != nil {
		fail(err)
		return
	}
	if release.Clean(req.Version) != m.Version {
		fail(fmt.Errorf("version %s does not match the signed manifest (%s)", req.Version, m.Version))
		return
	}
	a.minSupported(m)
	cfg, err := a.loadConfig()
	if err != nil {
		fail(err)
		return
	}
	if t, ok := cfg.Tunnels[req.Site]; !ok || t.Site != config.SiteConnector {
		fail(fmt.Errorf("site %q is not a connector site on this node", req.Site))
		return
	}
	nid := req.ID
	if nid == "" {
		nid = upgrade.NewID()
	}
	n := proto.UpdateNotice{ID: nid, Version: m.Version, Manifest: req.Manifest, Signature: req.Signature, Sources: req.Sources, Apply: req.Apply}
	if err := a.o.Connectors.OfferUpdate(req.Site, n); err != nil {
		fail(err)
		return
	}
	a.o.Connectors.PruneReleaseCache(map[string]bool{m.Version: true})
	a.log.Info("connector update offered", "site", req.Site, "version", m.Version, "apply", req.Apply)
	a.nudgeStatus()
}

// connectorUpdateState converts the connector's report.
func connectorUpdateState(u *proto.UpdateState) *nodeproto.ConnectorUpdateState {
	if u == nil {
		return nil
	}
	return &nodeproto.ConnectorUpdateState{ID: u.ID, Version: u.Version, State: u.State, Message: u.Message,
		From: u.From, To: u.To, RolledBack: u.RolledBack, Time: u.Time}
}

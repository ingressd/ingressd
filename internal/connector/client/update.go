// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/upgrade"
	"github.com/ingressd/ingressd/internal/version"
	"github.com/ingressd/ingressd/pkg/release"
)

// Connector self-update (internal/connector/proto/update.go): a notice
// from an edge is verified with the release key built into this binary;
// service installs then stage the new binary (through the edge's release
// relay, else straight from the notice's sources) and hand over to the
// upgrade helper, which swaps it, restarts the service and rolls back if
// the new version does not bring a tunnel up.

// launchdServiceLabel is the launchd label of the installed service
// (service_darwin.go installs it).
const launchdServiceLabel = "com.ingressd.connector"

// restartEnv forces a restart mode (testing: "exec" restarts the process
// itself instead of its service).
const restartEnv = "INGRESSD_UPGRADE_RESTART"

// updateSeenFile remembers the last handled notice so a rolled-back
// update is not retried on every restart.
const updateSeenFile = "update-seen"

// updater is the session's update state.
type updater struct {
	mu      sync.Mutex
	work    string
	install string
	seen    string
	state   *proto.UpdateState
	running bool
}

func newUpdater(statePath string) *updater {
	u := &updater{work: filepath.Join(filepath.Dir(statePath), "upgrade"), install: upgrade.DetectInstall(launchdServiceLabel)}
	if b, err := os.ReadFile(filepath.Join(u.work, updateSeenFile)); err == nil {
		u.seen = strings.TrimSpace(string(b))
	}
	if o := upgrade.LastResult(u.work); o != nil {
		u.state = outcomeState(o)
	}
	return u
}

func outcomeState(o *upgrade.Outcome) *proto.UpdateState {
	st := &proto.UpdateState{ID: o.ID, Version: o.To, From: o.From, To: o.To, RolledBack: o.RolledBack, Message: o.Reason, Time: o.Time}
	switch {
	case o.OK:
		st.State = proto.UpdateUpdated
	case o.RolledBack:
		st.State = proto.UpdateRolledBack
	default:
		st.State = proto.UpdateFailed
	}
	return st
}

func (u *updater) seenID() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.seen
}

func (u *updater) snapshot() *proto.UpdateState {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.state == nil {
		return nil
	}
	c := *u.state
	return &c
}

func (u *updater) set(id, ver, state, msg string) {
	u.mu.Lock()
	u.state = &proto.UpdateState{ID: id, Version: ver, State: state, Message: msg, Time: time.Now().UTC()}
	u.mu.Unlock()
}

// claim marks a notice as handled (so edges stop delivering it); false
// when it was handled before or another one is being installed.
func (u *updater) claim(id string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if id == u.seen {
		return false
	}
	u.seen = id
	_ = upgrade.EnsureDir(u.work)
	_ = upgrade.WriteFileAtomic(filepath.Join(u.work, updateSeenFile), []byte(id+"\n"))
	if u.running {
		return false
	}
	u.running = true
	return true
}

func (u *updater) done() {
	u.mu.Lock()
	u.running = false
	u.mu.Unlock()
}

// tick confirms a pending update once this version has a working tunnel
// and picks up the helper's result.
func (u *updater) tick(healthy bool) {
	if healthy {
		upgrade.WriteBeacon(u.work, version.Version)
	}
	if o := upgrade.TakeResult(u.work); o != nil {
		u.mu.Lock()
		u.state = outcomeState(o)
		u.mu.Unlock()
	}
}

// onNotice handles a claimed update notice from edge e (runs in its own
// goroutine).
func (s *session) onNotice(e *edge, n proto.UpdateNotice) {
	u := s.upd
	defer u.done()
	log := s.log.With("version", n.Version, "id", n.ID)
	m, err := release.VerifyManifest(release.TrustedPublicKey(), []byte(n.Manifest), []byte(n.Signature))
	if err != nil {
		log.Warn("update notice rejected", "err", err)
		u.set(n.ID, n.Version, proto.UpdateFailed, err.Error())
		return
	}
	cur := release.Clean(version.Version)
	if err := u.checkVersion(m, n.Version, version.Version); err != nil {
		if errors.Is(err, errCurrent) {
			u.set(n.ID, m.Version, proto.UpdateCurrent, "already running "+cur)
			return
		}
		log.Warn("update notice rejected", "err", err)
		u.set(n.ID, m.Version, proto.UpdateFailed, err.Error())
		return
	}
	if !release.SelfUpdatable(u.install) {
		msg := "update by downloading " + release.AssetName("ingressd-connector", runtime.GOOS, runtime.GOARCH) + " " + m.Version
		if u.install == release.InstallDocker {
			msg = release.DockerPullCommand(m.Version)
		}
		log.Info("update available", "install", u.install, "how", msg)
		u.set(n.ID, m.Version, proto.UpdateManual, msg)
		return
	}
	if !n.Apply {
		log.Info("update available")
		u.set(n.ID, m.Version, proto.UpdateNotified, "")
		return
	}
	log.Info("updating the connector", "from", cur)
	u.set(n.ID, m.Version, proto.UpdateDownloading, "")
	if err := s.install(e, n, m, cur); err != nil {
		log.Warn("update failed", "err", err)
		u.set(n.ID, m.Version, proto.UpdateFailed, err.Error())
		_ = upgrade.WriteResult(u.work, upgrade.Outcome{ID: n.ID, From: cur, To: m.Version, Reason: err.Error()})
		return
	}
	u.set(n.ID, m.Version, proto.UpdateInstalling, "restarting into "+m.Version)
}

// errCurrent: the offered release is not newer than the running one.
var errCurrent = errors.New("already current")

// checkVersion decides whether the verified manifest m may replace the
// running version running (noticeVersion is what the notice claims).
//
//   - A release at or below the running one is never installed (errCurrent):
//     edges only offer upgrades, so this is never a downgrade path.
//   - Nothing below the highest min_supported seen in any verified
//     manifest is installed (as the node does).
//   - A running version that cannot be compared fails closed, unless it is
//     a development build: those have no place in the version order, and
//     the manifest has already been verified with the release key built
//     into this binary, so what gets installed is a genuine release (the
//     same trust a fresh install of it would get).
func (u *updater) checkVersion(m *release.Manifest, noticeVersion, running string) error {
	if noticeVersion != "" && release.Clean(noticeVersion) != m.Version {
		return fmt.Errorf("notice version %s does not match the signed manifest (%s)", noticeVersion, m.Version)
	}
	if floor := u.minSupported(m); floor != "" {
		if c, ok := release.CompareStrings(m.Version, floor); !ok || c < 0 {
			return fmt.Errorf("%s is below the minimum supported version %s", m.Version, floor)
		}
	}
	c, ok := release.CompareStrings(m.Version, running)
	switch {
	case ok && c <= 0:
		return errCurrent
	case !ok && !release.DevBuild(running):
		return fmt.Errorf("cannot compare the running version %q with %s; not updating", release.Clean(running), m.Version)
	}
	return nil
}

// minSupportedFile keeps the highest min_supported seen in any verified
// manifest: the connector never installs anything below it.
const minSupportedFile = "min-supported"

// minSupported records m's min_supported if it is the highest seen and
// returns the highest.
func (u *updater) minSupported(m *release.Manifest) string {
	path := filepath.Join(u.work, minSupportedFile)
	b, _ := os.ReadFile(path)
	floor := strings.TrimSpace(string(b))
	if !release.Comparable(floor) {
		floor = ""
	}
	if m.MinSupported == "" {
		return floor
	}
	if c, ok := release.CompareStrings(m.MinSupported, floor); floor == "" || (ok && c > 0) {
		floor = m.MinSupported
		if err := upgrade.EnsureDir(u.work); err == nil {
			_ = upgrade.WriteFileAtomic(path, []byte(floor+"\n"))
		}
	}
	return floor
}

func (s *session) install(e *edge, n proto.UpdateNotice, m *release.Manifest, cur string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	ctx, cancel := context.WithTimeout(e.runCtx, 15*time.Minute)
	defer cancel()
	plan, err := upgrade.Stage(ctx, upgrade.StageOptions{
		Manifest: m, Sources: n.Sources, OS: runtime.GOOS, Arch: runtime.GOARCH, WorkDir: s.upd.work, From: cur,
		Binaries: []upgrade.Binary{{Name: "ingressd-connector", Path: exe, CheckVersion: true}},
		Fetch: func(ctx context.Context, asset string) (io.ReadCloser, error) {
			resp, err := e.do(ctx, http.MethodGet, proto.ReleasePathPrefix+asset, nil, nil)
			if err != nil {
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				return nil, fmt.Errorf("edge relay: %s", resp.Status)
			}
			return resp.Body, nil
		},
		Progress: func(msg string) { s.log.Info("update: " + msg) },
	})
	if err != nil {
		return err
	}
	plan.ID = n.ID
	plan.Restart = s.restartPlan()
	if d, err := time.ParseDuration(os.Getenv("INGRESSD_UPGRADE_HEALTH_TIMEOUT")); err == nil && d > 0 {
		plan.HealthTimeout = d
	}
	path, err := plan.Save()
	if err == nil {
		if err = upgrade.Spawn(plan, exe, "upgrade-helper", "--plan", path); err != nil {
			_ = os.Remove(path)
		}
	}
	if err != nil {
		plan.Discard()
		return fmt.Errorf("start the update: %w", err)
	}
	return nil
}

// restartPlan says how the helper restarts this connector.
func (s *session) restartPlan() upgrade.Restart {
	mode := upgrade.RestartMode(s.upd.install)
	if m := os.Getenv(restartEnv); m != "" {
		mode = m
	}
	switch mode {
	case upgrade.RestartSystemd:
		return upgrade.Restart{Mode: mode, Units: []string{ServiceName + ".service"}}
	case upgrade.RestartLaunchd:
		return upgrade.Restart{Mode: mode, Units: []string{launchdServiceLabel}}
	case upgrade.RestartWindows:
		return upgrade.Restart{Mode: mode, Units: []string{ServiceName}}
	}
	return upgrade.ExecRestart()
}

// RunUpgradeHelper is `ingressd-connector upgrade-helper`.
func RunUpgradeHelper(plan string) error {
	if plan == "" {
		return errors.New("--plan is required")
	}
	return upgrade.RunHelper(context.Background(), plan)
}

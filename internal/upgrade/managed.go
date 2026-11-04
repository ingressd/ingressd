// SPDX-License-Identifier: Apache-2.0

package upgrade

// Managed updates (panel-driven, docs/RELEASING.md §6): the
// running process stages a release described by a signed manifest, writes
// a Plan and starts a detached helper (`<binary> upgrade-helper --plan
// <file>`) that survives the restart. The helper swaps the binaries,
// restarts the service, waits for the new process to write a health
// beacon, and rolls back (restores the previous binaries and restarts
// again) when it does not. The outcome lands in result.json, which the
// process running afterwards (new or rolled back) reports.
//
// Work directory layout (<state-dir>/upgrade):
//
//	plan.json        the update in progress (removed when it ends)
//	beacon.json      written by the new process once it is healthy
//	result.json      outcome, waiting to be reported (TakeResult)
//	last-result.json the last reported outcome
//	helper.log       the helper's log

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ingressd/ingressd/pkg/release"
)

// Work directory files.
const (
	PlanFile       = "plan.json"
	BeaconFile     = "beacon.json"
	ResultFile     = "result.json"
	LastResultFile = "last-result.json"
	HelperLogFile  = "helper.log"
)

// Restart modes.
const (
	RestartSystemd = "systemd"         // systemctl restart <units>
	RestartLaunchd = "launchd"         // launchctl kickstart -k system/<unit>
	RestartWindows = "windows-service" // stop and start the service <unit>
	RestartExec    = "exec"            // stop PID, start Argv again (no service manager)
)

// DefaultHealthTimeout is how long the new version has to report healthy.
const DefaultHealthTimeout = 2 * time.Minute

// Binary is one installed binary an update replaces.
type Binary struct {
	Name string // release name, e.g. "ingressd" (asset <name>_<os>_<arch>)
	Path string // installed path
	// CheckVersion runs "<new binary> version" before installing and
	// requires the release version in its output.
	CheckVersion bool
}

// StageOptions describe what to download and where.
type StageOptions struct {
	Manifest *release.Manifest
	// Fetch, when set, is tried first for every asset (the connector
	// downloads through its edge). Then each of Sources (base URLs; the
	// asset URL is <base>/<asset>).
	Fetch    func(ctx context.Context, asset string) (io.ReadCloser, error)
	Sources  []string
	Binaries []Binary
	OS, Arch string
	WorkDir  string
	From     string // version being replaced (for the result)
	Client   *http.Client
	// Progress receives human-readable progress lines.
	Progress func(msg string)
	// MaxSize caps one binary (default 512 MiB).
	MaxSize int64
}

// Swap is one binary replacement.
type Swap struct {
	Path string `json:"path"`
	New  string `json:"new"`
	Old  string `json:"old"`
}

// Restart says how the helper restarts the updated program.
type Restart struct {
	Mode  string   `json:"mode"`
	Units []string `json:"units,omitempty"`
	// RestartExec: the process to stop and the command that starts it.
	PID  int      `json:"pid,omitempty"`
	Argv []string `json:"argv,omitempty"`
	Env  []string `json:"env,omitempty"`
	Dir  string   `json:"dir,omitempty"`
}

// Plan is a staged update the helper carries out.
type Plan struct {
	ID            string        `json:"id"`
	From          string        `json:"from"`
	To            string        `json:"to"`
	Swaps         []Swap        `json:"swaps"`
	Restart       Restart       `json:"restart"`
	WorkDir       string        `json:"work_dir"`
	HealthTimeout time.Duration `json:"health_timeout"`
	Created       time.Time     `json:"created"`
}

// Outcome is the result of an update.
type Outcome struct {
	ID         string    `json:"id"`
	OK         bool      `json:"ok"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	RolledBack bool      `json:"rolled_back"`
	Reason     string    `json:"reason,omitempty"`
	Time       time.Time `json:"time"`
}

// Beacon is written by the new process once it is healthy.
type Beacon struct {
	Version string    `json:"version"`
	PID     int       `json:"pid"`
	Time    time.Time `json:"time"`
}

// NewID returns a random update id.
func NewID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "upg_" + hex.EncodeToString(b)
}

// stagedPath is where a binary's new version is written: next to it (same
// file system, so the swap is an atomic rename), keeping the extension so
// Windows can run it.
func stagedPath(path string) string {
	dir, base := filepath.Split(path)
	ext := filepath.Ext(base)
	return filepath.Join(dir, "."+strings.TrimSuffix(base, ext)+".new"+ext)
}

// OldPath is where the previous binary is kept after a swap.
func OldPath(path string) string { return path + ".old" }

// Stage downloads every binary of the release, verifies it against the
// (already verified) manifest and checks that it runs. Nothing installed
// is touched. The returned plan still needs a Restart and an ID.
func Stage(ctx context.Context, o StageOptions) (*Plan, error) {
	if o.Manifest == nil {
		return nil, errors.New("no release manifest")
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if o.MaxSize <= 0 {
		o.MaxSize = 512 << 20
	}
	progress := func(f string, a ...any) {
		if o.Progress != nil {
			o.Progress(fmt.Sprintf(f, a...))
		}
	}
	p := &Plan{From: o.From, To: o.Manifest.Version, WorkDir: o.WorkDir, HealthTimeout: DefaultHealthTimeout, Created: time.Now().UTC()}
	cleanup := func() {
		for _, s := range p.Swaps {
			_ = os.Remove(s.New)
		}
	}
	for _, b := range o.Binaries {
		asset := release.AssetName(b.Name, o.OS, o.Arch)
		want, ok := o.Manifest.Asset(asset)
		if !ok {
			cleanup()
			return nil, fmt.Errorf("release %s has no %s", o.Manifest.Version, asset)
		}
		tmp := stagedPath(b.Path)
		progress("Downloading %s", asset)
		if err := o.download(ctx, asset, want, tmp); err != nil {
			cleanup()
			return nil, err
		}
		p.Swaps = append(p.Swaps, Swap{Path: b.Path, New: tmp, Old: OldPath(b.Path)})
		progress("Verified %s (sha256 %s…)", asset, want[:12])
		if b.CheckVersion {
			if err := checkVersion(ctx, tmp, o.Manifest.Version); err != nil {
				cleanup()
				return nil, fmt.Errorf("%s: %w", asset, err)
			}
		}
	}
	return p, nil
}

func (o *StageOptions) download(ctx context.Context, asset, want, dst string) error {
	var errs []error
	try := func(name string, open func() (io.ReadCloser, error)) bool {
		rc, err := open()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			return false
		}
		defer rc.Close()
		err = writeVerified(rc, dst, want, o.MaxSize)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			return false
		}
		return true
	}
	if o.Fetch != nil && try("edge", func() (io.ReadCloser, error) { return o.Fetch(ctx, asset) }) {
		return nil
	}
	for _, base := range o.Sources {
		u := strings.TrimSuffix(base, "/") + "/" + asset
		if try(u, func() (io.ReadCloser, error) { return httpGet(ctx, o.Client, u) }) {
			return nil
		}
	}
	if len(errs) == 0 {
		return fmt.Errorf("download %s: no download source", asset)
	}
	return fmt.Errorf("download %s: %w", asset, errors.Join(errs...))
}

// FetchVerified downloads asset from the first source (base URL) that
// serves it with the expected SHA-256 into dst (mode 0755).
func FetchVerified(ctx context.Context, c *http.Client, sources []string, asset, sha256hex, dst string, limit int64) error {
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Minute}
	}
	if limit <= 0 {
		limit = 512 << 20
	}
	o := StageOptions{Sources: sources, Client: c, MaxSize: limit}
	return o.download(ctx, asset, sha256hex, dst)
}

func httpGet(ctx context.Context, c *http.Client, u string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// writeVerified streams r to dst (mode 0755) and checks its SHA-256.
// A leftover dst is removed first and dst created exclusively, so a file
// someone else created there is never written into.
func writeVerified(r io.Reader, dst, want string, limit int64) error {
	_ = os.Remove(dst)
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755) //nolint:gosec // G302: the staged file is an executable
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("larger than %d bytes", limit)
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != want {
		err = errors.New("checksum mismatch")
	}
	if err != nil {
		_ = os.Remove(dst)
		return err
	}
	return os.Chmod(dst, 0o755) //nolint:gosec // G302: the staged file is an executable
}

// checkVersion runs "<bin> version" and requires the release version in
// its output: a binary that does not start (wrong architecture, corrupt)
// never gets installed.
func checkVersion(ctx context.Context, bin, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("the new binary does not run (%w): %s", err, strings.TrimSpace(string(out)))
	}
	if !bytes.Contains(out, []byte(want)) {
		return fmt.Errorf("the new binary reports %q, not %s", strings.TrimSpace(string(out)), want)
	}
	return nil
}

// Discard removes the staged binaries of a plan that will not run.
func (p *Plan) Discard() {
	for _, s := range p.Swaps {
		_ = os.Remove(s.New)
	}
}

// Save writes the plan to <work-dir>/plan.json and returns its path.
func (p *Plan) Save() (string, error) {
	if err := EnsureDir(p.WorkDir); err != nil {
		return "", err
	}
	_ = os.Remove(filepath.Join(p.WorkDir, BeaconFile))
	path := filepath.Join(p.WorkDir, PlanFile)
	return path, writeJSON(path, p)
}

// LoadPlan reads a plan file.
func LoadPlan(path string) (*Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePlan(path, b)
}

// LoadTrustedPlan reads a plan file the helper is about to carry out. The
// plan names binaries to install and, in exec mode, a command to run as the
// helper's (privileged) account, so one that a less privileged user could
// have written is refused (ReadTrusted).
func LoadTrustedPlan(path string) (*Plan, error) {
	b, err := ReadTrusted(path)
	if err != nil {
		return nil, fmt.Errorf("refusing plan: %w", err)
	}
	return parsePlan(path, b)
}

func parsePlan(path string, b []byte) (*Plan, error) {
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

// Pending returns the update in progress in workDir, or nil. A plan older
// than its health timeout plus ten minutes is stale (the helper died, e.g.
// in a reboot) and is removed.
func Pending(workDir string) *Plan {
	p, err := LoadPlan(filepath.Join(workDir, PlanFile))
	if err != nil {
		return nil
	}
	timeout := p.HealthTimeout
	if timeout <= 0 {
		timeout = DefaultHealthTimeout
	}
	if time.Since(p.Created) > timeout+10*time.Minute {
		_ = os.Remove(filepath.Join(workDir, PlanFile))
		return nil
	}
	return p
}

// WriteBeacon tells the helper that this process (running version) is
// healthy. It only writes when an update to that version is in progress
// and reports whether it did.
func WriteBeacon(workDir, version string) bool {
	p := Pending(workDir)
	if p == nil || release.Clean(p.To) != release.Clean(version) {
		return false
	}
	path := filepath.Join(workDir, BeaconFile)
	if b, err := readBeacon(path); err == nil && b.PID == os.Getpid() {
		return false // already written by this process
	}
	return writeJSON(path, Beacon{Version: release.Clean(version), PID: os.Getpid(), Time: time.Now().UTC()}) == nil
}

func readBeacon(path string) (*Beacon, error) {
	var b Beacon
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &b, json.Unmarshal(data, &b)
}

// TakeResult returns the outcome waiting to be reported, moving it to
// last-result.json, or nil.
func TakeResult(workDir string) *Outcome {
	path := filepath.Join(workDir, ResultFile)
	o, err := readOutcome(path)
	if err != nil {
		return nil
	}
	_ = os.Rename(path, filepath.Join(workDir, LastResultFile))
	return o
}

// LastResult returns the most recent outcome (reported or not), or nil.
func LastResult(workDir string) *Outcome {
	if o, err := readOutcome(filepath.Join(workDir, ResultFile)); err == nil {
		return o
	}
	o, _ := readOutcome(filepath.Join(workDir, LastResultFile))
	return o
}

func readOutcome(path string) (*Outcome, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var o Outcome
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// WriteResult records an outcome (used by the helper, and by callers that
// fail before a helper runs).
func WriteResult(workDir string, o Outcome) error {
	if o.Time.IsZero() {
		o.Time = time.Now().UTC()
	}
	if err := EnsureDir(workDir); err != nil {
		return err
	}
	return writeJSON(filepath.Join(workDir, ResultFile), o)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(b, '\n'))
}

// Spawn starts the helper for a saved plan, detached so it survives the
// restart of the process (and, under systemd, of its unit): exe is the
// binary to run (normally the running one) and args its helper arguments.
func Spawn(p *Plan, exe string, args ...string) error {
	if p.Restart.Mode == RestartSystemd {
		if sr, err := exec.LookPath("systemd-run"); err == nil {
			unit := "ingressd-upgrade-" + strings.TrimPrefix(p.ID, "upg_")
			cmd := exec.Command(sr, append([]string{"--unit=" + unit, "--collect", "--quiet", "--", exe}, args...)...)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("systemd-run: %w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

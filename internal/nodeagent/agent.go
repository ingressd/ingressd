// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/ingressd/ingressd/internal/connector"
	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/internal/pipeline"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/internal/version"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// LogSource is the access-log side of internal/observe the agent needs.
type LogSource interface {
	Subscribe(ctx context.Context, f observe.Filter) <-chan observe.Entry
	TakeUsage() map[string]observe.Totals
}

// Options configure an Agent. Paths match the env of `ingressd serve`.
type Options struct {
	StateDir   string
	KeyPath    string
	ConfigPath string
	// AdminSocket is ingressd-edge's (Caddy's) admin socket, for checks.
	AdminSocket string
	// CaddyStorage is Caddy's storage dir (<state-dir>/caddy): edge
	// certificates and the internal CA.
	CaddyStorage string
	// Pipeline applies snapshots (shared with the rest of the process).
	Pipeline *pipeline.Pipeline
	// Keys returns WireGuard keys including connector-enrolled site keys.
	Keys func(cfg *config.Config, st *secrets.Store) tunnel.Keys
	// Logs is the observer (nil: no usage per app, no live preview).
	Logs LogSource
	// Connectors is the connector control server (discovery relay); nil
	// disables discover_request.
	Connectors *connector.Server
	// ConnectorStore holds enrolment tokens and connector health.
	ConnectorStore *connector.Store
	// OnApplied runs after a snapshot was applied (refresh control hosts).
	OnApplied func(cfg *config.Config)
	// ExtraChecks adds doctor-style checks to status.
	ExtraChecks func(ctx context.Context) []nodeproto.Check
	Log         *slog.Logger
	// Intervals (defaults 15 s, 60 s, 5 s); tests shorten them.
	StatusInterval time.Duration
	UsageInterval  time.Duration
	StatusPoll     time.Duration
	// HTTPClient dials the panel (tests); default has sane timeouts.
	HTTPClient *http.Client
	// Upgrade configures remote updates (upgrade.go).
	Upgrade UpgradeOptions
}

// ErrDetached is returned by Run when the node was detached.
var ErrDetached = errors.New("node detached from the panel")

// Agent is the managed-mode client.
type Agent struct {
	o     Options
	log   *slog.Logger
	start time.Time

	mu    sync.Mutex
	state *State
	sess  *session

	usage     *usageQueue
	snapshots chan snapshotJob
	detached  chan struct{}
	detachOne sync.Once

	discMu   sync.Mutex
	discReqs map[string]string // site → request envelope id
	nudge    chan struct{}

	storageCalls pendingCalls // storage_request → storage_response (storage.go)
	upgrading    atomic.Bool  // an upgrade_request is being staged (upgrade.go)
	replay       replayCache  // signed request nonces / forced snapshots seen (trust.go)
}

// session is one WebSocket connection.
type session struct {
	conn   *websocket.Conn
	out    chan []byte
	ctx    context.Context
	cancel context.CancelFunc
	live   *liveSet
}

type snapshotJob struct {
	id string
	s  nodeproto.Snapshot
	// received is when the snapshot arrived: its signature validity is
	// checked against it, so time spent in the queue does not expire it.
	received time.Time
}

// New loads node.json and the usage queue.
func New(o Options) (*Agent, error) {
	st, err := LoadState(o.StateDir)
	if err != nil {
		return nil, err
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.StatusInterval <= 0 {
		o.StatusInterval = 15 * time.Second
	}
	if o.UsageInterval <= 0 {
		o.UsageInterval = 60 * time.Second
	}
	if o.StatusPoll <= 0 {
		o.StatusPoll = 5 * time.Second
	}
	if o.CaddyStorage == "" {
		o.CaddyStorage = filepath.Join(o.StateDir, "caddy")
	}
	if o.ConnectorStore == nil {
		o.ConnectorStore = connector.NewStore(o.StateDir)
	}
	u, err := loadUsage(filepath.Join(o.StateDir, UsageFile))
	if err != nil {
		return nil, err
	}
	a := &Agent{
		o: o, log: o.Log.With("component", "nodeagent"), start: time.Now(),
		state: st, usage: u,
		snapshots: make(chan snapshotJob, 8),
		detached:  make(chan struct{}),
		discReqs:  map[string]string{},
		nudge:     make(chan struct{}, 1),
	}
	a.upgradeDefaults()
	return a, nil
}

// State returns a copy of node.json as the agent sees it.
func (a *Agent) State() State {
	a.mu.Lock()
	defer a.mu.Unlock()
	return *a.state
}

// AppliedConfigSHA is the SHA-256 (hex) of the last applied snapshot's
// config, used by serve to recognise local edits.
func (a *Agent) AppliedConfigSHA() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state.AppliedConfigSHA
}

// Detached is closed when the node is detached.
func (a *Agent) Detached() <-chan struct{} { return a.detached }

// Run keeps the control channel up until ctx is done or the node is
// detached (ErrDetached). The node keeps serving its last applied config
// whether or not the panel is reachable.
func (a *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if a.o.Connectors != nil {
		a.o.Connectors.OnDiscovery = a.onDiscovery
		defer func() { a.o.Connectors.OnDiscovery = nil }()
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); a.snapshotWorker(ctx) }()
	go func() { defer wg.Done(); a.usageLoop(ctx) }()
	go func() { defer wg.Done(); a.watchDetach(ctx) }()
	defer wg.Wait()
	defer cancel()

	backoff := time.Second
	for {
		started := time.Now()
		err := a.session(ctx)
		select {
		case <-a.detached:
			return ErrDetached
		default:
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			a.log.Warn("panel connection", "err", err)
			a.writeRuntime(false, err.Error())
		}
		if time.Since(started) > 30*time.Second {
			backoff = time.Second
		}
		wait := backoff/2 + rand.N(backoff/2+1)
		select {
		case <-ctx.Done():
			return nil
		case <-a.detached:
			return ErrDetached
		case <-time.After(wait):
		}
		backoff = min(backoff*2, 60*time.Second)
	}
}

func (a *Agent) connectURL() (string, error) {
	st := a.State()
	u, err := url.Parse(st.PanelURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		// Only the test escape hatch allows a plain-text control channel.
		if !insecurePanelAllowed() {
			return "", fmt.Errorf("node.json panel_url %q is plain http; the control channel requires https "+
				"(detach and re-enrol with an https panel URL)", st.PanelURL)
		}
		warnInsecurePanel(a.log, st.PanelURL)
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("node.json panel_url %q is not an https URL", st.PanelURL)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + nodeproto.PathConnect
	return u.String(), nil
}

// session runs one connection until it fails or ctx ends.
func (a *Agent) session(ctx context.Context) error {
	wsURL, err := a.connectURL()
	if err != nil {
		return err
	}
	st := a.State()
	dctx, dcancel := context.WithTimeout(ctx, 20*time.Second)
	conn, resp, err := websocket.Dial(dctx, wsURL, &websocket.DialOptions{
		HTTPClient: a.o.HTTPClient,
		HTTPHeader: http.Header{"Authorization": {"Bearer " + st.NodeID + "." + st.Credential}},
	})
	dcancel()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("the panel rejected this node's credential (%w); re-enroll if the node was deleted", err)
		}
		return err
	}
	conn.SetReadLimit(32 << 20)
	sctx, scancel := context.WithCancel(ctx)
	s := &session{conn: conn, out: make(chan []byte, 256), ctx: sctx, cancel: scancel}
	s.live = newLiveSet(a, s)
	defer func() {
		scancel()
		s.live.stopAll()
		a.mu.Lock()
		if a.sess == s {
			a.sess = nil
		}
		a.mu.Unlock()
		conn.CloseNow()
	}()

	writeErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-sctx.Done():
				return
			case b := <-s.out:
				wctx, cancel := context.WithTimeout(sctx, 30*time.Second)
				err := conn.Write(wctx, websocket.MessageText, b)
				cancel()
				if err != nil {
					writeErr <- err
					scancel()
					return
				}
			}
		}
	}()

	if err := a.sendOn(s, nodeproto.TypeHello, "", a.hello()); err != nil {
		return err
	}
	a.mu.Lock()
	a.sess = s
	a.mu.Unlock()
	a.log.Info("connected to panel", "url", wsURL)
	a.writeRuntime(true, "")
	// Resend every unacknowledged usage delta; the panel dedups by seq.
	for _, u := range a.usage.pendingCopy() {
		_ = a.sendOn(s, nodeproto.TypeUsage, "", u)
	}

	readErr := make(chan error, 1)
	go func() {
		for {
			_, b, err := conn.Read(sctx)
			if err != nil {
				readErr <- err
				return
			}
			var env nodeproto.Envelope
			if err := json.Unmarshal(b, &env); err != nil {
				a.log.Warn("bad message from panel", "err", err)
				continue
			}
			a.dispatch(s, env)
		}
	}()

	statusTick := time.NewTicker(a.o.StatusPoll)
	defer statusTick.Stop()
	pingTick := time.NewTicker(30 * time.Second)
	defer pingTick.Stop()
	var lastSig string
	var lastSent time.Time
	sendStatus := func(force bool) {
		stv := a.buildStatus(sctx)
		sig := statusSignature(stv)
		if force || sig != lastSig || time.Since(lastSent) >= a.o.StatusInterval {
			if a.sendOn(s, nodeproto.TypeStatus, "", stv) == nil {
				lastSig, lastSent = sig, time.Now()
			}
		}
		a.upgradeTick(s, stv)
	}
	sendStatus(true)
	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusGoingAway, "node shutting down")
			return nil
		case <-a.detached:
			_ = a.sendNow(s, nodeproto.TypeEvent, "", nodeproto.Event{Kind: "detached", Severity: "info", Message: "node detached; continuing standalone", Time: time.Now().UTC()})
			conn.Close(websocket.StatusNormalClosure, "detached")
			return nil
		case err := <-readErr:
			return fmt.Errorf("read: %w", err)
		case err := <-writeErr:
			return fmt.Errorf("write: %w", err)
		case <-statusTick.C:
			sendStatus(false)
		case <-a.statusNudge():
			sendStatus(true)
		case <-pingTick.C:
			pctx, cancel := context.WithTimeout(sctx, 15*time.Second)
			err := conn.Ping(pctx)
			cancel()
			if err != nil {
				return fmt.Errorf("ping: %w", err)
			}
		}
	}
}

// statusNudge fires when something changed that the panel should see now.
func (a *Agent) statusNudge() <-chan struct{} { return a.nudge }

func (a *Agent) nudgeStatus() {
	select {
	case a.nudge <- struct{}{}:
	default:
	}
}

func (a *Agent) hello() nodeproto.Hello {
	st := a.State()
	h := nodeproto.Hello{
		NodeID: st.NodeID, ProtocolVersion: nodeproto.Version, AgentVersion: version.String(),
		PublicIPv4: st.PublicIPv4, PublicIPv6: st.PublicIPv6,
		AppliedRevision: st.AppliedRevision, UsageSeq: a.usage.seq(),
		Hostname: st.Hostname, SSHPort: st.SSHPort,
		Capabilities: append(append([]string{"live", "diag", "discovery", "usage_ack", nodeproto.CapabilityUpgrade, nodeproto.CapabilityAccessIdentity, nodeproto.CapabilityAccessPasskey, nodeproto.CapabilitySmartDNSChecks, nodeproto.CapabilitySmartDNSFailover}, trustCapabilities...), hookCapabilities()...),
		Install:      a.o.Upgrade.Install, OS: runtime.GOOS, Arch: runtime.GOARCH,
	}
	if id, err := secrets.LoadIdentity(a.o.KeyPath); err == nil {
		h.AgeRecipient = id.Recipient().String()
	}
	if pub, err := a.ensureMeshKey(); err != nil {
		a.log.Warn("mesh key", "err", err)
	} else {
		h.MeshPublicKey = pub
	}
	return h
}

// send queues a message on the current connection; it fails when the node
// is offline.
func (a *Agent) send(typ, id string, v any) error {
	a.mu.Lock()
	s := a.sess
	a.mu.Unlock()
	if s == nil {
		return errors.New("not connected to the panel")
	}
	return a.sendOn(s, typ, id, v)
}

func (a *Agent) sendOn(s *session, typ, id string, v any) error {
	b, err := nodeproto.Encode(typ, id, v)
	if err != nil {
		return err
	}
	select {
	case s.out <- b:
		return nil
	case <-s.ctx.Done():
		return errors.New("connection closed")
	case <-time.After(10 * time.Second):
		return errors.New("send queue full")
	}
}

// sendNow writes synchronously (used just before closing).
func (a *Agent) sendNow(s *session, typ, id string, v any) error {
	b, err := nodeproto.Encode(typ, id, v)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.conn.Write(ctx, websocket.MessageText, b)
}

// dispatch handles one panel message. Long work runs off the read loop.
func (a *Agent) dispatch(s *session, env nodeproto.Envelope) {
	if nodeproto.RequiresSignature(env.Type) {
		if err := a.verifyRequest(env, time.Now()); err != nil {
			a.rejectRequest(s, env, err)
			return
		}
	}
	switch env.Type {
	case nodeproto.TypePing:
		_ = a.sendOn(s, nodeproto.TypePong, env.ID, nil)
	case nodeproto.TypeSnapshot:
		var snap nodeproto.Snapshot
		if err := env.Decode(&snap); err != nil {
			_ = a.sendOn(s, nodeproto.TypeApplied, env.ID, nodeproto.Applied{OK: false, Error: "bad snapshot: " + err.Error()})
			return
		}
		select {
		case a.snapshots <- snapshotJob{id: env.ID, s: snap, received: time.Now()}:
		default:
			_ = a.sendOn(s, nodeproto.TypeApplied, env.ID, nodeproto.Applied{Revision: snap.Revision, Error: "node busy: too many queued snapshots"})
		}
	case nodeproto.TypeUsageAck:
		var ack nodeproto.UsageAck
		if env.Decode(&ack) == nil {
			a.usage.ack(ack.Seq)
		}
	case nodeproto.TypeLiveSubscribe:
		var sub nodeproto.LiveSubscribe
		if env.Decode(&sub) == nil {
			s.live.start(sub)
		}
	case nodeproto.TypeLiveUnsubscribe:
		var u nodeproto.LiveUnsubscribe
		if env.Decode(&u) == nil {
			s.live.stop(u.SubscriptionID)
		}
	case nodeproto.TypeDiagRequest:
		var req nodeproto.DiagRequest
		if err := env.Decode(&req); err != nil {
			return
		}
		go func() {
			res := a.Diagnose(s.ctx, req)
			_ = a.sendOn(s, nodeproto.TypeDiagResult, env.ID, res)
		}()
	case nodeproto.TypeConnectorTokenRequest:
		var req nodeproto.ConnectorTokenRequest
		_ = env.Decode(&req)
		go func() { _ = a.sendOn(s, nodeproto.TypeConnectorToken, env.ID, a.ConnectorToken(req)) }()
	case nodeproto.TypeSiteConfigRequest:
		var req nodeproto.SiteConfigRequest
		_ = env.Decode(&req)
		go func() { _ = a.sendOn(s, nodeproto.TypeSiteConfig, env.ID, a.SiteConfig(req)) }()
	case nodeproto.TypeSmartDNSRecentRequest:
		var req nodeproto.SmartDNSRecentRequest
		_ = env.Decode(&req)
		lookups := hookRecent(max(req.Limit, 0))
		if lookups == nil {
			lookups = []nodeproto.RecentLookup{}
		}
		_ = a.sendOn(s, nodeproto.TypeSmartDNSRecent, env.ID, nodeproto.SmartDNSRecent{Lookups: lookups})
	case nodeproto.TypeDiscoverRequest:
		var req nodeproto.DiscoverRequest
		_ = env.Decode(&req)
		go a.discover(s, env.ID, req)
	case nodeproto.TypeAuthOTPStartResult, nodeproto.TypeAuthOTPVerifyResult, nodeproto.TypeAuthRevoke, nodeproto.TypeL4Allow:
		a.onAccess(env) // hosted Access (auth.go)
	case nodeproto.TypeUpgradeRequest:
		var req nodeproto.UpgradeRequest
		if err := env.Decode(&req); err != nil {
			a.log.Warn("bad upgrade_request", "err", err)
			return
		}
		go a.handleUpgrade(s, env.ID, req)
	case nodeproto.TypeConnectorUpdate:
		var req nodeproto.ConnectorUpdate
		if err := env.Decode(&req); err != nil {
			a.log.Warn("bad connector_update", "err", err)
			return
		}
		go a.handleConnectorUpdate(s, env.ID, req)
	case nodeproto.TypeStorageResponse:
		a.storageCalls.resolve(env)
	case nodeproto.TypeDetach:
		var d nodeproto.Detach
		_ = env.Decode(&d)
		a.log.Info("panel detached this node; continuing standalone", "reason", d.Reason)
		if err := a.Detach(); err != nil {
			a.log.Error("detach", "err", err)
		}
	default:
		a.log.Debug("ignoring unknown message", "type", env.Type)
	}
}

// Detach stops managed mode: node.json is deleted, config.yaml, secrets
// and the edge endpoint stay, and the node keeps serving standalone.
func (a *Agent) Detach() error {
	err := RemoveState(a.o.StateDir)
	_ = os.Remove(filepath.Join(a.o.StateDir, RuntimeFile))
	_ = os.Remove(filepath.Join(a.o.StateDir, SnapshotFile))
	a.detachOne.Do(func() { close(a.detached) })
	return err
}

// watchDetach notices `ingressd node detach` run from the CLI (node.json
// deleted while the agent runs).
func (a *Agent) watchDetach(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.detached:
			return
		case <-t.C:
			if !Managed(a.o.StateDir) {
				a.log.Info("node.json removed; leaving managed mode")
				a.detachOne.Do(func() { close(a.detached) })
				return
			}
		}
	}
}

func (a *Agent) writeRuntime(connected bool, lastErr string) {
	path := filepath.Join(a.o.StateDir, RuntimeFile)
	if !Managed(a.o.StateDir) {
		return
	}
	prev, _ := LoadRuntime(a.o.StateDir)
	r := Runtime{Connected: connected, LastError: lastErr, PID: os.Getpid(), UsageSeq: a.usage.seq(), UsagePending: a.usage.pendingLen()}
	if prev != nil {
		r.LastConnected = prev.LastConnected
		if connected && prev.Connected {
			r.Since = prev.Since
		}
	}
	if connected {
		if r.Since.IsZero() {
			r.Since = time.Now().UTC()
		}
		r.LastConnected = time.Now().UTC()
	}
	_ = writeJSON(path, r, 0o644)
}

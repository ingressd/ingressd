// SPDX-License-Identifier: Apache-2.0

// Package fakepanel is a minimal stand-in for the hosted panel, for tests of
// the node agent: enrolment, the control channel, signed snapshots, and a
// record of everything the node sends. cmd/fakepanel wraps it in a program
// with a small HTTP test API for the netns end-to-end test.
package fakepanel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/coder/websocket"

	"github.com/ingressd/ingressd/internal/storagerelay"
	"github.com/ingressd/ingressd/pkg/access"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Server is the fake panel. One node at a time is expected.
type Server struct {
	// URL is returned as panel_url at enrolment (optional).
	URL string
	// AckUsage controls whether usage messages are acknowledged.
	AckUsage bool
	// MailLog, if set, receives every access code the fake panel "emails"
	// (hosted Access, email.provider panel) in the node's log-provider
	// format, so tests read codes the same way as with provider log.
	MailLog string
	// Downloads, if set, is served at /downloads/ (the panel's release
	// mirror, for remote updates).
	Downloads string

	orgPub  string
	orgPriv ed25519.PrivateKey

	mu        sync.Mutex
	tokens    map[string]bool
	nodeID    string
	cred      string
	recipient string
	conn      *websocket.Conn
	connects  int
	revision  int64
	lastSnap  nodeproto.Snapshot // as last sent (SnapshotOptions.Replay)
	hello     *nodeproto.Hello
	status    *nodeproto.Status
	usage     map[int64]nodeproto.Usage
	usageMsgs int
	logs      []nodeproto.LogEntry
	logDrops  int
	events    []nodeproto.Event
	discovery []nodeproto.Discovery
	otpCodes  map[string]string // email → code
	otpStarts []nodeproto.AuthOTPStart
	revokes   []nodeproto.AuthRevoke
	l4Allows  []nodeproto.L4Allow
	upgrades  []nodeproto.UpgradeProgress
	results   []nodeproto.UpgradeResult
	waiters   map[string]chan nodeproto.Envelope
	changed   chan struct{}
	storage   *storagerelay.Memory // shared certificate storage (storage.go)
}

// New creates a fake panel with a fresh org signing key.
func New() *Server {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Server{
		AckUsage: true,
		orgPub:   base64.StdEncoding.EncodeToString(pub), orgPriv: priv,
		tokens: map[string]bool{}, usage: map[int64]nodeproto.Usage{}, otpCodes: map[string]string{},
		waiters: map[string]chan nodeproto.Envelope{}, changed: make(chan struct{}),
		storage: storagerelay.NewMemory(),
	}
}

// OrgPublicKey is the base64 org signing key nodes pin.
func (s *Server) OrgPublicKey() string { return s.orgPub }

// AddToken registers a one-time enrolment token.
func (s *Server) AddToken(tok string) {
	s.mu.Lock()
	s.tokens[tok] = true
	s.mu.Unlock()
}

func (s *Server) notify() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// Handler serves the node API and, under /test/, the test API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+nodeproto.PathEnroll, s.enroll)
	mux.HandleFunc("GET "+nodeproto.PathConnect, s.connect)
	if s.Downloads != "" {
		mux.Handle("GET /downloads/", http.StripPrefix("/downloads/", http.FileServer(http.Dir(s.Downloads))))
	}
	s.testAPI(mux)
	return mux
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req nodeproto.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := age.ParseX25519Recipient(req.AgeRecipient); err != nil {
		http.Error(w, "age_recipient: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tokens[req.Token] {
		http.Error(w, "invalid or used token", http.StatusForbidden)
		return
	}
	delete(s.tokens, req.Token)
	s.nodeID, s.cred, s.recipient = "nod_"+randHex(6), randHex(24), req.AgeRecipient
	s.revision = 0
	s.notify()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(nodeproto.EnrollResponse{
		NodeID: s.nodeID, OrgID: OrgID, Name: "node-" + req.Hostname,
		Credential: s.cred, OrgSigningKey: s.orgPub, PanelURL: s.URL,
	})
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	want := "Bearer " + s.nodeID + "." + s.cred
	ok := s.nodeID != "" && r.Header.Get("Authorization") == want
	s.mu.Unlock()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(32 << 20)
	ctx := r.Context()
	_, b, err := c.Read(ctx)
	if err != nil {
		return
	}
	var env nodeproto.Envelope
	if json.Unmarshal(b, &env) != nil || env.Type != nodeproto.TypeHello {
		c.Close(websocket.StatusPolicyViolation, "expected hello")
		return
	}
	var h nodeproto.Hello
	_ = env.Decode(&h)
	s.mu.Lock()
	if s.conn != nil {
		s.conn.CloseNow()
	}
	s.conn, s.hello = c, &h
	s.connects++
	s.notify()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.conn == c {
			s.conn = nil
			s.notify()
		}
		s.mu.Unlock()
		c.CloseNow()
	}()
	for {
		_, b, err := c.Read(ctx)
		if err != nil {
			return
		}
		// A fresh envelope per message: json.RawMessage reuses its buffer,
		// and waiters keep the envelope after this loop moves on.
		var env nodeproto.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			continue
		}
		s.handle(ctx, c, env)
	}
}

func (s *Server) handle(ctx context.Context, c *websocket.Conn, env nodeproto.Envelope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.notify()
	switch env.Type {
	case nodeproto.TypeStatus:
		var st nodeproto.Status
		if env.Decode(&st) == nil {
			s.status = &st
		}
	case nodeproto.TypeUsage:
		var u nodeproto.Usage
		if env.Decode(&u) != nil {
			return
		}
		s.usageMsgs++
		if _, dup := s.usage[u.Seq]; !dup {
			s.usage[u.Seq] = u
		}
		if s.AckUsage {
			b, _ := nodeproto.Encode(nodeproto.TypeUsageAck, "", nodeproto.UsageAck{Seq: u.Seq})
			go func() { _ = c.Write(ctx, websocket.MessageText, b) }()
		}
	case nodeproto.TypeLog:
		var lb nodeproto.LogBatch
		if env.Decode(&lb) == nil {
			s.logs = append(s.logs, lb.Entries...)
			s.logDrops += lb.Dropped
		}
	case nodeproto.TypeEvent:
		var ev nodeproto.Event
		if env.Decode(&ev) == nil {
			s.events = append(s.events, ev)
		}
	case nodeproto.TypeDiscovery:
		var d nodeproto.Discovery
		if env.Decode(&d) == nil {
			s.discovery = append(s.discovery, d)
		}
	case nodeproto.TypeStorageRequest:
		s.handleStorage(ctx, c, env, s.nodeID)
		return // not a reply to a panel request; nothing changed for waiters
	case nodeproto.TypePing:
		b, _ := nodeproto.Encode(nodeproto.TypePong, env.ID, nil)
		go func() { _ = c.Write(ctx, websocket.MessageText, b) }()
	case nodeproto.TypeAuthOTPStart, nodeproto.TypeAuthOTPVerify:
		typ, res := s.otp(env)
		b, _ := nodeproto.Encode(typ, env.ID, res)
		go func() { _ = c.Write(ctx, websocket.MessageText, b) }()
		return // a request, not a reply to one of ours
	case nodeproto.TypeAuthRevoke:
		var r nodeproto.AuthRevoke
		if env.Decode(&r) == nil {
			s.revokes = append(s.revokes, r)
		}
	case nodeproto.TypeL4Allow:
		var a nodeproto.L4Allow
		if env.Decode(&a) == nil {
			s.l4Allows = append(s.l4Allows, a)
		}
	case nodeproto.TypeUpgradeProgress:
		var p nodeproto.UpgradeProgress
		if env.Decode(&p) == nil {
			s.upgrades = append(s.upgrades, p)
		}
	case nodeproto.TypeUpgradeResult:
		var r nodeproto.UpgradeResult
		if env.Decode(&r) == nil {
			s.results = append(s.results, r)
		}
	}
	if env.ID != "" {
		if ch := s.waiters[env.ID]; ch != nil {
			delete(s.waiters, env.ID)
			ch <- env
		}
	}
}

// otp answers auth_otp_start / auth_otp_verify like the hosted panel
// (without its rate limits). Called with the lock held.
func (s *Server) otp(env nodeproto.Envelope) (string, any) {
	if env.Type == nodeproto.TypeAuthOTPStart {
		var req nodeproto.AuthOTPStart
		if err := env.Decode(&req); err != nil {
			return nodeproto.TypeAuthOTPStartResult, nodeproto.AuthOTPStartResult{Code: nodeproto.OTPUnavailable, Message: err.Error()}
		}
		n := req.Length
		if n < 4 || n > 8 {
			n = 6
		}
		code := ""
		for _, b := range []byte(randHex(n))[:n] {
			code += string(rune('0' + b%10))
		}
		s.otpCodes[req.Email] = code
		s.otpStarts = append(s.otpStarts, req)
		if s.MailLog != "" {
			label := req.Label
			if label == "" {
				label = req.Host
			}
			if f, err := os.OpenFile(s.MailLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
				fmt.Fprintf(f, "Date: %s\nTo: %s\nSubject: Your sign-in code for %s\n\nYour sign-in code for %s is: %s\n\nRequested from %s on %s.\n-----\n",
					time.Now().UTC().Format(time.RFC3339), req.Email, label, label, code, req.ClientIP, req.Host)
				_ = f.Close()
			}
		}
		return nodeproto.TypeAuthOTPStartResult, nodeproto.AuthOTPStartResult{OK: true, Code: nodeproto.OTPOK, TTL: 10 * time.Minute}
	}
	var req nodeproto.AuthOTPVerify
	if err := env.Decode(&req); err != nil {
		return nodeproto.TypeAuthOTPVerifyResult, nodeproto.AuthOTPVerifyResult{Code: nodeproto.OTPInvalid}
	}
	if c, ok := s.otpCodes[req.Email]; ok && c == req.Code {
		delete(s.otpCodes, req.Email)
		return nodeproto.TypeAuthOTPVerifyResult, nodeproto.AuthOTPVerifyResult{OK: true, Code: nodeproto.OTPOK, Email: req.Email}
	}
	return nodeproto.TypeAuthOTPVerifyResult, nodeproto.AuthOTPVerifyResult{Code: nodeproto.OTPInvalid}
}

// OTPCode returns the last code "emailed" to email ("" if none).
func (s *Server) OTPCode(email string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.otpCodes[email]
}

// Connected reports whether a node is connected.
func (s *Server) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn != nil
}

// WaitConnected waits until a node is connected (and has sent hello).
func (s *Server) WaitConnected(ctx context.Context) error {
	return s.Wait(ctx, func() bool { return s.conn != nil })
}

// Wait blocks until cond (called with the lock held) is true.
func (s *Server) Wait(ctx context.Context, cond func() bool) error {
	for {
		s.mu.Lock()
		ok := cond()
		ch := s.changed
		s.mu.Unlock()
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Send sends a message without waiting for a reply. Like the panel, it
// org-signs the types nodeproto.RequiresSignature lists when the node
// advertised nodeproto.CapabilitySignedRequests.
func (s *Server) Send(ctx context.Context, typ, id string, data any) error {
	return s.send(ctx, typ, id, data, true)
}

// SendUnsigned sends a message without a request signature (tests that the
// node rejects it).
func (s *Server) SendUnsigned(ctx context.Context, typ, id string, data any) error {
	return s.send(ctx, typ, id, data, false)
}

func (s *Server) wantsSigned() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hello != nil && slices.Contains(s.hello.Capabilities, nodeproto.CapabilitySignedRequests)
}

func (s *Server) send(ctx context.Context, typ, id string, data any, sign bool) error {
	var b []byte
	var err error
	if sign && nodeproto.RequiresSignature(typ) && s.wantsSigned() {
		b, err = s.SignedEnvelope(typ, id, data)
	} else {
		b, err = nodeproto.Encode(typ, id, data)
	}
	if err != nil {
		return err
	}
	return s.SendRaw(ctx, b)
}

// SignedEnvelope encodes an org-signed envelope for the enrolled node.
func (s *Server) SignedEnvelope(typ, id string, data any) ([]byte, error) {
	s.mu.Lock()
	nodeID := s.nodeID
	s.mu.Unlock()
	return nodeproto.EncodeSigned(typ, id, data, nodeID, OrgID, time.Now(), s.orgPriv)
}

// SendRaw writes an encoded envelope to the node as is (replay tests).
func (s *Server) SendRaw(ctx context.Context, b []byte) error {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c == nil {
		return errors.New("no node connected")
	}
	return c.Write(ctx, websocket.MessageText, b)
}

// Request sends a message and waits for the reply that echoes its id.
func (s *Server) Request(ctx context.Context, typ string, data any) (nodeproto.Envelope, error) {
	return s.request(ctx, typ, data, true)
}

// RequestUnsigned is Request without a request signature.
func (s *Server) RequestUnsigned(ctx context.Context, typ string, data any) (nodeproto.Envelope, error) {
	return s.request(ctx, typ, data, false)
}

func (s *Server) request(ctx context.Context, typ string, data any, sign bool) (nodeproto.Envelope, error) {
	id := randHex(8)
	ch := make(chan nodeproto.Envelope, 1)
	s.mu.Lock()
	s.waiters[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.waiters, id)
		s.mu.Unlock()
	}()
	if err := s.send(ctx, typ, id, data, sign); err != nil {
		return nodeproto.Envelope{}, err
	}
	select {
	case env := <-ch:
		return env, nil
	case <-ctx.Done():
		return nodeproto.Envelope{}, fmt.Errorf("waiting for reply to %s: %w", typ, ctx.Err())
	}
}

// OrgID is the org the fake panel enrols nodes into.
const OrgID = "org_test"

// SnapshotOptions tweak SendSnapshot.
type SnapshotOptions struct {
	Secrets       map[string]string // plaintext; encrypted to the node here
	RemoveSecrets []string
	Force         bool
	// Revision overrides the next revision (0: previous + 1).
	Revision int64
	// Tamper changes the config after signing (the node must reject it).
	Tamper bool
	// Legacy signs with the v1 payload (what an old panel sends; current
	// nodes must reject it).
	Legacy bool `json:"legacy"`
	// SignedAt signs as of this time (zero: now); an old time yields an
	// expired snapshot.
	SignedAt time.Time `json:"signed_at"`
	// ForNode binds the snapshot to another node ID (must be rejected).
	ForNode string `json:"for_node"`
	// Replay resends the previous snapshot exactly as it was sent (same
	// signature); the other options are ignored.
	Replay bool `json:"replay"`
}

// SendSnapshot signs and sends a snapshot and returns the node's reply.
func (s *Server) SendSnapshot(ctx context.Context, configYAML string, o SnapshotOptions) (nodeproto.Applied, error) {
	s.mu.Lock()
	rcpt := s.recipient
	rev := o.Revision
	if rev == 0 {
		rev = s.revision + 1
	}
	s.mu.Unlock()
	snap := nodeproto.Snapshot{Revision: rev, ConfigYAML: configYAML, RemoveSecrets: o.RemoveSecrets, Force: o.Force, SignedAt: time.Now().UTC()}
	if len(o.Secrets) > 0 {
		snap.Secrets = map[string]string{}
		for name, v := range o.Secrets {
			ct, err := Encrypt(v, rcpt)
			if err != nil {
				return nodeproto.Applied{}, err
			}
			snap.Secrets[name] = ct
		}
	}
	s.mu.Lock()
	nodeID := s.nodeID
	s.mu.Unlock()
	if o.ForNode != "" {
		nodeID = o.ForNode
	}
	switch {
	case o.Replay:
		s.mu.Lock()
		snap = s.lastSnap
		rev = snap.Revision
		s.mu.Unlock()
	case o.Legacy:
		nodeproto.Sign(&snap, s.orgPriv)
	default:
		at := o.SignedAt
		if at.IsZero() {
			at = time.Now()
		}
		nodeproto.SignV2(&snap, nodeID, OrgID, at, s.orgPriv)
	}
	if o.Tamper {
		snap.ConfigYAML += "\n# tampered\n"
	}
	s.mu.Lock()
	s.lastSnap = snap
	s.mu.Unlock()
	env, err := s.Request(ctx, nodeproto.TypeSnapshot, snap)
	if err != nil {
		return nodeproto.Applied{}, err
	}
	var a nodeproto.Applied
	if err := env.Decode(&a); err != nil {
		return a, err
	}
	if a.OK {
		s.mu.Lock()
		s.revision = max(s.revision, rev)
		s.mu.Unlock()
	}
	return a, nil
}

// Encrypt encrypts plaintext to an age recipient (armored), as the panel's
// browser code does.
func Encrypt(plaintext, recipient string) (string, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		return "", err
	}
	_, _ = io.WriteString(w, plaintext)
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := aw.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// AppTotals sums deduplicated usage per app.
type AppTotals struct {
	Requests  int64 `json:"requests"`
	BytesOut  int64 `json:"bytes_out"`
	Status2xx int64 `json:"status_2xx"`
	Status4xx int64 `json:"status_4xx"`
	Status5xx int64 `json:"status_5xx"`
}

// Snapshot of what the panel has seen, for assertions.
type State struct {
	NodeID    string                `json:"node_id"`
	Connected bool                  `json:"connected"`
	Connects  int                   `json:"connects"`
	Revision  int64                 `json:"revision"`
	Hello     *nodeproto.Hello      `json:"hello"`
	Status    *nodeproto.Status     `json:"status"`
	UsageSeqs []int64               `json:"usage_seqs"`
	UsageMsgs int                   `json:"usage_msgs"`
	Apps      map[string]AppTotals  `json:"apps"`
	Sites     map[string][2]int64   `json:"sites"`
	Logs      []nodeproto.LogEntry  `json:"logs"`
	LogDrops  int                   `json:"log_drops"`
	Events    []nodeproto.Event     `json:"events"`
	Discovery []nodeproto.Discovery `json:"discovery"`
	// Hosted Access traffic.
	OTPStarts []nodeproto.AuthOTPStart `json:"otp_starts"`
	Revokes   []nodeproto.AuthRevoke   `json:"revokes"`
	L4Allows  []nodeproto.L4Allow      `json:"l4_allows"`
	// Remote updates.
	UpgradeProgress []nodeproto.UpgradeProgress `json:"upgrade_progress"`
	UpgradeResults  []nodeproto.UpgradeResult   `json:"upgrade_results"`
}

// State returns everything recorded so far.
func (s *Server) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := State{
		NodeID: s.nodeID, Connected: s.conn != nil, Connects: s.connects, Revision: s.revision,
		Hello: s.hello, Status: s.status, UsageMsgs: s.usageMsgs,
		Apps: map[string]AppTotals{}, Sites: map[string][2]int64{},
		Logs: slices.Clone(s.logs), LogDrops: s.logDrops,
		Events: slices.Clone(s.events), Discovery: slices.Clone(s.discovery),
		OTPStarts: slices.Clone(s.otpStarts), Revokes: slices.Clone(s.revokes), L4Allows: slices.Clone(s.l4Allows),
		UpgradeProgress: slices.Clone(s.upgrades), UpgradeResults: slices.Clone(s.results),
	}
	for seq, u := range s.usage {
		st.UsageSeqs = append(st.UsageSeqs, seq)
		for _, a := range u.Apps {
			t := st.Apps[a.App]
			t.Requests += a.Requests
			t.BytesOut += a.BytesOut
			t.Status2xx += a.Status2xx
			t.Status4xx += a.Status4xx
			t.Status5xx += a.Status5xx
			st.Apps[a.App] = t
		}
		for _, x := range u.Sites {
			v := st.Sites[x.Site]
			st.Sites[x.Site] = [2]int64{v[0] + x.RxBytes, v[1] + x.TxBytes}
		}
	}
	slices.Sort(st.UsageSeqs)
	return st
}

// testAPI is the HTTP surface the netns test drives with curl.
func (s *Server) testAPI(mux *http.ServeMux) {
	reply := func(w http.ResponseWriter, v any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}
	timeout := func(r *http.Request) (context.Context, context.CancelFunc) {
		return context.WithTimeout(r.Context(), 60*time.Second)
	}
	mux.HandleFunc("POST /test/token", func(w http.ResponseWriter, r *http.Request) {
		s.AddToken(r.URL.Query().Get("t"))
		reply(w, map[string]bool{"ok": true}, nil)
	})
	s.storageAPI(mux)
	mux.HandleFunc("GET /test/state", func(w http.ResponseWriter, r *http.Request) {
		reply(w, s.State(), nil)
	})
	mux.HandleFunc("POST /test/ack", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.AckUsage = r.URL.Query().Get("on") != "0"
		s.mu.Unlock()
		reply(w, map[string]bool{"ok": true}, nil)
	})
	mux.HandleFunc("POST /test/snapshot", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ConfigYAML string `json:"config_yaml"`
			SnapshotOptions
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reply(w, nil, err)
			return
		}
		ctx, cancel := timeout(r)
		defer cancel()
		a, err := s.SendSnapshot(ctx, req.ConfigYAML, req.SnapshotOptions)
		reply(w, a, err)
	})
	mux.HandleFunc("POST /test/request", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
			// Unsigned skips the request signature (the node must reject it).
			Unsigned bool `json:"unsigned"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reply(w, nil, err)
			return
		}
		ctx, cancel := timeout(r)
		defer cancel()
		env, err := s.request(ctx, req.Type, req.Data, !req.Unsigned)
		reply(w, env, err)
	})
	mux.HandleFunc("POST /test/send", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Type     string          `json:"type"`
			Data     json.RawMessage `json:"data"`
			Unsigned bool            `json:"unsigned"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reply(w, nil, err)
			return
		}
		reply(w, map[string]bool{"ok": true}, s.send(r.Context(), req.Type, "", req.Data, !req.Unsigned))
	})
	// The panel's central sign-in portal (access.portal_url): after the
	// visitor proved an email, the panel seals a callback code with the org
	// keys. Tests pass the keys they delivered in the snapshot.
	mux.HandleFunc("POST /test/portal-code", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SessionKey string `json:"session_key"`
			JWTKey     string `json:"jwt_key"`
			App        string `json:"app"`
			RD         string `json:"rd"`
			Email      string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reply(w, nil, err)
			return
		}
		cb, err := PortalCallback(req.SessionKey, req.JWTKey, req.App, req.RD, req.Email)
		reply(w, map[string]string{"callback": cb}, err)
	})
	mux.HandleFunc("GET /test/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "fake panel: "+strings.Join([]string{"POST /test/token?t=", "GET /test/state", "POST /test/snapshot", "POST /test/request", "POST /test/send", "POST /test/ack?on=0|1", "POST /test/portal-code"}, ", ")+"\n")
	})
}

// PortalCallback plays the panel's central portal: it seals a callback code
// for email (as if they signed in) and returns the app's callback URL.
func PortalCallback(sessionKey, jwtKey, app, rd, email string) (string, error) {
	keys, err := access.ParseKeys(sessionKey, jwtKey)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(rd)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid rd %q", rd)
	}
	now := time.Now()
	code, err := keys.SealCode(access.SealedCode{ID: randHex(16), SID: "panel-" + randHex(8), Email: email, App: app, RD: rd,
		SessionIssued: now, SessionExpires: now.Add(24 * time.Hour), Expires: now.Add(time.Minute)})
	if err != nil {
		return "", err
	}
	return (&url.URL{Scheme: "https", Host: u.Host, Path: "/.ingressd/callback", RawQuery: url.Values{"code": {code}}.Encode()}).String(), nil
}

// Drop closes the node's connection (it should reconnect).
func (s *Server) Drop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.CloseNow()
	}
}

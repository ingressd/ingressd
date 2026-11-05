// SPDX-License-Identifier: Apache-2.0

// Package nodeproto is the panel ↔ node control channel protocol (see
// docs/rev1/ARCHITECTURE.md §4). It has no dependencies on the rest of the
// code base so both the panel and the node agent can import it.
//
// Transport: the node dials PathConnect as a WebSocket with
// "Authorization: Bearer <node_id>.<credential>" and exchanges JSON
// Envelopes. Enrolment is a plain HTTPS POST to PathEnroll.
package nodeproto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Version is the protocol version sent in Hello. Bump on breaking changes.
const Version = 1

const (
	PathEnroll  = "/api/node/v1/enroll"
	PathConnect = "/api/node/v1/connect"
)

// Message types, panel → node.
const (
	TypeSnapshot        = "snapshot"
	TypeLiveSubscribe   = "live_subscribe"
	TypeLiveUnsubscribe = "live_unsubscribe"
	TypeDiagRequest     = "diag_request"
	TypeDiscoverRequest = "discover_request"
	TypeDetach          = "detach"
	TypePing            = "ping"
	// Requests answered by the node because the data lives only there.
	TypeConnectorTokenRequest = "connector_token_request" // → TypeConnectorToken
	TypeSiteConfigRequest     = "site_config_request"     // → TypeSiteConfig
	TypeSmartDNSRecentRequest = "smartdns_recent_request" // → TypeSmartDNSRecent
	// TypeUsageAck acknowledges usage messages up to and including a seq;
	// the node keeps (and resends after reconnecting) every unacknowledged
	// usage message.
	TypeUsageAck = "usage_ack"
)

// Message types, node → panel.
const (
	TypeHello      = "hello"
	TypeApplied    = "applied"
	TypeStatus     = "status"
	TypeUsage      = "usage"
	TypeLog        = "log"
	TypeDiagResult = "diag_result"
	TypeDiscovery  = "discovery"
	TypeEvent      = "event"
	TypePong       = "pong"
	// Responses to the node-answered requests above; ID echoes the request.
	TypeConnectorToken = "connector_token"
	TypeSiteConfig     = "site_config"
	TypeSmartDNSRecent = "smartdns_recent"
)

// Envelope frames every WebSocket message.
type Envelope struct {
	Type string          `json:"type"`
	ID   string          `json:"id,omitempty"` // correlates requests and results where useful
	Data json.RawMessage `json:"data,omitempty"`
	// Auth is the org-key signature of a panel → node request (signing.go);
	// set for the types RequiresSignature lists when the node advertises
	// CapabilitySignedRequests.
	Auth *RequestAuth `json:"auth,omitempty"`
}

// Encode wraps v in an envelope of the given type.
func Encode(typ, id string, v any) ([]byte, error) {
	var data json.RawMessage
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		data = b
	}
	return json.Marshal(Envelope{Type: typ, ID: id, Data: data})
}

// Decode unmarshals an envelope's data into v.
func (e Envelope) Decode(v any) error {
	if len(e.Data) == 0 {
		return fmt.Errorf("%s: empty data", e.Type)
	}
	return json.Unmarshal(e.Data, v)
}

// --- Enrolment ---

type EnrollRequest struct {
	Token        string `json:"token"`
	Name         string `json:"name,omitempty"` // optional; the token may already carry one
	Hostname     string `json:"hostname"`
	PublicIPv4   string `json:"public_ipv4,omitempty"`
	PublicIPv6   string `json:"public_ipv6,omitempty"`
	AgeRecipient string `json:"age_recipient"` // node's age X25519 public key
	// SSHPort is the port sshd listens on (additive, rev1); the compiler
	// must set edge.ssh_port to it or the managed firewall locks the owner out.
	SSHPort int    `json:"ssh_port,omitempty"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

type EnrollResponse struct {
	NodeID     string `json:"node_id"`
	OrgID      string `json:"org_id"`
	Name       string `json:"name"`
	Credential string `json:"credential"` // shown once; panel stores a hash
	// OrgSigningKey is the org's ed25519 public key (base64, std encoding).
	// The node pins it and rejects snapshots not signed by it.
	OrgSigningKey string `json:"org_signing_key"`
	PanelURL      string `json:"panel_url"`
}

// --- Node → panel ---

type Hello struct {
	NodeID          string   `json:"node_id"`
	ProtocolVersion int      `json:"protocol_version"`
	AgentVersion    string   `json:"agent_version"`
	AgeRecipient    string   `json:"age_recipient"`
	PublicIPv4      string   `json:"public_ipv4,omitempty"`
	PublicIPv6      string   `json:"public_ipv6,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"` // e.g. "smartdns", "mesh", "l4"
	AppliedRevision int64    `json:"applied_revision"`
	UsageSeq        int64    `json:"usage_seq"` // last usage seq the node sent
	// MetricsSeq is the last metrics seq the node produced (additive).
	MetricsSeq int64 `json:"metrics_seq,omitempty"`
	// MeshPublicKey is the node's WireGuard key for the org mesh (generated
	// and kept on the node); the panel distributes it to the other nodes.
	MeshPublicKey string `json:"mesh_public_key,omitempty"`
	// Hostname is the node's public DNS name if one was configured at
	// enrolment (used for connector endpoints and site configs).
	Hostname string `json:"hostname,omitempty"`
	// SSHPort is the port sshd listens on (additive, rev1; see EnrollRequest).
	SSHPort int `json:"ssh_port,omitempty"`
	// Install is how the node was installed (pkg/release Install*: systemd,
	// docker, manual), OS/Arch its platform: what remote updates need
	// (additive).
	Install string `json:"install,omitempty"`
	OS      string `json:"os,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

type Applied struct {
	Revision int64  `json:"revision"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
}

// Health values.
const (
	HealthOK       = "ok"
	HealthDegraded = "degraded"
	HealthDown     = "down"
)

type Status struct {
	Time            time.Time      `json:"time"`
	Health          string         `json:"health"`
	Checks          []Check        `json:"checks,omitempty"` // doctor-style checks
	AppliedRevision int64          `json:"applied_revision"`
	Tunnels         []TunnelStatus `json:"tunnels,omitempty"`
	Certs           []CertStatus   `json:"certs,omitempty"`
	Exits           []ExitStatus   `json:"exits,omitempty"` // smart DNS exits hosted on this node
	// SmartDNSServices are the smart DNS services this node relays and the
	// exit each uses now (additive).
	SmartDNSServices []ServiceStatus `json:"smartdns_services,omitempty"`
	Mesh             []MeshPeer      `json:"mesh,omitempty"`
	DiskFreeBytes    int64           `json:"disk_free_bytes,omitempty"`
	Uptime           int64           `json:"uptime_seconds,omitempty"`
}

type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Warn    bool   `json:"warn,omitempty"`
	Message string `json:"message,omitempty"`
}

type TunnelStatus struct {
	Site          string    `json:"site"` // tunnel key = site name
	Up            bool      `json:"up"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	Endpoint      string    `json:"endpoint,omitempty"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	Transport     string    `json:"transport,omitempty"` // connector: "udp" | "websocket"
	// EdgePublicKey is this node's WireGuard public key for the tunnel
	// (multi-PoP: other nodes list it as a sibling).
	EdgePublicKey string `json:"edge_public_key,omitempty"`
	// ConnectorPublicKey is the connector's key for connector sites: the
	// one that enrolled on this node, else the configured public_key.
	ConnectorPublicKey string `json:"connector_public_key,omitempty"`
	// Connector build and installation as reported by the connector
	// (connector sites, additive): version, install method (pkg/release
	// Install*), platform, and the state of its last update notice.
	ConnectorVersion string                `json:"connector_version,omitempty"`
	ConnectorInstall string                `json:"connector_install,omitempty"`
	ConnectorOS      string                `json:"connector_os,omitempty"`
	ConnectorArch    string                `json:"connector_arch,omitempty"`
	ConnectorUpdate  *ConnectorUpdateState `json:"connector_update,omitempty"`
	// ConnectorEdges is the connector's last report of every edge of the
	// site (connector sites, additive), so RTTs to all nodes can be read
	// from any one of them.
	ConnectorEdges []ConnectorEdge `json:"connector_edges,omitempty"`
	// ConnectorSmartDNS is the connector's last Smart DNS report (connector
	// sites, additive).
	ConnectorSmartDNS *ConnectorSmartDNS `json:"connector_smartdns,omitempty"`
}

// ConnectorEdge is one edge as a connector reported it. RTTMillis is the
// connector's smoothed round trip through the tunnel (0 = not measured).
type ConnectorEdge struct {
	Node          string  `json:"node,omitempty"`
	EdgePublicKey string  `json:"edge_public_key,omitempty"`
	RTTMillis     float64 `json:"rtt_ms,omitempty"`
	Up            bool    `json:"up"`
	Transport     string  `json:"transport,omitempty"`
}

// Certificate states.
const (
	CertPending = "pending"
	CertIssuing = "issuing"
	CertValid   = "valid"
	CertFailed  = "failed"
)

type CertStatus struct {
	Host     string    `json:"host"`
	State    string    `json:"state"`
	Issuer   string    `json:"issuer,omitempty"`
	NotAfter time.Time `json:"not_after,omitempty"`
	Error    string    `json:"error,omitempty"`
}

type ExitStatus struct {
	Name    string `json:"name"`
	Country string `json:"country"` // what the exit's egress geolocates to, if checked
	Up      bool   `json:"up"`
	Egress  string `json:"egress,omitempty"` // egress IP
	VPN     bool   `json:"vpn,omitempty"`    // egress via a VPN interface
	// Endpoint is the VPN server address the tunnel uses now (IP:port,
	// after resolving the config's host name), additive.
	Endpoint string `json:"endpoint,omitempty"`
	Message  string `json:"message,omitempty"`
}

// ServiceStatus is a smart DNS service's exit choice on one home node.
type ServiceStatus struct {
	Name  string   `json:"name"`
	Exits []string `json:"exits"` // in order of preference
	// Active is the exit new connections use, empty while every exit is
	// down; Failover is true when it is not Exits[0].
	Active   string    `json:"active,omitempty"`
	Failover bool      `json:"failover,omitempty"`
	Since    time.Time `json:"since,omitempty"` // when Active was chosen
	Message  string    `json:"message,omitempty"`
}

type MeshPeer struct {
	NodeID        string    `json:"node_id"`
	Up            bool      `json:"up"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	RTTMillis     float64   `json:"rtt_ms,omitempty"`
}

// Usage carries deltas since the previous Usage message. Seq increases by 1
// per message; the panel ignores seqs it has already ingested, so the node
// may resend after reconnecting.
type Usage struct {
	Seq   int64          `json:"seq"`
	From  time.Time      `json:"from"`
	To    time.Time      `json:"to"`
	Apps  []AppUsage     `json:"apps,omitempty"`
	Sites []SiteUsage    `json:"sites,omitempty"`
	Smart []ServiceUsage `json:"smartdns,omitempty"`
}

type AppUsage struct {
	App       string `json:"app"` // config app key = panel app name
	Requests  int64  `json:"requests"`
	BytesIn   int64  `json:"bytes_in"`
	BytesOut  int64  `json:"bytes_out"`
	Status2xx int64  `json:"status_2xx"`
	Status3xx int64  `json:"status_3xx"`
	Status4xx int64  `json:"status_4xx"`
	Status5xx int64  `json:"status_5xx"`
}

type SiteUsage struct {
	Site    string `json:"site"`
	RxBytes int64  `json:"rx_bytes"` // from the site into the edge
	TxBytes int64  `json:"tx_bytes"` // from the edge to the site
}

type ServiceUsage struct {
	// Site is the connector site whose relay carried the bytes.
	Site    string `json:"site,omitempty"`
	Service string `json:"service"`
	Bytes   int64  `json:"bytes"`
	Conns   int64  `json:"connections"`
}

type LogBatch struct {
	SubscriptionID string     `json:"subscription_id"`
	Entries        []LogEntry `json:"entries"`
	Dropped        int        `json:"dropped,omitempty"` // entries dropped by rate limiting
}

// Decision values for LogEntry.Decision.
const (
	DecisionAllow     = "allow"
	DecisionWAFBlock  = "waf_block"
	DecisionAccess    = "access_denied"
	DecisionChallenge = "challenge"
	DecisionRateLimit = "rate_limited"
)

type LogEntry struct {
	Time       time.Time `json:"time"`
	App        string    `json:"app,omitempty"`
	Host       string    `json:"host"`
	Method     string    `json:"method"`
	Path       string    `json:"path"` // query string stripped of values
	Status     int       `json:"status"`
	DurationMS float64   `json:"duration_ms"`
	BytesOut   int64     `json:"bytes_out"`
	ClientIP   string    `json:"client_ip"`
	Country    string    `json:"country,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Decision   string    `json:"decision,omitempty"`
	TLS        string    `json:"tls,omitempty"`
}

// Diagnostic kinds.
const (
	DiagOrigin = "origin" // TCP+HTTP to an app origin through its tunnel
	DiagHTTP   = "http"   // full request to https://host via the node's public address
	DiagTunnel = "tunnel" // tunnel handshake / reachability summary
	// DiagL4 checks an l4 service's target through its tunnel (TCP
	// connect, or a UDP probe); App names the service.
	DiagL4 = "l4"
)

// Diagnostic codes: stable identifiers the UI maps to hints.
const (
	DiagCodeOK          = "ok"
	DiagCodeTunnelDown  = "tunnel_down"  // no recent handshake from the site
	DiagCodeNoReply     = "no_reply"     // SYN sent into the tunnel, nothing back (router firewall)
	DiagCodeRefused     = "refused"      // RST from origin: nothing listening on that port
	DiagCodeTimeout     = "timeout"      // connected but no HTTP response
	DiagCodeHTTPError   = "http_error"   // origin answered 5xx
	DiagCodeTLSError    = "tls_error"    // TLS handshake to origin or edge failed
	DiagCodeDNSMissing  = "dns_missing"  // hostname doesn't resolve
	DiagCodeDNSWrong    = "dns_wrong"    // resolves elsewhere
	DiagCodeDNSProxied  = "dns_proxied"  // resolves to Cloudflare's proxy
	DiagCodeCertPending = "cert_pending" // certificate not issued yet
	DiagCodeCertFailed  = "cert_failed"
)

type DiagRequest struct {
	RequestID string        `json:"request_id"`
	Kind      string        `json:"kind"`
	App       string        `json:"app,omitempty"`
	Host      string        `json:"host,omitempty"`
	Timeout   time.Duration `json:"timeout,omitempty"`
}

type DiagResult struct {
	RequestID string     `json:"request_id"`
	Kind      string     `json:"kind"`
	OK        bool       `json:"ok"`
	Code      string     `json:"code"`
	Steps     []DiagStep `json:"steps,omitempty"`
	Message   string     `json:"message,omitempty"`
}

type DiagStep struct {
	Name       string  `json:"name"` // e.g. "edge", "tunnel", "site", "origin"
	OK         bool    `json:"ok"`
	DurationMS float64 `json:"duration_ms"`
	Detail     string  `json:"detail,omitempty"`
}

type DiscoverRequest struct {
	Site string `json:"site"`
}

type Discovery struct {
	Site     string              `json:"site"`
	Services []DiscoveredService `json:"services"`
}

type DiscoveredService struct {
	Address string `json:"address"` // IPv4
	Port    int    `json:"port"`
	Scheme  string `json:"scheme"`           // http | https
	Title   string `json:"title,omitempty"`  // HTML <title>
	Server  string `json:"server,omitempty"` // Server header
}

type Event struct {
	Kind     string            `json:"kind"`
	Severity string            `json:"severity,omitempty"`
	Message  string            `json:"message"`
	Fields   map[string]string `json:"fields,omitempty"`
	Time     time.Time         `json:"time"`
}

// --- Panel → node ---

// Snapshot is a node's complete configuration at a revision.
type Snapshot struct {
	Revision   int64  `json:"revision"`
	ConfigYAML string `json:"config_yaml"`
	// Secrets maps secret name → age ciphertext (armored) encrypted to this
	// node's recipient. The node merges them into its secrets store; names
	// absent from the map are left alone (removal is explicit below).
	Secrets       map[string]string `json:"secrets,omitempty"`
	RemoveSecrets []string          `json:"remove_secrets,omitempty"`
	// Force applies even if Revision <= the applied revision (resync).
	Force bool `json:"force,omitempty"`
	// Signature is base64 ed25519 over SnapshotSigningPayloadV2 (nodes
	// advertising CapabilitySnapshotV2), else the legacy
	// SnapshotSigningPayload.
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
	// v2 binding (signing.go): the node and org the snapshot is for, and
	// its validity window. Empty in legacy v1 snapshots.
	NodeID    string    `json:"node_id,omitempty"`
	OrgID     string    `json:"org_id,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitzero"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

type LiveSubscribe struct {
	SubscriptionID string    `json:"subscription_id"`
	Hosts          []string  `json:"hosts,omitempty"` // empty = all hosts on the node for this org
	Apps           []string  `json:"apps,omitempty"`
	Until          time.Time `json:"until"` // node stops streaming after this
	MaxPerSecond   int       `json:"max_per_second,omitempty"`
}

type LiveUnsubscribe struct {
	SubscriptionID string `json:"subscription_id"`
}

type Detach struct {
	Reason string `json:"reason,omitempty"`
}

// ConnectorTokenRequest asks the node for a one-time connector enrolment
// token for a site (tunnel). The node creates it with its existing
// connector store and answers with a join string.
type ConnectorTokenRequest struct {
	Site string `json:"site"`
}

type ConnectorToken struct {
	Site string `json:"site"`
	// JoinString is a single opaque argument for `ingressd-connector enroll`:
	// base64url JSON {"u": edge URL, "t": token, "ca": PEM of the CA the edge
	// certificate chains to when it has no public certificate}.
	JoinString string    `json:"join_string,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// SiteConfigRequest asks the node for a router site's WireGuard config
// (the site private key lives only on the node).
type SiteConfigRequest struct {
	Site   string `json:"site"`
	Format string `json:"format,omitempty"` // "wg-quick" (default) or "wg"
}

type SiteConfig struct {
	Site   string `json:"site"`
	Config string `json:"config,omitempty"`
	Error  string `json:"error,omitempty"`
}

type SmartDNSRecentRequest struct {
	// Site is the connector site whose lookups are wanted.
	Site  string `json:"site,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

type SmartDNSRecent struct {
	Lookups []RecentLookup `json:"lookups"`
}

type RecentLookup struct {
	Time    time.Time `json:"time"`
	Site    string    `json:"site,omitempty"` // tunnel the query arrived on
	Name    string    `json:"name"`
	Type    string    `json:"type"` // A, AAAA, HTTPS, …
	Routed  bool      `json:"routed"`
	Service string    `json:"service,omitempty"`
}

// --- Snapshot signing ---

// SnapshotSigningPayload is the legacy (v1) byte string the org key signs:
// a domain separator, the revision, the force flag, the SHA-256 of the
// config, and every secret and removal in sorted order. It binds neither
// node, org nor time, so a captured snapshot can be replayed: the panel
// signs it only for agents that do not advertise CapabilitySnapshotV2, and
// current agents accept only VerifyV2. The node still uses it as a content
// hash (snapshotSHA).
func SnapshotSigningPayload(s Snapshot) []byte {
	h := sha256.New()
	// The signing domain separator is shared by every panel and node release;
	// changing it needs a new protocol version, so it keeps the old name.
	h.Write([]byte("homeedge-snapshot-v1\x00")) // legacy homeedge name, remove after 2027-01 (signature label)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(s.Revision))
	h.Write(buf[:])
	if s.Force {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	cfg := sha256.Sum256([]byte(s.ConfigYAML))
	h.Write(cfg[:])
	names := make([]string, 0, len(s.Secrets))
	for n := range s.Secrets {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		h.Write([]byte("S" + n + "\x00" + s.Secrets[n] + "\x00"))
	}
	removed := slices.Clone(s.RemoveSecrets)
	slices.Sort(removed)
	for _, n := range removed {
		h.Write([]byte("R" + n + "\x00"))
	}
	return h.Sum(nil)
}

// Sign sets s.Signature using the org private key (legacy v1 format, for
// agents without CapabilitySnapshotV2).
func Sign(s *Snapshot, key ed25519.PrivateKey) {
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, SnapshotSigningPayload(*s)))
}

// Verify checks s.Signature against the pinned org public key (base64).
func Verify(s Snapshot, orgPublicKey string) error {
	pub, err := base64.StdEncoding.DecodeString(orgPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid org signing key")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return errors.New("invalid snapshot signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), SnapshotSigningPayload(s), sig) {
		return errors.New("snapshot signature does not match the org key")
	}
	return nil
}

// UsageAck (panel → node) confirms that every usage message with
// Seq <= this Seq has been ingested, so the node may drop them.
type UsageAck struct {
	Seq int64 `json:"seq"`
}

// SPDX-License-Identifier: Apache-2.0

package nodeproto

import "time"

// Node metrics (S7, panel docs MANAGED.md §9.3). The agent samples every
// 10 s and sends a Metrics message with 1-minute aggregates every 60 s. It
// keeps the last 60 messages in memory and, after reconnecting, resends the
// ones it could not send (and, once the panel acknowledges with
// TypeMetricsAck, every unacknowledged one); the panel dedups by Seq.
//
// While a MetricsSubscribe is active the node also sends one MetricsLive
// sample every 2 s until MetricsUnsubscribe, Until, or 10 minutes.
const (
	TypeMetrics     = "metrics"      // node → panel, Metrics
	TypeMetricsLive = "metrics_live" // node → panel, MetricsLive

	TypeMetricsSubscribe   = "metrics_subscribe"   // panel → node, MetricsSubscribe
	TypeMetricsUnsubscribe = "metrics_unsubscribe" // panel → node, MetricsUnsubscribe
	TypeMetricsAck         = "metrics_ack"         // panel → node, MetricsAck
)

// CapabilityMetrics is listed in Hello.Capabilities by nodes that send
// metrics and accept metrics_subscribe.
const CapabilityMetrics = "metrics"

// Metrics is one aggregation window. Groups the node cannot measure (non-
// Linux builds, missing /proc files) are omitted.
type Metrics struct {
	Seq     int64     `json:"seq"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Samples int       `json:"samples"` // samples aggregated (avg/max are over these)

	CPU     *CPUMetrics     `json:"cpu,omitempty"`
	Memory  *MemoryMetrics  `json:"memory,omitempty"`
	Network *NetworkMetrics `json:"network,omitempty"`
	Disk    *DiskMetrics    `json:"disk,omitempty"`
	Edge    *EdgeMetrics    `json:"edge,omitempty"`
	Tunnels *TunnelMetrics  `json:"tunnels,omitempty"`
	// TopApps are the 10 apps with the most bytes (in + out) in the window;
	// hosts that belong to no app are not listed.
	TopApps []AppBytes `json:"top_apps,omitempty"`
}

// Gauge is the average and maximum of a value over a window's samples.
type Gauge struct {
	Avg float64 `json:"avg"`
	Max float64 `json:"max"`
}

type CPUMetrics struct {
	Cores  int     `json:"cores"`
	Usage  Gauge   `json:"usage_pct"` // everything but idle and iowait
	Steal  Gauge   `json:"steal_pct"`
	IOWait Gauge   `json:"iowait_pct"`
	Load1  float64 `json:"load1"` // at the end of the window
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

type MemoryMetrics struct {
	TotalBytes int64 `json:"total_bytes"`
	Used       Gauge `json:"used_bytes"` // total - available
	Available  Gauge `json:"available_bytes"`
	SwapUsed   Gauge `json:"swap_used_bytes"`
	// RSS of the edge proxy (ingressd-edge) and the agent; omitted when
	// the edge runs outside the agent's process namespace.
	EdgeRSS  *Gauge `json:"edge_rss_bytes,omitempty"`
	AgentRSS *Gauge `json:"agent_rss_bytes,omitempty"`
}

// Interface roles.
const (
	IfacePublic  = "public"  // the default-route interface
	IfaceMesh    = "mesh"    // ix-mesh
	IfaceTunnels = "tunnels" // sum over the ix-* tunnel interfaces except ix-mesh (Name "ix-*")
)

type InterfaceMetrics struct {
	Name      string `json:"name"`
	Role      string `json:"role,omitempty"`
	RxBits    Gauge  `json:"rx_bps"`
	TxBits    Gauge  `json:"tx_bps"`
	RxPackets Gauge  `json:"rx_pps"`
	TxPackets Gauge  `json:"tx_pps"`
	Drops     int64  `json:"drops"`  // rx + tx, in the window
	Errors    int64  `json:"errors"` // rx + tx, in the window
}

type NetworkMetrics struct {
	Interfaces     []InterfaceMetrics `json:"interfaces,omitempty"`
	TCPEstablished Gauge              `json:"tcp_established"`
	// Conntrack is omitted when nf_conntrack is not loaded.
	ConntrackCount *Gauge `json:"conntrack_count,omitempty"`
	ConntrackMax   int64  `json:"conntrack_max,omitempty"`
}

type DiskMetrics struct {
	FreeBytes  int64 `json:"free_bytes"` // state disk, at the end of the window
	TotalBytes int64 `json:"total_bytes"`
	// Device and I/O rates of the block device holding the state dir;
	// omitted when it cannot be mapped (overlay, device mapper).
	Device     string `json:"device,omitempty"`
	ReadBytes  *Gauge `json:"read_bps,omitempty"`  // bytes/s
	WriteBytes *Gauge `json:"write_bps,omitempty"` // bytes/s
}

// EdgeMetrics come from the edge access log. Latency is the full request
// duration the edge logs (origin time plus edge overhead).
type EdgeMetrics struct {
	Requests       int64 `json:"requests"`
	RequestsPerSec Gauge `json:"requests_per_sec"`
	// ActiveConns counts established TCP connections to local ports 80 and 443.
	ActiveConns  Gauge   `json:"active_connections"`
	Status4xx    int64   `json:"status_4xx"`
	Status5xx    int64   `json:"status_5xx"`
	OriginErrors int64   `json:"origin_errors"` // 502, 503 and 504 responses
	LatencyP50MS float64 `json:"latency_p50_ms"`
	LatencyP95MS float64 `json:"latency_p95_ms"`
}

type TunnelMetrics struct {
	Up    int `json:"up"`
	Total int `json:"total"`
	// WebSocket counts connector tunnels on the WebSocket fallback.
	WebSocket int `json:"websocket"`
	// OldestHandshakeSeconds is the age of the oldest handshake among the
	// tunnels that are up.
	OldestHandshakeSeconds int64 `json:"oldest_handshake_seconds,omitempty"`
}

type AppBytes struct {
	App      string `json:"app"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	Requests int64  `json:"requests"`
}

// MetricsLive is one live sample (Samples 1, Seq 0).
type MetricsLive struct {
	SubscriptionID string `json:"subscription_id"`
	Metrics
}

type MetricsSubscribe struct {
	SubscriptionID string    `json:"subscription_id"`
	Until          time.Time `json:"until,omitzero"` // capped at 10 minutes from now
}

type MetricsUnsubscribe struct {
	SubscriptionID string `json:"subscription_id"`
}

// MetricsAck confirms every Metrics message with Seq <= this Seq.
type MetricsAck struct {
	Seq int64 `json:"seq"`
}

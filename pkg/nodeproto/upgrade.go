// SPDX-License-Identifier: Apache-2.0

package nodeproto

import "time"

// Remote updates (additive). The panel learns of releases from their
// signed manifest (release.json + release.json.minisig, see pkg/release)
// and passes both on unchanged: nodes and connectors verify the signature
// themselves with the key built into them, so the panel cannot make them
// install anything the release key did not sign.
const (
	// TypeUpgradeRequest (panel → node): update this node's binaries.
	// The node answers with upgrade_progress events and one
	// upgrade_result (possibly from the restarted process, after it
	// reconnects); every message carries the request's ID.
	TypeUpgradeRequest = "upgrade_request"
	// TypeConnectorUpdate (panel → node): tell a connector site's
	// connector that a release is available (and whether to install it).
	TypeConnectorUpdate = "connector_update"
	// Node → panel.
	TypeUpgradeProgress = "upgrade_progress"
	TypeUpgradeResult   = "upgrade_result"
)

// CapabilityUpgrade is listed in Hello.Capabilities by nodes that accept
// upgrade_request and connector_update.
const CapabilityUpgrade = "upgrade"

// UpgradeRequest asks the node to install a release.
type UpgradeRequest struct {
	ID      string `json:"id"`      // update id, echoed in progress and result
	Version string `json:"version"` // must equal the manifest's version
	// Manifest is release.json verbatim and Signature its minisign
	// signature (release.json.minisig).
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
	// Latest is the newest release the panel knows (same format), so the
	// node learns the current min_supported even when installing an older
	// release. Optional.
	LatestManifest  string `json:"latest_manifest,omitempty"`
	LatestSignature string `json:"latest_signature,omitempty"`
	// Sources are download base URLs tried in order (asset URL =
	// <source>/<asset>): the panel's /downloads mirror, then GitHub.
	Sources []string `json:"sources"`
	// Force allows a downgrade (never below min_supported).
	Force bool `json:"force,omitempty"`
}

// Upgrade stages reported in UpgradeProgress.
const (
	UpgradeStageAccepted    = "accepted"
	UpgradeStageDownloading = "downloading"
	UpgradeStageVerified    = "verified"
	UpgradeStageRestarting  = "restarting"
	UpgradeStageHealthCheck = "health_check"
)

type UpgradeProgress struct {
	ID      string    `json:"id"`
	Stage   string    `json:"stage"`
	Message string    `json:"message,omitempty"`
	Version string    `json:"version,omitempty"` // version of the reporting process
	Time    time.Time `json:"time"`
}

type UpgradeResult struct {
	ID         string    `json:"id"`
	OK         bool      `json:"ok"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	RolledBack bool      `json:"rolled_back"`
	Reason     string    `json:"reason,omitempty"`
	Time       time.Time `json:"time"`
}

// ConnectorUpdate tells the node to offer a release to a site's connector.
// Connectors installed as a system service (systemd, launchd, Windows
// service) install it when Apply is set; Docker and manual installs only
// show the notice.
type ConnectorUpdate struct {
	Site      string   `json:"site"`
	ID        string   `json:"id"`
	Version   string   `json:"version"`
	Manifest  string   `json:"manifest"`
	Signature string   `json:"signature"`
	Sources   []string `json:"sources"`
	Apply     bool     `json:"apply"`
}

// ConnectorUpdateState is a connector's view of its last update notice
// (TunnelStatus.ConnectorUpdate).
type ConnectorUpdateState struct {
	ID         string    `json:"id,omitempty"`
	Version    string    `json:"version,omitempty"`
	State      string    `json:"state"` // notified|downloading|installing|updated|failed|rolled_back|manual|current
	Message    string    `json:"message,omitempty"`
	From       string    `json:"from,omitempty"`
	To         string    `json:"to,omitempty"`
	RolledBack bool      `json:"rolled_back,omitempty"`
	Time       time.Time `json:"time"`
}

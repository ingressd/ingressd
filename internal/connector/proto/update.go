// SPDX-License-Identifier: Apache-2.0

package proto

import "time"

// Connector self-update (additive):
//
//  1. A connector that understands updates adds "upd=<last notice id it
//     handled>" to every poll (UpdateParam; empty before the first).
//  2. When the panel offers a release (nodeproto.ConnectorUpdate) the edge
//     answers the next poll at once with the TunnelConfig and Update set,
//     like a discovery request (not part of Revision, no link restart).
//  3. The connector verifies the manifest signature with its own key and,
//     when it runs as a system service and Apply is set, downloads its
//     binary (through the edge: ReleasePathPrefix + asset, which the edge
//     fetches from the notice's sources and checks against the manifest;
//     else straight from the sources), swaps it, restarts and rolls back
//     if the new version does not come up. Its health reports carry the
//     install method and the update state.
const (
	UpdateParam       = "upd"
	ReleasePathPrefix = "/.ingressd/connector/release/"
)

// UpdateNotice offers a release to the connector.
type UpdateNotice struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	// Manifest is release.json verbatim, Signature its minisign signature.
	Manifest  string   `json:"manifest"`
	Signature string   `json:"signature"`
	Sources   []string `json:"sources,omitempty"`
	// Apply asks a service install to install it now.
	Apply bool `json:"apply"`
}

// UpdateState is the connector's progress on the last notice.
type UpdateState struct {
	ID         string    `json:"id,omitempty"`
	Version    string    `json:"version,omitempty"`
	State      string    `json:"state"`
	Message    string    `json:"message,omitempty"`
	From       string    `json:"from,omitempty"`
	To         string    `json:"to,omitempty"`
	RolledBack bool      `json:"rolled_back,omitempty"`
	Time       time.Time `json:"time"`
}

// Update states.
const (
	UpdateNotified    = "notified"    // known, not installing (Apply unset)
	UpdateManual      = "manual"      // install method cannot self-update
	UpdateDownloading = "downloading" // staging the new binary
	UpdateInstalling  = "installing"  // helper swapped/restarting
	UpdateUpdated     = "updated"     // running the new version
	UpdateFailed      = "failed"      // could not install (still on the old version)
	UpdateRolledBack  = "rolled_back" // installed, unhealthy, previous version restored
	UpdateCurrent     = "current"     // already at (or past) that version
)

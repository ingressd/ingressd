// SPDX-License-Identifier: Apache-2.0

// Package deploy embeds the one-line installer scripts so the panel can
// serve them (GET /install/connector.sh) from the node repo's copy.
package deploy

import _ "embed"

// ConnectorInstaller is deploy/install-connector.sh, served as
// <panel>/install/connector.sh.
//
//go:embed install-connector.sh
var ConnectorInstaller string

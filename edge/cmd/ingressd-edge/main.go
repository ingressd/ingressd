// SPDX-License-Identifier: Apache-2.0

// Command ingressd-edge is Caddy built with the plugins and custom modules
// ingressd needs. It is the equivalent of an xcaddy build, but versions are
// pinned by edge/go.mod so builds are reproducible.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Third-party plugins (see docs/DESIGN.md §2 and docs/spikes/01-caddy-plugin-build.md).
	_ "github.com/caddy-dns/cloudflare"
	_ "github.com/caddyserver/cache-handler"
	_ "github.com/corazawaf/coraza-caddy/v2"
	_ "github.com/darkweak/storages/badger/caddy" // on-disk store for cache-handler
	_ "github.com/hslatman/caddy-crowdsec-bouncer/http"
	_ "github.com/hslatman/caddy-crowdsec-bouncer/layer4"
	_ "github.com/mholt/caddy-l4"
	_ "github.com/mholt/caddy-ratelimit"
	_ "github.com/porech/caddy-maxmind-geolocation"

	// ingressd modules.
	_ "github.com/ingressd/ingressd/edge/modules/edgeauth"
	_ "github.com/ingressd/ingressd/edge/modules/edgechallenge"
	_ "github.com/ingressd/ingressd/edge/modules/edgefallback"
	_ "github.com/ingressd/ingressd/edge/modules/edgehello"
	_ "github.com/ingressd/ingressd/edge/modules/edgelb"
	_ "github.com/ingressd/ingressd/edge/modules/edgestate"
	_ "github.com/ingressd/ingressd/edge/modules/edgestorage"
)

func main() {
	caddycmd.Main()
}

#!/usr/bin/env bash
# Fails if the edge binary is missing any Caddy module the plan depends on.
# Usage: scripts/check-edge-modules.sh [path/to/ingressd-edge]
set -euo pipefail

bin=${1:-bin/ingressd-edge}
mods=$("$bin" list-modules)

required=(
	http.handlers.ingressd_hello      # our placeholder module
	edge_state                        # ingressd runtime state (Phase 6)
	admin.api.edge_state              # its admin API route
	http.reverse_proxy.selection_policies.edge_tiered # ingressd load balancing (Phase 6)
	http.handlers.edge_challenge      # edge/modules/edgechallenge (bot challenge)
	http.handlers.edge_auth           # Access: cookie check, login redirect, identity headers
	http.handlers.waf                 # coraza-caddy
	http.handlers.rate_limit          # caddy-ratelimit
	layer4                            # caddy-l4
	http.handlers.cache               # cache-handler (Souin)
	storages.cache.badger             # cache-handler on-disk store
	admin.api.souin                   # cache purge API (admin socket only)
	http.handlers.edge_fallback       # Always Online snapshots
	dns.providers.cloudflare          # caddy-dns/cloudflare
	http.matchers.maxmind_geolocation # caddy-maxmind-geolocation
	crowdsec                          # caddy-crowdsec-bouncer app
	http.handlers.crowdsec            # caddy-crowdsec-bouncer handler
)

missing=0
for want in "${required[@]}"; do
	if grep -qx "$want" <<<"$mods"; then
		echo "ok      $want"
	else
		echo "MISSING $want"
		missing=1
	fi
done
exit "$missing"

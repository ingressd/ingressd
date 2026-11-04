#!/usr/bin/env bash
# e2e remote-updates: a fake release (binaries built here with
# a higher VERSION, signed with a throwaway minisign key, served from the
# fake panel's /downloads mirror) is installed on a managed node by an
# upgrade_request and on its connector through the node (connector_update,
# downloaded through the node's release relay). Refusals (unsigned,
# tampered, downgrade) and a deliberately broken release that rolls back
# are checked for both. Nothing runs under systemd here: the node restarts
# itself in place (restart mode exec) and the connector is told it is a
# service install (INGRESSD_INSTALL=systemd, INGRESSD_UPGRADE_RESTART=exec).
#
#   fake panel 198.51.100.2:8443 (client ns) ── edge (node) ── site (connector) ── lan
#
# Needs the Go toolchain (it builds the versions it installs).
set -euo pipefail
P=he-up
source "$(dirname "$0")/lib.sh"
# The fake panel speaks plain http: test-only escape hatch (nodeagent.InsecurePanelEnv).
export INGRESSD_INSECURE_PANEL=1
# scripts/e2e.sh re-runs suites through sudo, whose PATH may lack Go.
if ! command -v go >/dev/null; then
	for d in ${GOROOT:+"$GOROOT/bin"} /usr/local/go/bin ${SUDO_USER:+"$(getent passwd "$SUDO_USER" | cut -d: -f6)/.local/go/bin"} ${SUDO_USER:+"$(getent passwd "$SUDO_USER" | cut -d: -f6)/go/bin"}; do
		[[ -x $d/go ]] && { PATH=$d:$PATH; break; }
	done
fi
export CGO_ENABLED=0
command -v go >/dev/null || { echo "SKIP remote-updates-e2e: the go toolchain is needed to build the test releases"; exit 0; }
# Update helpers ignore SIGTERM (a service restart must not stop them half
# way); lib.sh's cleanup SIGKILLs whatever outlives the TERM, helpers and
# the processes they restarted included (all live in this run's namespaces).

PANEL=198.51.100.2:8443
OLD=v0.9.0 NEW=v0.9.1 BROKEN=v0.9.2
ARCH=$(go env GOARCH)
NBIN=$TMP/nbin # the node's install dir (never the repo's bin/: updates rewrite it)
CBIN=$TMP/cbin # the connector's install dir
MIRROR=$TMP/mirror

pj() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
pstate() { in_client curl -s --max-time 5 "http://$PANEL/test/state"; }
preq() { in_client curl -s --max-time 70 -X POST "http://$PANEL/test/request" -d "$1"; }
psend() { in_client curl -s --max-time 10 -X POST "http://$PANEL/test/send" -d "$1"; }
psnap() {
	local body
	body=$(python3 -c 'import json,sys; print(json.dumps({"config_yaml": open(sys.argv[1]).read()}))' "$1")
	in_client curl -s --max-time 120 -X POST "http://$PANEL/test/snapshot" -d "$body"
}
# wait_state <description> <python condition on d> [seconds]
wait_state() {
	local desc=$1 cond=$2 secs=${3:-30}
	for _ in $(seq $((secs * 2))); do
		if [[ $(pstate | pj "bool($cond)" 2>/dev/null) == True ]]; then pass "$desc"; return; fi
		sleep 0.5
	done
	fail "$desc: condition '$cond' not met; results: $(pstate | pj 'd["upgrade_results"]' 2>/dev/null) progress: $(pstate | pj '[p["stage"] for p in d["upgrade_progress"]]' 2>/dev/null)"
}
result_of() { pstate | pj "next((r for r in d['upgrade_results'] if r['id']=='$1'), None)"; }
# CT is a python expression for the connector tunnel's status.
CT='next((t for t in (d["status"] or {}).get("tunnels") or [] if t["site"]=="conn"), {})'
conn_tunnel() { pstate | pj "$CT"; }

# --- Test releases ---------------------------------------------------------
build_version() { # <out-dir> <version>
	local ld="-X github.com/ingressd/ingressd/internal/version.Version=$2 -X github.com/ingressd/ingressd/internal/version.Commit=e2e"
	mkdir -p "$1"
	(cd "$ROOT" && go build -trimpath -ldflags "$ld" -o "$1/ingressd" ./cmd/ingressd &&
		go build -trimpath -ldflags "$ld" -o "$1/ingressd-connector" ./cmd/ingressd-connector) || { echo "build $2 failed" >&2; exit 1; }
}
broken() { # a binary that passes the version check, then exits at once
	printf '#!/bin/sh\ncase "$*" in *version*) echo "%s %s (e2e broken)"; exit 0;; esac\necho "deliberately broken build" >&2\nexit 1\n' "$1" "$BROKEN"
}
build_version "$TMP/build-old" "$OLD"
build_version "$TMP/build-new" "$NEW"
(cd "$ROOT" && go build -o "$TMP/releasetool" ./scripts/releasetool) || exit 1
"$TMP/releasetool" keygen --pub "$TMP/release.pub" --key "$TMP/release.key"
"$TMP/releasetool" keygen --pub "$TMP/other.pub" --key "$TMP/other.key"

mkdir -p "$NBIN" "$CBIN" "$MIRROR/$NEW" "$MIRROR/$BROKEN"
cp "$TMP/build-old/ingressd" "$NBIN/ingressd"
cp "$BIN/ingressd-edge" "$NBIN/ingressd-edge"
cp "$TMP/build-old/ingressd-connector" "$CBIN/ingressd-connector"
cp "$TMP/build-new/ingressd" "$MIRROR/$NEW/ingressd_linux_$ARCH"
cp "$TMP/build-new/ingressd-connector" "$MIRROR/$NEW/ingressd-connector_linux_$ARCH"
cp "$BIN/ingressd-edge" "$MIRROR/$NEW/ingressd-edge_linux_$ARCH"
broken ingressd >"$MIRROR/$BROKEN/ingressd_linux_$ARCH"
broken ingressd-connector >"$MIRROR/$BROKEN/ingressd-connector_linux_$ARCH"
cp "$BIN/ingressd-edge" "$MIRROR/$BROKEN/ingressd-edge_linux_$ARCH"
chmod 755 "$MIRROR"/*/*
"$TMP/releasetool" manifest --dir "$MIRROR/$NEW" --version "$NEW" --min-supported v0.8.0 --notes-url https://example.test/notes --key "$TMP/release.key" >/dev/null
"$TMP/releasetool" manifest --dir "$MIRROR/$BROKEN" --version "$BROKEN" --key "$TMP/release.key" >/dev/null
mkdir -p "$MIRROR/$OLD" && cp "$MIRROR/$NEW/ingressd-edge_linux_$ARCH" "$MIRROR/$OLD/" && cp "$TMP/build-old/ingressd" "$MIRROR/$OLD/ingressd_linux_$ARCH"
"$TMP/releasetool" manifest --dir "$MIRROR/$OLD" --version "$OLD" --key "$TMP/release.key" >/dev/null
chmod -R a+rX "$TMP"
[[ $("$TMP/releasetool" verify --pub "$TMP/release.pub" --dir "$MIRROR/$NEW") == *"OK: $NEW"* ]] && pass "test release $NEW is signed" || fail "test release signature"

# upgrade_request / connector_update bodies from a release directory.
req_json() { # <type> <id> <version> [extra python dict]
	python3 - "$MIRROR/$3" "$1" "$2" "$3" "http://$PANEL/downloads/$3" "${4:-{\}}" <<'EOF'
import json, sys
d, typ, rid, ver, src, extra = sys.argv[1:]
m = open(d + "/release.json").read()
sig = open(d + "/release.json.minisig").read()
data = {"id": rid, "version": ver, "manifest": m, "signature": sig, "sources": [src]}
if typ == "connector_update":
    data.update({"site": "conn", "apply": True})
data.update(json.loads(extra))
print(json.dumps({"type": typ, "data": data}))
EOF
}

# --- Node and connector ----------------------------------------------------
build_topology
lan_http 8080 "hello from lan"
start_edge_proxy
in_client "$BIN/fakepanel" --listen "$PANEL" --tokens tok-up --downloads "$MIRROR" >"$TMP/panel.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do in_client curl -s -o /dev/null "http://$PANEL/test/" && break; sleep 0.1; done
expect "test release served by the panel mirror" "\"version\": \"$NEW\"" in_client curl -s "http://$PANEL/downloads/$NEW/release.json"

PUB=$(cat "$TMP/release.pub")
nhe() { in_edge "$NBIN/ingressd" --config-dir "$TMP/conf" --key "$TMP/keys/age.key" --state-dir "$TMP/state" --run-dir "$TMP/run" "$@"; }
expect "node enrols" "Enrolled as nod_" nhe node enroll --panel "http://$PANEL" --token tok-up --public-ip 172.16.1.1
ip netns exec "$EDGE" env INGRESSD_AGENT_STATUS_INTERVAL=1s INGRESSD_UPGRADE_HEALTH_TIMEOUT=60s INGRESSD_RELEASE_PUBLIC_KEY="$PUB" \
	"$NBIN/ingressd" --config-dir "$TMP/conf" --key "$TMP/keys/age.key" \
	--state-dir "$TMP/state" --run-dir "$TMP/run" serve --watch-interval 1s >>"$TMP/serve.log" 2>&1 &
PIDS+=($!)
wait_state "node connects running $OLD and offers updates" "d['connected'] and '$OLD' in d['hello']['agent_version'] and 'upgrade' in d['hello']['capabilities'] and d['hello']['install']=='manual' and d['hello']['arch']=='$ARCH'"

cat >"$TMP/snap.yaml" <<'EOF'
version: 1
edge:
  public_ipv4: 172.16.1.1
  acme: { ca: internal }
tunnels:
  conn:
    site: connector
    listen_port: 51821
    transit: 10.100.2.0/24
    subnets: [192.168.0.0/24]
    fallback_ws: true
apps:
  web:
    hosts: [web.example.test]
    origin: http://192.168.0.17:8080
    tunnel: conn
EOF
expect "snapshot with a connector site applied" '"ok":true' psnap "$TMP/snap.yaml"
JOIN=""
for _ in $(seq 40); do
	JOIN=$(preq '{"type":"connector_token_request","data":{"site":"conn"}}' | pj 'd["data"].get("join_string","")' 2>/dev/null || true)
	[[ -n $JOIN ]] && break
	sleep 0.5
done
[[ -n $JOIN ]] && pass "connector join string from the node" || fail "no join string"
CSTATE=$TMP/conn/connector.json
expect "connector enrols" "Enrolled tunnel" in_site "$CBIN/ingressd-connector" --state "$CSTATE" enroll "$JOIN" --edge-addr 172.16.1.1 --mode tun
ip netns exec "$SITE" env INGRESSD_INSTALL=systemd INGRESSD_UPGRADE_RESTART=exec INGRESSD_UPGRADE_HEALTH_TIMEOUT=90s INGRESSD_RELEASE_PUBLIC_KEY="$PUB" \
	"$CBIN/ingressd-connector" --state "$CSTATE" run --udp-timeout 5s >>"$TMP/conn.log" 2>&1 &
PIDS+=($!)
CURL=(in_client curl -sS --max-time 3 -k --resolve web.example.test:443:198.51.100.1)
expect "app reachable through the connector" "hello from lan" "${CURL[@]}" https://web.example.test/
wait_state "node reports the connector's version and install method" "(lambda t: '$OLD' in t.get('connector_version','') and t.get('connector_install')=='systemd' and t.get('connector_arch')=='$ARCH')($CT)" 60

# --- Refusals ----------------------------------------------------------------
psend "$(req_json upgrade_request upg-unsigned "$NEW" '{"signature":""}')" >/dev/null
wait_state "unsigned manifest refused" "any(r['id']=='upg-unsigned' and not r['ok'] and 'not signed' in r['reason'] for r in d['upgrade_results'])"
TAMPERED=$(req_json upgrade_request upg-tampered "$NEW" | python3 -c 'import json,sys; d=json.load(sys.stdin); d["data"]["manifest"]=d["data"]["manifest"].replace("v0.8.0","v0.1.0"); print(json.dumps(d))')
psend "$TAMPERED" >/dev/null
wait_state "tampered manifest refused" "any(r['id']=='upg-tampered' and not r['ok'] and 'signature' in r['reason'] for r in d['upgrade_results'])"
cp "$MIRROR/$NEW/release.json" "$TMP/other-release.json" && "$TMP/releasetool" sign --key "$TMP/other.key" "$TMP/other-release.json"
OTHERSIG=$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "$TMP/other-release.json.minisig")
psend "$(req_json upgrade_request upg-otherkey "$NEW" "{\"signature\":$OTHERSIG}")" >/dev/null
wait_state "release signed by another key refused" "any(r['id']=='upg-otherkey' and not r['ok'] for r in d['upgrade_results'])"
psend "$(req_json upgrade_request upg-same "$OLD")" >/dev/null
wait_state "same version refused" "any(r['id']=='upg-same' and 'already running' in r['reason'] for r in d['upgrade_results'])"
expect "node still runs $OLD after refusals" "$OLD" "$NBIN/ingressd" version

# --- Node update ---------------------------------------------------------------
CONNECTS=$(pstate | pj 'd["connects"]')
psend "$(req_json upgrade_request upg-node-1 "$NEW")" >/dev/null
wait_state "node reports update progress" "{'accepted','downloading','verified','restarting'} <= {p['stage'] for p in d['upgrade_progress'] if p['id']=='upg-node-1'}" 60
wait_state "updated node reconnects running $NEW" "d['connected'] and d['connects']>$CONNECTS and '$NEW' in d['hello']['agent_version']" 90
wait_state "update result: ok $OLD -> $NEW" "any(r['id']=='upg-node-1' and r['ok'] and r['from']=='$OLD' and r['to']=='$NEW' and not r['rolled_back'] for r in d['upgrade_results'])" 90
wait_state "new version confirmed its health" "any(p['id']=='upg-node-1' and p['stage']=='health_check' and p['version']=='$NEW' for p in d['upgrade_progress'])"
expect "installed binary is $NEW" "$NEW" "$NBIN/ingressd" version
expect "previous binary kept as ingressd.old" "$OLD" "$NBIN/ingressd.old" version
expect "apps keep working after the node update" "hello from lan" "${CURL[@]}" https://web.example.test/
psend "$(req_json upgrade_request upg-downgrade "$OLD")" >/dev/null
wait_state "downgrade refused without force" "any(r['id']=='upg-downgrade' and 'must be forced' in r['reason'] for r in d['upgrade_results'])"

# --- Broken node release: rolled back ---------------------------------------------
CONNECTS=$(pstate | pj 'd["connects"]')
psend "$(req_json upgrade_request upg-node-broken "$BROKEN")" >/dev/null
wait_state "broken release rolled back" "any(r['id']=='upg-node-broken' and not r['ok'] and r['rolled_back'] and r['to']=='$BROKEN' for r in d['upgrade_results'])" 120
wait_state "node is back on $NEW" "d['connected'] and d['connects']>$CONNECTS and '$NEW' in d['hello']['agent_version']" 60
expect "installed binary restored to $NEW" "$NEW" "$NBIN/ingressd" version
expect "helper logged the rollback" "rolling back" cat "$TMP/state/upgrade/helper.log"
expect "apps work after the rollback" "hello from lan" "${CURL[@]}" https://web.example.test/

# --- Connector update through the node -----------------------------------------
psend "$(req_json connector_update upg-conn-1 "$NEW")" >/dev/null
wait_state "connector reports it updated to $NEW" "(lambda t: '$NEW' in t.get('connector_version','') and (t.get('connector_update') or {}).get('state')=='updated' and (t.get('connector_update') or {}).get('id')=='upg-conn-1')($CT)" 180
expect "connector binary is $NEW" "$NEW" "$CBIN/ingressd-connector" version
expect "node relayed the connector binary" "ingressd-connector_linux_$ARCH" ls "$TMP/state/connector-releases/$NEW"
expect "app reachable through the updated connector" "hello from lan" "${CURL[@]}" https://web.example.test/

# --- Broken connector release: rolled back --------------------------------------
psend "$(req_json connector_update upg-conn-broken "$BROKEN")" >/dev/null
wait_state "broken connector release rolled back" "(lambda t: (t.get('connector_update') or {}).get('id')=='upg-conn-broken' and (t.get('connector_update') or {}).get('state')=='rolled_back' and '$NEW' in t.get('connector_version',''))($CT)" 180
expect "connector binary restored to $NEW" "$NEW" "$CBIN/ingressd-connector" version
expect "app reachable after the connector rollback" "hello from lan" "${CURL[@]}" https://web.example.test/

if [[ $FAIL -ne 0 ]]; then
	for f in serve conn panel; do echo "--- $f.log (tail) ---"; tail -60 "$TMP/$f.log" 2>/dev/null || true; done
	for f in "$TMP/state/upgrade/helper.log" "$TMP/conn/upgrade/helper.log"; do echo "--- $f ---"; cat "$f" 2>/dev/null || true; done
	echo "--- state ---"; pstate | pj '{k: d[k] for k in ("upgrade_results","upgrade_progress","connects")}' || true
	conn_tunnel || true
fi
finish

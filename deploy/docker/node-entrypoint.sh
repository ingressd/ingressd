#!/bin/bash
# Entrypoint of Dockerfile.node: the systemd units' equivalent. Starts the
# Caddy edge, then the control plane, and exits (so Docker restarts the
# container) when either stops.
set -euo pipefail

# Volumes still mounted at the pre-rename paths are used in place: each new
# path that is empty becomes a symlink to the old one. The autosaved Caddy
# config names old paths, so it is dropped; serve re-applies within seconds.
migrated=0
for pair in /etc/homeedge:/etc/ingressd /etc/homeedge-keys:/etc/ingressd-keys /var/lib/homeedge:/var/lib/ingressd /var/lib/homeedge-edge:/var/lib/ingressd-edge; do # legacy homeedge name, remove after 2027-01
	old=${pair%%:*} new=${pair#*:}
	if [[ -d $old && ! -L $new && -n $(ls -A "$old" 2>/dev/null) && -z $(ls -A "$new" 2>/dev/null) ]]; then
		if rmdir "$new" 2>/dev/null; then
			ln -s "$old" "$new"
		else # a mount point (Dockerfile VOLUME): link each entry instead
			for f in "$old"/* "$old"/.[!.]*; do [[ -e $f ]] && ln -s "$f" "$new/"; done
		fi
		migrated=1
		echo "ingressd: using $old for $new; rename the volume mount to $new" >&2
	fi
done
[[ $migrated == 0 ]] || rm -f /var/lib/ingressd-edge/caddy/autosave.json

# Ownership as deploy/install.sh: the edge (user ingressd) traverses the state
# dir via its group and owns only its own directories. /run/ingressd is
# root's, sticky and group-writable: the edge creates its admin socket there
# but cannot replace the control plane's sockets.
install -d -m 0750 /etc/ingressd
install -d -m 0700 /etc/ingressd-keys
install -d -m 0750 -o root -g ingressd /var/lib/ingressd
install -d -m 1770 -o root -g ingressd /run/ingressd
for d in /var/lib/ingressd/caddy /var/lib/ingressd/cache /var/lib/ingressd/waf /var/lib/ingressd-edge; do
	install -d -m 0750 "$d"
	# Volumes from images that ran the edge as root: hand them over once.
	[[ $(stat -L -c %U "$d") == ingressd ]] || chown -R -H ingressd:ingressd "$d"
done

if [[ ! -f /etc/ingressd/config.yaml ]]; then
	ingressd init
	echo "ingressd: wrote /etc/ingressd/config.yaml; edit it (or enrol with a panel) and restart the container" >&2
fi

# --resume serves the last applied config at once, before the control plane.
# The edge runs unprivileged, keeping only CAP_NET_BIND_SERVICE (ports 80/443).
setpriv --reuid=ingressd --regid=ingressd --init-groups \
	--inh-caps=-all,+net_bind_service --ambient-caps=-all,+net_bind_service \
	--bounding-set=-all,+net_bind_service --no-new-privs \
	ingressd-edge run --environ --resume --config /etc/ingressd-edge/bootstrap.json &
edge=$!
for _ in $(seq 100); do
	[[ -S /run/ingressd/caddy-admin.sock ]] && break
	kill -0 "$edge" 2>/dev/null || exit 1
	sleep 0.1
done

ingressd serve "$@" &
serve=$!
trap 'kill -TERM "$serve" "$edge" 2>/dev/null || true' TERM INT
wait -n "$edge" "$serve" || true
kill -TERM "$serve" "$edge" 2>/dev/null || true
wait || true
exit 1

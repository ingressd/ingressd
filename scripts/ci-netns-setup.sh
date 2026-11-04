#!/usr/bin/env bash
# Prepares a GitHub-hosted Ubuntu runner for the netns end-to-end tests.
set -euo pipefail

sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools nftables >/dev/null
sudo modprobe wireguard || true

# Newer Ubuntu images confine wg(8) with an AppArmor profile that only lets
# it read keys from the usual WireGuard locations, so the tests' keys in
# mktemp directories fail with "fopen: Permission denied". This runner is
# throwaway: unload any profile that confines wg or wg-quick.
if command -v apparmor_parser >/dev/null && [[ -d /etc/apparmor.d ]]; then
	for p in /etc/apparmor.d/*; do
		[[ -f $p ]] || continue
		if grep -qE '/usr/bin/wg(-quick)?([^-a-z]|$)' "$p"; then
			if sudo apparmor_parser -R "$p" 2>/dev/null; then echo "unloaded AppArmor profile $p"; fi
		fi
	done
fi
echo "kernel $(uname -r); $(wg --version)"

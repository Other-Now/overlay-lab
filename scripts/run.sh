#!/bin/bash
# Run a lab script inside a private network + mount namespace.
#
#   scripts/run.sh scripts/bench.sh
#
# As root (CI): unshare --net --mount.
# As a normal user (no sudo): adds --user --map-root-user, so we are "root"
# only over namespaces we created. Nothing touches the host's network.
#
# OL_DEPS: optional root of unpacked .debs (strongSwan, iperf3), for a box
# where those packages cannot be installed. See README "Running without sudo".
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" != "--inside" ]]; then
    if [[ $(id -u) -eq 0 ]]; then
        exec unshare --net --mount "$0" --inside "$@"
    else
        exec unshare --user --map-root-user --net --mount "$0" --inside "$@"
    fi
fi
shift

# Private /run so `ip netns add` can create /run/netns without touching the host's.
mount -t tmpfs none /run
mkdir -p /run/netns

if [[ -n "${OL_DEPS:-}" ]]; then
    # charon has /usr/lib/ipsec/plugins compiled in. To make it visible we
    # replace /usr/lib, inside this mount namespace only, with a tmpfs of
    # symlinks to the real entries plus one extra entry: ipsec -> the unpacked copy.
    # (Unprivileged overlayfs is refused on this WSL kernel, and a plain
    # --bind of /usr/lib is refused because of locked submounts; --rbind works.)
    mkdir -p /tmp/ol-orig /tmp/ol-farm
    mount --rbind /usr/lib /tmp/ol-orig
    mount -t tmpfs none /tmp/ol-farm
    for e in /tmp/ol-orig/*; do ln -s "$e" "/tmp/ol-farm/$(basename "$e")"; done
    ln -s "$OL_DEPS/usr/lib/ipsec" /tmp/ol-farm/ipsec
    mount --rbind /tmp/ol-farm /usr/lib
    export PATH="$OL_DEPS/usr/sbin:$OL_DEPS/usr/bin:$PATH"
    export LD_LIBRARY_PATH="$OL_DEPS/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

exec "$@"

#!/bin/bash
# Bring up each overlay and ping across it once.
source "$(dirname "$0")/lib.sh"
fail=0
for m in plain gre vxlan uvxlan ipsec ike; do
    topo_reset
    mode_$m
    if na ping -q -c3 -i0.2 -W2 -I "$SRC" "$TARGET" >/dev/null 2>&1; then log "$m: ping ok"; else log "$m: PING FAILED"; fail=1; fi
done
topo_reset; "$LAB_ROOT/scripts/ike.sh" down
exit $fail

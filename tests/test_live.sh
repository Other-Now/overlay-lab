#!/bin/bash
# Live interop: user-space VTEP in a <-> kernel vxlan in b, checked by Scapy in r.
#   scripts/run.sh tests/test_live.sh
source "$(dirname "$0")/../scripts/lib.sh"
PY=${PY:-python3}

topo_reset
mode_uvxlan
na ping -q -c2 -W2 "$TARGET" >/dev/null

cap=$(nr $PY "$LAB_ROOT/tests/live_capture.py") || { log "capture check failed: $cap"; exit 1; }
log "capture: $cap"

# Large frames: a 1422-byte ping payload is a 1450-byte inner IP packet,
# exactly the TAP MTU. One byte more must be refused at a with DF set.
na ping -q -M do -c2 -W2 -s 1422 "$TARGET" >/dev/null || { log "full-MTU ping failed"; exit 1; }
if na ping -q -M do -c1 -W1 -s 1423 "$TARGET" >/dev/null 2>&1; then log "1423 should not fit"; exit 1; fi

pkill -INT -x vxlan_tun; sleep 0.5
c=$(cat "$WORK/vxlan_tun.json")
log "vxlan_tun counters: $c"
topo_reset

$PY - "$c" <<'EOF'
import json, sys
c = json.loads(sys.argv[1])
want = {"rx_wrong_vni": 1, "rx_no_i_flag": 1, "rx_too_short": 1, "rx_wrong_peer": 1, "tx_errors": 0, "tx_emsgsize": 0}
bad = {k: (c[k], v) for k, v in want.items() if c[k] != v}
assert c["rx_frames"] > 0 and c["tx_frames"] > 0, c
if bad:
    print("counter mismatch (got, want):", bad); sys.exit(1)
print("live interop: OK")
EOF

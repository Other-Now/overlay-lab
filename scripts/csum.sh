#!/bin/bash
# Why TCP stalled through the user-space VTEP while ping worked.
#
# b's kernel stack leaves the inner TCP checksum for "hardware" to fill in
# (CHECKSUM_PARTIAL, because vx0 and the veth both advertise tx checksum
# offload). A veth never serializes the packet, so nobody fills it in. The
# kernel VXLAN receiver carries the skb's checksum state across and never
# looks. Our VTEP gets plain bytes from a UDP socket and writes them to a TAP,
# so a's TCP sees a bad checksum on every segment from b and drops it.
#
# For each case: TCP throughput a->b (capped at 100 Mbit/s), and Scapy's count of inner TCP segments
# with a bad checksum on the r wire (b -> a). Writes results/csum.csv.
source "$(dirname "$0")/lib.sh"
PY=${PY:-python3}
OUT="$LAB_ROOT/results/csum.csv"
mkdir -p "$LAB_ROOT/results"
echo "case,a_side,b_tx_csum_offload,gbps,inner_tcp_seen,inner_tcp_bad_csum" >"$OUT"

one() {  # $1 case  $2 setup  $3 a-side label  $4 offload label  $5 b-side tweak
    topo_reset
    eval "$2"
    eval "${5:-true}"
    na ping -q -c2 -W2 "$TARGET" >/dev/null
    nr $PY "$LAB_ROOT/tests/csum_check.py" 4 >"$WORK/csum.json" &
    local cpid=$!
    sleep 1.0
    local g; g=$(iperf_gbps 2 100M)   # capped so Scapy can keep up
    wait $cpid
    local seen bad
    seen=$($PY -c 'import json,sys; print(json.load(open(sys.argv[1]))["inner_tcp"])' "$WORK/csum.json")
    bad=$($PY -c 'import json,sys; print(json.load(open(sys.argv[1]))["bad_csum"])' "$WORK/csum.json")
    log "$1: $g Gbit/s, inner TCP seen $seen, bad checksum $bad"
    echo "$1,$3,$4,$g,$seen,$bad" >>"$OUT"
    pkill -INT -x vxlan_tun 2>/dev/null || true
}

one kernel_to_kernel          mode_vxlan  "kernel vxlan"  on
one kernel_to_userspace       "mode_uvxlan keep-offload" "vxlan_tun" on
one kernel_to_userspace_fixed mode_uvxlan                "vxlan_tun" "off (vx0)"
topo_reset
log "wrote $OUT"

#!/bin/bash
# For each overlay: measured per-packet overhead, the largest ICMP payload that
# crosses with DF set, and TCP throughput (iperf3, REPS x SECS).
# Writes results/bench.csv.
source "$(dirname "$0")/lib.sh"

REPS=${REPS:-3}
SECS=${SECS:-5}
MODES=${MODES:-"plain gre vxlan uvxlan ipsec ike"}
OUT="$LAB_ROOT/results/bench.csv"
mkdir -p "$LAB_ROOT/results"

PROBE=1000   # ICMP payload for the overhead probe; inner IP packet = PROBE + 28

echo "mode,rep,wire_bytes_1000B_ping,overhead_bytes,max_df_payload,gbps,esp_packets" >"$OUT"
for m in $MODES; do
    topo_reset
    mode_$m
    na ping -q -c2 -i0.2 -W2 -I "$SRC" "$TARGET" >/dev/null   # neighbours, SAs
    wire=$(wire_bytes $PROBE)
    # plain: wire = 14 (eth) + 1028; anything above that is the encapsulation.
    over=$(( wire - 14 - PROBE - 28 ))
    maxdf=$(max_df_payload)
    for rep in $(seq "$REPS"); do
        g=$(iperf_gbps "$SECS")
        esp=0
        if [[ $m == ipsec || $m == ike ]]; then
            # Proof the bytes really went through ESP: packet counter of a's outbound SA.
            esp=$(esp_out_packets)
        fi
        log "$m rep $rep: wire=$wire overhead=$over maxdf=$maxdf ${g} Gbit/s esp=$esp"
        echo "$m,$rep,$wire,$over,$maxdf,$g,$esp" >>"$OUT"
    done
    if [[ $m == uvxlan ]]; then
        pkill -INT -x vxlan_tun; sleep 0.3
        cp "$WORK/vxlan_tun.json" "$LAB_ROOT/results/uvxlan_counters.json"
    fi
    [[ $m == ike ]] && cp "$WORK/ike/sas.txt" "$LAB_ROOT/results/ike_sas.txt"
done
topo_reset; "$LAB_ROOT/scripts/ike.sh" down
log "wrote $OUT"

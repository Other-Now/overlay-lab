#!/bin/bash
# MTU black hole: reproduce it, then fix it.
#
# The r<->w "WAN" link gets MTU 1400 while a and b keep their 1500-byte
# links. A packet with DF set that is too big for that link gets dropped at r,
# and r sends back ICMP "fragmentation needed" (type 3 code 4) carrying the
# next-hop MTU. Path MTU discovery depends on that ICMP. A firewall that drops
# it turns "too big" into "silently lost": small packets (TCP handshake,
# ping) get through, but full-size data segments never arrive.
#
# Each case records: does a small ping pass, does a full-size DF ping pass
# (payload = sender's interface MTU - 28),
# iperf3 TCP throughput (median of REPS runs, with min-max), and how many ICMP dest-unreachables r sent and how
# many its filter dropped. Writes results/blackhole.csv.
source "$(dirname "$0")/lib.sh"

SECS=${SECS:-5}
REPS=${REPS:-3}
WAN_MTU=1400
OUT="$LAB_ROOT/results/blackhole.csv"
mkdir -p "$LAB_ROOT/results"

shrink_wan() {
    ip -n r link set rw mtu $WAN_MTU
    ip -n w link set wr mtu $WAN_MTU
}

# Largest payload the sender believes fits: its outgoing interface MTU - 28.
full_size() {
    local dev; dev=$(ip -n a route get "$TARGET" from "$SRC" | grep -oE 'dev [^ ]+' | head -1 | cut -d' ' -f2)
    echo $(( $(na cat /sys/class/net/"$dev"/mtu) - 28 ))
}

# Drop exactly ICMP type 3 code 4 leaving r towards a: the "security" rule
# that causes the classic black hole. Everything else, including echo, passes.
drop_frag_needed() {
    tc -n r qdisc add dev ra clsact
    tc -n r filter add dev ra egress protocol ip pref 1 flower ip_proto icmp type 3 code 4 action drop
}

filter_drops() {
    tc -n r -s filter show dev ra egress 2>/dev/null | awk '/Sent/ {print $4; exit}' | grep -E '^[0-9]+$' || echo 0
}

r_icmp_unreach() {
    nr awk '/^Icmp:/ { if (!h) { for (i=1;i<=NF;i++) n[i]=$i; h=1 } else { for (i=1;i<=NF;i++) if (n[i]=="OutDestUnreachs") print $i } }' /proc/net/snmp
}

ping_ok() {  # $1 = payload size
    na ping -q -M do -c2 -i0.3 -W1 -I "$SRC" -s "$1" "$TARGET" >/dev/null 2>&1 && echo yes || echo no
}

echo "case,overlay,icmp_frag_needed,fix,ping_56,full_payload,ping_df_full,gbps,gbps_min,gbps_max,r_icmp_unreach_sent,r_filter_dropped" >"$OUT"

run_case() {  # $1 name  $2 overlay setup cmd  $3 icmp ok|dropped  $4 fix (text)  $5 fix cmd
    local name=$1 setup=$2 icmp=$3 fix=$4 fixcmd=${5:-true}
    topo_reset
    shrink_wan
    eval "$setup"
    [[ $icmp == dropped ]] && drop_frag_needed
    eval "$fixcmd"
    sleep 0.3
    local p56 pfull full g sent dropped
    full=$(full_size)
    p56=$(ping_ok 56)
    pfull=$(ping_ok "$full")
    local all=()
    for _ in $(seq "$REPS"); do all+=("$(iperf_gbps "$SECS")"); done
    local sorted gmin gmax
    sorted=$(printf '%s\n' "${all[@]}" | sort -n)
    g=$(awk '{v[NR]=$1} END {print v[int((NR+1)/2)]}' <<<"$sorted")
    gmin=$(head -1 <<<"$sorted"); gmax=$(tail -1 <<<"$sorted")
    sent=$(r_icmp_unreach)
    dropped=$(filter_drops)
    log "$name: ping56=$p56 ping$full=$pfull ${g} Gbit/s (${gmin}-${gmax}), r sent $sent unreachables, filter dropped $dropped"
    echo "$name,${setup%% *},$icmp,$fix,$p56,$full,$pfull,$g,$gmin,$gmax,$sent,$dropped" >>"$OUT"
}

# Baseline: no tunnel. TCP's own PMTU discovery handles the 1400 link if ICMP gets back.
run_case plain_icmp_ok        "mode_plain"           ok      none
run_case plain_icmp_dropped   "mode_plain"           dropped none

# VXLAN, outer DF set: the overlay needs PMTU discovery on the outer path.
run_case vxlan_df_icmp_ok      "mode_vxlan 'df set'" ok      none
run_case vxlan_df_icmp_dropped "mode_vxlan 'df set'" dropped none
# Fix 1: size the overlay for the real path: 1400 - 50 = 1350.
run_case vxlan_df_icmp_dropped_mtu1350 "mode_vxlan 'df set'" dropped "vx0 mtu 1350" \
    "ip -n a link set vx0 mtu 1350; ip -n b link set vx0 mtu 1350"
# Fix 2: Linux's default (df unset): r fragments the outer packet instead.
run_case vxlan_nodf_icmp_dropped "mode_vxlan"         dropped "outer DF off (default)"

# GRE: pmtudisc is on by default, so the outer header always carries DF.
run_case gre_icmp_ok          "mode_gre"             ok      none
run_case gre_icmp_dropped     "mode_gre"             dropped none
run_case gre_icmp_dropped_mtu1376 "mode_gre"         dropped "gre1 mtu 1376" \
    "ip -n a link set gre1 mtu 1376; ip -n b link set gre1 mtu 1376"

# IPsec ESP tunnel mode: the outer DF is copied from the inner packet (TCP sets DF).
run_case ipsec_icmp_ok        "mode_ipsec"           ok      none
run_case ipsec_icmp_dropped   "mode_ipsec"           dropped none

topo_reset
log "wrote $OUT"

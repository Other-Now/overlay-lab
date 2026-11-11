# Shared helpers. Source this file from inside the lab namespace (see run.sh).
#
# Topology (four network namespaces, all on one host):
#
#   [ a ] ul 10.0.1.1 --- 10.0.1.254 ra [ r ] rw 10.0.9.1 --- 10.0.9.2 wr [ w ] wb 10.0.2.254 --- 10.0.2.1 ul [ b ]
#
#   a and b are the tunnel endpoints. r and w are plain IPv4 routers. The r<->w
#   link is the "WAN": blackhole.sh shrinks its MTU and makes r drop ICMP, while
#   a and b keep their 1500-byte links. If b's own link were the small one, b
#   would advertise a smaller TCP MSS and hide the problem.
#   Overlay addresses: 172.16.0.1 (a) <-> 172.16.0.2 (b) for GRE/VXLAN.
#   IPsec protects 172.16.1.1 (a) <-> 172.16.2.1 (b); each sits on a dummy interface.

set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${BUILD:-$LAB_ROOT/build}"
WORK="${WORK:-/tmp/overlay-lab}"
mkdir -p "$WORK"

A_UL=10.0.1.1; R_A=10.0.1.254
B_UL=10.0.2.1; R_B=10.0.2.254   # R_B lives on w
R_W=10.0.9.1;   W_R=10.0.9.2
A_OV=172.16.0.1; B_OV=172.16.0.2
A_SEC=172.16.1.1; B_SEC=172.16.2.1

na() { ip netns exec a "$@"; }
nb() { ip netns exec b "$@"; }
nr() { ip netns exec r "$@"; }
nw() { ip netns exec w "$@"; }

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

# Tear everything down and build the bare a - r - w - b underlay.
topo_reset() {
    for ns in a r w b; do ip netns del "$ns" 2>/dev/null || true; done
    pkill -x vxlan_tun 2>/dev/null || true
    pkill -x iperf3 2>/dev/null || true
    pkill -x charon 2>/dev/null || true
    sleep 0.2
    for ns in a r w b; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
    ip link add ul netns a type veth peer name ra netns r
    ip link add rw netns r type veth peer name wr netns w
    ip link add ul netns b type veth peer name wb netns w
    ip -n a addr add $A_UL/24 dev ul
    ip -n r addr add $R_A/24 dev ra
    ip -n r addr add $R_W/30 dev rw
    ip -n w addr add $W_R/30 dev wr
    ip -n w addr add $R_B/24 dev wb
    ip -n b addr add $B_UL/24 dev ul
    for x in "a ul" "r ra" "r rw" "w wr" "w wb" "b ul"; do
        set -- $x
        ip -n "$1" link set "$2" up
        # Segmentation offloads off on every veth. With GSO/TSO on, the stack
        # hands 64 KiB "packets" to the veth, and MTU problems stay hidden
        # until a real NIC segments them.
        ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null
    done
    ip -n a route add default via $R_A
    ip -n b route add default via $R_B
    ip -n r route add 10.0.2.0/24 via $W_R
    ip -n w route add 10.0.1.0/24 via $R_W
    nr sysctl -qw net.ipv4.ip_forward=1
    nw sysctl -qw net.ipv4.ip_forward=1
}

# ---- one function per overlay; each leaves "$TARGET" set to the address to test ----

mode_plain() {
    TARGET=$B_UL; SRC=$A_UL
}

mode_gre() {
    ip -n a link add gre1 type gre local $A_UL remote $B_UL ttl 64
    ip -n b link add gre1 type gre local $B_UL remote $A_UL ttl 64
    ip -n a addr add $A_OV/30 dev gre1; ip -n a link set gre1 up
    ip -n b addr add $B_OV/30 dev gre1; ip -n b link set gre1 up
    TARGET=$B_OV; SRC=$A_OV
}

# $1 = extra vxlan options, e.g. "df set"
mode_vxlan() {
    local extra="${1:-}"
    ip -n a link add vx0 type vxlan id 42 local $A_UL remote $B_UL dstport 4789 dev ul $extra
    ip -n b link add vx0 type vxlan id 42 local $B_UL remote $A_UL dstport 4789 dev ul $extra
    ip -n a addr add $A_OV/24 dev vx0; ip -n a link set vx0 up
    ip -n b addr add $B_OV/24 dev vx0; ip -n b link set vx0 up
    TARGET=$B_OV; SRC=$A_OV
}

# a runs the user-space VTEP (src/vxlan_tun.cpp); b runs the kernel vxlan device.
# $1 = "keep-offload" leaves b's tx checksum offload on, which reproduces the
# TCP stall that scripts/csum.sh explains. By default it is turned off on b's vx0:
# the kernel would otherwise send inner TCP segments with unfinished checksums,
# and a user-space receiver can't tell (see README, "The checksum bug").
mode_uvxlan() {
    ip -n b link add vx0 type vxlan id 42 local $B_UL remote $A_UL dstport 4789 dev ul
    ip -n b addr add $B_OV/24 dev vx0; ip -n b link set vx0 up
    [[ ${1:-} == keep-offload ]] || nb ethtool -K vx0 tx off >/dev/null
    na "$BUILD/vxlan_tun" --tap uvx0 --local $A_UL --remote $B_UL --vni 42 \
        >"$WORK/vxlan_tun.json" 2>"$WORK/vxlan_tun.log" &
    for _ in $(seq 50); do ip -n a link show uvx0 >/dev/null 2>&1 && break; sleep 0.1; done
    ip -n a addr add $A_OV/24 dev uvx0; ip -n a link set uvx0 up
    TARGET=$B_OV; SRC=$A_OV
}

# Static-key IPsec: ESP tunnel mode, AES-128-GCM, keys typed in by hand.
# This is what IKE automates; the SPIs and keys are fixed lab values.
mode_ipsec() {
    sec_addrs
    local k1=0x$(printf '11%.0s' $(seq 20)) k2=0x$(printf '22%.0s' $(seq 20))
    for ns in a b; do
        ip -n $ns xfrm state add src $A_UL dst $B_UL proto esp spi 0x1001 reqid 1 mode tunnel \
            aead 'rfc4106(gcm(aes))' $k1 128
        ip -n $ns xfrm state add src $B_UL dst $A_UL proto esp spi 0x2002 reqid 2 mode tunnel \
            aead 'rfc4106(gcm(aes))' $k2 128
    done
    ip -n a xfrm policy add src $A_SEC/32 dst $B_SEC/32 dir out tmpl src $A_UL dst $B_UL proto esp reqid 1 mode tunnel
    ip -n a xfrm policy add src $B_SEC/32 dst $A_SEC/32 dir in  tmpl src $B_UL dst $A_UL proto esp reqid 2 mode tunnel
    ip -n b xfrm policy add src $B_SEC/32 dst $A_SEC/32 dir out tmpl src $B_UL dst $A_UL proto esp reqid 2 mode tunnel
    ip -n b xfrm policy add src $A_SEC/32 dst $B_SEC/32 dir in  tmpl src $A_UL dst $B_UL proto esp reqid 1 mode tunnel
    TARGET=$B_SEC; SRC=$A_SEC
}

# The protected endpoints live on dummy interfaces, routed over the underlay.
sec_addrs() {
    ip -n a link add sec0 type dummy; ip -n a addr add $A_SEC/32 dev sec0; ip -n a link set sec0 up
    ip -n b link add sec0 type dummy; ip -n b addr add $B_SEC/32 dev sec0; ip -n b link set sec0 up
    ip -n a route add $B_SEC/32 via $R_A src $A_SEC
    ip -n b route add $A_SEC/32 via $R_B src $B_SEC
    # r has no route to the 172.16.x hosts; only ESP between 10.0.x addresses
    # can cross it, so a cleartext packet that slips past the policy is dropped.
}

# IKEv2 with strongSwan: same ESP SA shape as mode_ipsec, but keys and SPIs are
# negotiated (PSK auth, AES-128-GCM, x25519 DH; the openssl plugin provides x25519).
mode_ike() {
    sec_addrs
    "$LAB_ROOT/scripts/ike.sh" up
    TARGET=$B_SEC; SRC=$A_SEC
}

# Largest ICMP payload that crosses with DF set, found by binary search.
max_df_payload() {
    local lo=0 hi=9000 mid
    while (( lo < hi )); do
        mid=$(( (lo + hi + 1) / 2 ))
        if na ping -q -M do -c1 -W1 -I "$SRC" -s $mid "$TARGET" >/dev/null 2>&1; then lo=$mid; else hi=$(( mid - 1 )); fi
    done
    echo $lo
}

# Bytes one inner ICMP echo request of payload $1 occupies on the a->r wire.
# Counts the L2 frame on r's ra interface (rx side), so it includes the
# 14-byte outer Ethernet header and every encapsulation layer.
wire_bytes() {
    local size=$1 before after
    na ping -q -c1 -W1 -I "$SRC" -s "$size" "$TARGET" >/dev/null 2>&1 || true  # warm ARP/neigh, SAs
    sleep 0.2
    before=$(nr cat /sys/class/net/ra/statistics/rx_bytes)
    na ping -q -c1 -W1 -I "$SRC" -s "$size" "$TARGET" >/dev/null 2>&1
    after=$(nr cat /sys/class/net/ra/statistics/rx_bytes)
    echo $(( after - before ))
}

# Packets sent on a's outbound ESP SA (src = a's underlay address).
esp_out_packets() {
    ip -n a -s xfrm state | python3 -c '
import re, sys
for blk in re.split(r"(?m)^src ", sys.stdin.read())[1:]:
    if blk.startswith("10.0.1.1 "):
        m = re.search(r"(\d+)\(bytes\), (\d+)\(packets\)", blk)
        print(m.group(2) if m else 0); break
else:
    print(0)'
}

IPERF="${IPERF:-iperf3}"

# TCP throughput a -> b over the overlay, $1 seconds, optional rate cap $2
# (iperf3 -b syntax, e.g. 50M). Prints Gbit/s received; 0.000 if the
# connection stalled. Both ends are under `timeout`, so a black hole
# can't hang the run.
iperf_gbps() {
    local secs=$1 rate=${2:-}
    nb timeout $(( secs + 15 )) $IPERF -s -1 -B "$TARGET" >/dev/null 2>&1 &
    local spid=$!
    sleep 0.3
    local out
    out=$(na timeout $(( secs + 10 )) $IPERF -c "$TARGET" -B "$SRC" -t "$secs" ${rate:+-b $rate} -J 2>/dev/null) || true
    wait $spid 2>/dev/null || true
    python3 -c 'import json,sys
try:
    d=json.loads(sys.stdin.read()); print("%.3f" % (d["end"]["sum_received"]["bits_per_second"]/1e9))
except Exception: print("0.000")' <<<"$out"
}

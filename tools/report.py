"""Summarise results/*.csv as Markdown tables.

  python3 tools/report.py results > results/RESULTS.md
"""
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

d = Path(sys.argv[1] if len(sys.argv) > 1 else "results")

LABEL = {
    "plain": "none (plain IPv4)",
    "gre": "GRE",
    "vxlan": "VXLAN (kernel)",
    "uvxlan": "VXLAN (vxlan_tun, user space) -> kernel",
    "ipsec": "IPsec ESP tunnel, static keys",
    "ike": "IPsec ESP tunnel, IKEv2 (strongSwan)",
}

bench = d / "bench.csv"
if bench.exists():
    rows = list(csv.DictReader(bench.open()))
    by = defaultdict(list)
    for r in rows:
        by[r["mode"]].append(r)
    base = None
    print("## Overhead and throughput\n")
    print("Overhead = bytes on the a->r wire for one 1000-byte ping, minus the bare "
          "packet (14 + 1028). Throughput = iperf3 TCP a->b, median of the reps (min-max).\n")
    print("| overlay | overhead (B) | max DF ping payload | tunnel MTU | TCP Gbit/s | vs plain | ESP pkts (last rep) |")
    print("|---|---:|---:|---:|---|---:|---:|")
    for m, rs in by.items():
        g = [float(r["gbps"]) for r in rs]
        med = statistics.median(g)
        if m == "plain":
            base = med
        rel = f"{med / base:.2f}x" if base else "-"
        mtu = int(rs[0]["max_df_payload"]) + 28
        esp = rs[-1]["esp_packets"] if m in ("ipsec", "ike") else "-"
        print(f"| {LABEL.get(m, m)} | {rs[0]['overhead_bytes']} | {rs[0]['max_df_payload']} | {mtu} | "
              f"{med:.2f} ({min(g):.2f}-{max(g):.2f}) | {rel} | {esp} |")
    print()

bh = d / "blackhole.csv"
if bh.exists():
    print("## MTU black hole (WAN link MTU 1400)\n")
    print("| case | ICMP frag-needed | fix | ping 56 | full-size DF ping | TCP Gbit/s | r: unreachables sent | r: filter dropped |")
    print("|---|---|---|---|---|---:|---:|---:|")
    for r in csv.DictReader(bh.open()):
        g = float(r["gbps"])
        gs = "**0 (stalled)**" if float(r["gbps_max"]) == 0 else f"{g:.2f} ({float(r['gbps_min']):.2f}-{float(r['gbps_max']):.2f})"
        print(f"| {r['case']} | {r['icmp_frag_needed']} | {r['fix']} | {r['ping_56']} | {r['ping_df_full']} ({r['full_payload']} B) | "
              f"{gs} | {r['r_icmp_unreach_sent']} | {r['r_filter_dropped']} |")
    print()

cs = d / "csum.csv"
if cs.exists():
    print("## Checksum offload and the user-space VTEP\n")
    print("Inner TCP segments travelling b->a, captured at r and checked by Scapy. iperf3 capped at 100 Mbit/s.\n")
    print("| case | receiver at a | b tx checksum offload | TCP Gbit/s | inner TCP seen | bad checksum |")
    print("|---|---|---|---:|---:|---:|")
    for r in csv.DictReader(cs.open()):
        g = float(r["gbps"])
        gs = "**0 (stalled)**" if g == 0 else f"{g:.2f}"
        print(f"| {r['case']} | {r['a_side']} | {r['b_tx_csum_offload']} | {gs} | {r['inner_tcp_seen']} | {r['inner_tcp_bad_csum']} |")
    print()

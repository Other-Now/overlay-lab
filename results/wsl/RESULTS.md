## Overhead and throughput

Overhead = bytes on the a->r wire for one 1000-byte ping, minus the bare packet (14 + 1028). Throughput = iperf3 TCP a->b, median of the reps (min-max).

| overlay | overhead (B) | max DF ping payload | tunnel MTU | TCP Gbit/s | vs plain | ESP pkts (last rep) |
|---|---:|---:|---:|---|---:|---:|
| none (plain IPv4) | 0 | 1472 | 1500 | 3.86 (3.23-3.88) | 1.00x | - |
| GRE | 24 | 1448 | 1476 | 3.35 (3.25-3.54) | 0.87x | - |
| VXLAN (kernel) | 50 | 1422 | 1450 | 3.40 (3.04-3.41) | 0.88x | - |
| VXLAN (vxlan_tun, user space) -> kernel | 50 | 1422 | 1450 | 0.33 (0.15-0.33) | 0.08x | - |
| IPsec ESP tunnel, static keys | 56 | 1418 | 1446 | 0.60 (0.52-0.77) | 0.16x | 856948 |
| IPsec ESP tunnel, IKEv2 (strongSwan) | 56 | 1418 | 1446 | 0.39 (0.38-0.55) | 0.10x | 596060 |

## MTU black hole (WAN link MTU 1400)

| case | ICMP frag-needed | fix | ping 56 | full-size DF ping | TCP Gbit/s | r: unreachables sent | r: filter dropped |
|---|---|---|---|---|---:|---:|---:|
| plain_icmp_ok | ok | none | yes | no (1472 B) | 3.34 (3.17-3.42) | 1 | 0 |
| plain_icmp_dropped | dropped | none | yes | no (1472 B) | **0 (stalled)** | 50 | 50 |
| vxlan_df_icmp_ok | ok | none | yes | no (1422 B) | 2.58 (2.39-2.90) | 1 | 0 |
| vxlan_df_icmp_dropped | dropped | none | yes | no (1422 B) | **0 (stalled)** | 50 | 50 |
| vxlan_df_icmp_dropped_mtu1350 | dropped | vx0 mtu 1350 | yes | yes (1322 B) | 2.65 (2.24-2.88) | 0 | 0 |
| vxlan_nodf_icmp_dropped | dropped | outer DF off (default) | yes | yes (1422 B) | 1.82 (1.77-1.82) | 0 | 0 |
| gre_icmp_ok | ok | none | yes | no (1448 B) | 3.46 (3.39-3.50) | 1 | 0 |
| gre_icmp_dropped | dropped | none | yes | no (1448 B) | **0 (stalled)** | 50 | 50 |
| gre_icmp_dropped_mtu1376 | dropped | gre1 mtu 1376 | yes | yes (1348 B) | 3.17 (2.85-3.39) | 0 | 0 |
| ipsec_icmp_ok | ok | none | yes | no (1472 B) | 0.75 (0.40-0.77) | 1 | 0 |
| ipsec_icmp_dropped | dropped | none | yes | no (1472 B) | **0 (stalled)** | 48 | 48 |

## Checksum offload and the user-space VTEP

Inner TCP segments travelling b->a, captured at r and checked by Scapy. iperf3 capped at 100 Mbit/s.

| case | receiver at a | b tx checksum offload | TCP Gbit/s | inner TCP seen | bad checksum |
|---|---|---|---:|---:|---:|
| kernel_to_kernel | kernel vxlan | on | 0.10 | 91 | 91 |
| kernel_to_userspace | vxlan_tun | on | **0 (stalled)** | 5 | 5 |
| kernel_to_userspace_fixed | vxlan_tun | off (vx0) | 0.10 | 747 | 0 |


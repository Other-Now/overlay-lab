## Overhead and throughput

Overhead = bytes on the a->r wire for one 1000-byte ping, minus the bare packet (14 + 1028). Throughput = iperf3 TCP a->b, median of the reps (min-max).

| overlay | overhead (B) | max DF ping payload | tunnel MTU | TCP Gbit/s | vs plain | ESP pkts (last rep) |
|---|---:|---:|---:|---|---:|---:|
| none (plain IPv4) | 0 | 1472 | 1500 | 3.18 (3.17-3.27) | 1.00x | - |
| GRE | 24 | 1448 | 1476 | 2.98 (2.94-3.00) | 0.93x | - |
| VXLAN (kernel) | 50 | 1422 | 1450 | 2.78 (2.68-2.80) | 0.87x | - |
| VXLAN (vxlan_tun, user space) -> kernel | 50 | 1422 | 1450 | 0.55 (0.55-0.56) | 0.17x | - |
| IPsec ESP tunnel, static keys | 56 | 1418 | 1446 | 0.57 (0.57-0.59) | 0.18x | 784191 |
| IPsec ESP tunnel, IKEv2 (strongSwan) | 56 | 1418 | 1446 | 0.56 (0.56-0.58) | 0.18x | 769190 |

## MTU black hole (WAN link MTU 1400)

| case | ICMP frag-needed | fix | ping 56 | full-size DF ping | TCP Gbit/s | r: unreachables sent | r: filter dropped |
|---|---|---|---|---|---:|---:|---:|
| plain_icmp_ok | ok | none | yes | no (1472 B) | 3.04 (3.04-3.08) | 1 | 0 |
| plain_icmp_dropped | dropped | none | yes | no (1472 B) | **0 (stalled)** | 50 | 50 |
| vxlan_df_icmp_ok | ok | none | yes | no (1422 B) | 2.56 (2.55-2.59) | 1 | 0 |
| vxlan_df_icmp_dropped | dropped | none | yes | no (1422 B) | **0 (stalled)** | 50 | 50 |
| vxlan_df_icmp_dropped_mtu1350 | dropped | vx0 mtu 1350 | yes | yes (1322 B) | 2.53 (2.52-2.57) | 0 | 0 |
| vxlan_nodf_icmp_dropped | dropped | outer DF off (default) | yes | yes (1422 B) | 1.28 (1.24-1.29) | 0 | 0 |
| gre_icmp_ok | ok | none | yes | no (1448 B) | 2.79 (2.76-2.82) | 1 | 0 |
| gre_icmp_dropped | dropped | none | yes | no (1448 B) | **0 (stalled)** | 50 | 50 |
| gre_icmp_dropped_mtu1376 | dropped | gre1 mtu 1376 | yes | yes (1348 B) | 2.92 (2.89-2.93) | 0 | 0 |
| ipsec_icmp_ok | ok | none | yes | no (1472 B) | 0.80 (0.51-0.83) | 1 | 0 |
| ipsec_icmp_dropped | dropped | none | yes | no (1472 B) | **0 (stalled)** | 48 | 48 |

## Checksum offload and the user-space VTEP

Inner TCP segments travelling b->a, captured at r and checked by Scapy. iperf3 capped at 100 Mbit/s.

| case | receiver at a | b tx checksum offload | TCP Gbit/s | inner TCP seen | bad checksum |
|---|---|---|---:|---:|---:|
| kernel_to_kernel | kernel vxlan | on | 0.10 | 79 | 79 |
| kernel_to_userspace | vxlan_tun | on | **0 (stalled)** | 5 | 5 |
| kernel_to_userspace_fixed | vxlan_tun | off (vx0) | 0.10 | 1086 | 0 |


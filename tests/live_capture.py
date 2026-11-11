"""Runs inside namespace r, between the user-space VTEP (a) and the kernel VXLAN device (b).

1. Sniffs both directions on r's interfaces while a pings b over the overlay.
   Every outer packet must parse in Scapy as UDP/4789 + VXLAN with I flag,
   VNI 42 and zero reserved fields. The a->b packets come from our encoder and
   the b->a packets from the kernel, so the two directions are compared field by field.
2. Injects bad packets from r towards a:4789 (wrong VNI, I flag clear, a
   truncated header, a spoofed peer). The VTEP must count and drop each one;
   test_live.sh checks its counters afterwards.
"""
import json
import subprocess
import sys
import time

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import AsyncSniffer, conf, send  # noqa: E402
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.vxlan import VXLAN
from scapy.packet import Raw

A_UL, B_UL = "10.0.1.1", "10.0.2.1"
conf.verb = 0

sniffer = AsyncSniffer(iface=["ra", "rw"], filter=None, store=True,
                       lfilter=lambda p: UDP in p and p[UDP].dport == 4789)
sniffer.start()
time.sleep(1.0)
subprocess.run(["ip", "netns", "exec", "a", "ping", "-q", "-c5", "-i0.2", "-W2", "-s", "200", "172.16.0.2"],
               check=True, stdout=subprocess.DEVNULL)
time.sleep(0.5)
pkts = sniffer.stop()

results = {"a_to_b": 0, "b_to_a": 0, "frames": 0, "bad": []}
for p in pkts:
    ip = p[IP]
    direction = "a_to_b" if ip.src == A_UL else "b_to_a" if ip.src == B_UL else None
    if direction is None:
        continue
    v = p[VXLAN]
    raw = bytes(p[UDP].payload)
    # Header checks apply to every frame; inner frames can be ARP as well as IP.
    ok = (v.flags == 0x08 and v.vni == 42 and raw[1:4] == b"\0\0\0" and raw[7] == 0
          and isinstance(v.payload, Ether))
    if not ok:
        results["bad"].append(f"{direction}: {raw[:8].hex()}")
        continue
    results["frames"] += 1
    if ICMP in v.payload:
        results[direction] += 1
# results counts ICMP frames per direction. Each echo request crosses r twice (in on ra, out on rw), and so does each reply.
print(json.dumps(results))

# Injection. The source address is spoofed as b, the VTEP's only allowed peer,
# except in the last packet.
inner = bytes(Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="172.16.0.99", dst="172.16.0.1") / ICMP())
inject = [
    IP(src=B_UL, dst=A_UL) / UDP(sport=4789, dport=4789) / VXLAN(vni=43, flags=0x08) / Raw(inner),  # wrong VNI
    IP(src=B_UL, dst=A_UL) / UDP(sport=4789, dport=4789) / VXLAN(vni=42, flags=0x00) / Raw(inner),  # I flag clear
    IP(src=B_UL, dst=A_UL) / UDP(sport=4789, dport=4789) / Raw(b"\x08\0\0\0\0\0\x2a\0" + inner[:5]),  # truncated
    IP(src="10.0.2.77", dst=A_UL) / UDP(sport=4789, dport=4789) / VXLAN(vni=42) / Raw(inner),       # wrong peer
]
for pkt in inject:
    send(pkt, iface="ra")
time.sleep(0.5)
sys.exit(1 if results["bad"] or results["a_to_b"] == 0 or results["b_to_a"] == 0 else 0)

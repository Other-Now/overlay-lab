"""Runs in namespace r. Sniffs VXLAN packets travelling b -> a for a few seconds
and checks the checksum of every inner TCP segment.

Prints JSON: {"inner_tcp": N, "bad_csum": M}
"""
import json
import sys

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.vxlan import VXLAN

secs = float(sys.argv[1]) if len(sys.argv) > 1 else 3.0
seen = bad = 0


def handle(p):
    global seen, bad
    if not (IP in p and p[IP].src == "10.0.2.1" and UDP in p and p[UDP].dport == 4789 and VXLAN in p):
        return
    inner = p[VXLAN].payload
    if IP not in inner or TCP not in inner:
        return
    seen += 1
    ip = inner[IP]
    on_wire = ip[TCP].chksum
    ip2 = ip.copy()
    del ip2[TCP].chksum
    if IP(bytes(ip2))[TCP].chksum != on_wire:
        bad += 1


sniff(iface="ra", prn=handle, store=False, timeout=secs)
print(json.dumps({"inner_tcp": seen, "bad_csum": bad}))

"""Check src/vxlan.hpp against Scapy's VXLAN layer (no root needed).

  python3 tests/test_codec.py [path/to/vxlan_codec]
"""
import logging
import random
import subprocess
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.vxlan import VXLAN
from scapy.packet import Raw

CODEC = sys.argv[1] if len(sys.argv) > 1 else "build/vxlan_codec"
rng = random.Random(7348)  # RFC number, fixed seed


def run(mode, vni, data):
    p = subprocess.run([CODEC, mode, str(vni)], input=data, capture_output=True)
    return p.returncode, p.stdout, p.stderr.decode().strip()


def inner_frames():
    for size in (0, 1, 18, 100, 1400, 1450 - 14 - 20 - 8):
        yield Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="172.16.0.1", dst="172.16.0.2") / UDP(sport=1234, dport=5678) / Raw(bytes(rng.getrandbits(8) for _ in range(size)))
    yield Ether() / IP() / ICMP() / Raw(b"ping")
    yield Ether() / IP() / TCP(flags="S")
    yield Ether(type=0x0806) / Raw(b"\x00" * 28)  # an ARP-sized frame


checks = 0
failures = 0


def check(cond, what):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1
        print("FAIL:", what)


VNIS = [0, 1, 42, 0x123456, 0xFFFFFF] + [rng.randrange(1 << 24) for _ in range(5)]

for frame in inner_frames():
    raw = bytes(frame)
    for vni in VNIS:
        want = bytes(VXLAN(vni=vni, flags=0x08) / frame)

        rc, got, _ = run("encap", vni, raw)
        check(rc == 0 and got == want, f"encap vni={vni} len={len(raw)}")

        rc, got, _ = run("decap", vni, want)
        check(rc == 0 and got == raw, f"decap vni={vni} len={len(raw)}")

        # Scapy must parse our encap output back to the same VNI and inner frame.
        parsed = VXLAN(run("encap", vni, raw)[1])
        check(parsed.vni == vni and parsed.flags == 0x08 and bytes(parsed.payload) == raw,
              f"scapy round-trip vni={vni}")

frame = bytes(Ether() / IP() / ICMP())

# Receive-side checks.
rc, _, err = run("decap", 42, bytes(VXLAN(vni=43, flags=0x08) / Raw(frame)))
check(rc == 2 and err == "wrong_vni", "wrong VNI rejected")

rc, _, err = run("decap", 42, bytes(VXLAN(vni=42, flags=0x00) / Raw(frame)))
check(rc == 2 and err == "no_i_flag", "I flag clear rejected")

for n in range(0, 8 + 14):
    rc, _, err = run("decap", 42, bytes(VXLAN(vni=42) / Raw(frame))[:n])
    check(rc == 2 and err == "too_short", f"truncated to {n} bytes rejected")

# RFC 7348: reserved bits MUST be ignored on receipt.
pkt = bytearray(bytes(VXLAN(vni=42, flags=0x08) / Raw(frame)))
pkt[0] |= 0xF7; pkt[1] = 0xAA; pkt[2] = 0xBB; pkt[3] = 0xCC; pkt[7] = 0xDD
rc, got, _ = run("decap", 42, bytes(pkt))
check(rc == 0 and got == frame, "reserved bits ignored on receive")

# ...and MUST be zero on transmit.
_, enc, _ = run("encap", 42, frame)
check(enc[0] == 0x08 and enc[1:4] == b"\0\0\0" and enc[7] == 0, "reserved bits zero on transmit")

print(f"{checks - failures}/{checks} codec checks passed")
sys.exit(1 if failures else 0)

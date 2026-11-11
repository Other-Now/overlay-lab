# overlay-lab

GRE, VXLAN and IPsec tunnels between Linux network namespaces, plus a VXLAN endpoint I wrote in C++. The lab measures what each tunnel costs and reproduces two failures: the classic MTU black hole, and a checksum-offload bug that stalled TCP through my own VXLAN endpoint.

Everything runs on one Linux host, inside namespaces. Root isn't required: `scripts/run.sh` falls back to a user namespace.

```
[ a ] ul 10.0.1.1 ── ra [ r ] rw ══ WAN ══ wr [ w ] wb ── ul 10.0.2.1 [ b ]
  tunnel endpoint      router        r<->w      router        tunnel endpoint
```

| piece | what it is |
|---|---|
| `scripts/lib.sh` | Builds the topology and one `mode_*` function per overlay: plain, `gre`, `vxlan` (kernel), `uvxlan` (my VTEP ↔ kernel), `ipsec` (ESP tunnel mode, static keys via `ip xfrm`), `ike` (same ESP, keys negotiated by strongSwan IKEv2) |
| `src/vxlan_tun.cpp` | User-space VXLAN tunnel endpoint (RFC 7348): TAP ↔ UDP/4789. Point-to-point, VNI check, peer check, drop counters |
| `src/vxlan.hpp` | Header codec: I flag, 24-bit VNI, reserved bits zero on send and ignored on receive |
| `scripts/ike.sh` | One strongSwan `charon` per namespace, PSK auth, AES-128-GCM + x25519 |
| `scripts/bench.sh` | Per overlay: overhead measured from router byte counters, largest DF ping, iperf3 TCP |
| `scripts/blackhole.sh` | WAN link MTU 1400, r drops ICMP "fragmentation needed"; each overlay is run with that ICMP allowed and with it dropped, plus fixes |
| `scripts/csum.sh` | The checksum-offload bug, measured with Scapy |
| `tests/` | Scapy codec test (296 checks), live interop test: kernel VXLAN ↔ my VTEP, Scapy at r validates both directions and injects malformed packets |

## Results

These are the local WSL2 numbers (i5-9300H, 4 vCPU, kernel 6.6; every namespace shares those CPUs). Throughput is CPU-bound software forwarding, not wire speed, so read the ratios rather than the absolute Gbit/s. The CI run on GitHub's runner is in the Actions summary, and `results/wsl/` holds the raw CSVs.

### 1. What each tunnel costs

| overlay | overhead, measured (B) | tunnel MTU | TCP Gbit/s, median (min–max) of 3 × 5 s |
|---|---:|---:|---|
| none | 0 | 1500 | 3.86 (3.23–3.88) |
| GRE | 24 | 1476 | 3.35 (3.25–3.54) |
| VXLAN, kernel | 50 | 1450 | 3.40 (3.04–3.41) |
| VXLAN, `vxlan_tun` → kernel | 50 | 1450 | 0.33 (0.15–0.33) |
| IPsec ESP, static keys | 56 | 1446 | 0.60 (0.52–0.77) |
| IPsec ESP, IKEv2 | 56 | 1446 | 0.39 (0.38–0.55) |

- Overhead is measured, not looked up: it's the bytes r's interface received for one 1000-byte ping, minus the bare packet. The results match the header math: GRE adds IP 20 + GRE 4. VXLAN adds IP 20 + UDP 8 + VXLAN 8 + inner Ethernet 14. ESP with AES-GCM adds IP 20 + SPI/seq 8 + IV 8 + ICV 16 + pad/trailer 4 for this size.
- The ESP SA counters show ~600k–860k packets went through ESP during the runs, so the IPsec rows really were encrypted.
- `vxlan_tun` makes one syscall per frame in each direction with no batching. That's about 10× slower than the kernel, which is expected and not tuned.
- ESP is 5–10× slower than plain. The kernel is using the `rfc4106-gcm-aesni-avx` driver, so it isn't missing AES-NI. **I have not profiled where the time goes.**

### 2. The MTU black hole

The WAN link r↔w has MTU 1400; a and b both still have 1500. Each row is 3 × 5 s of iperf3.

| overlay | ICMP frag-needed at r | 56-byte ping | TCP Gbit/s | ICMP sent by r / dropped by filter |
|---|---|---|---|---|
| none | allowed | ok | 3.34 | 1 / 0 |
| none | **dropped** | ok | **0, stalled** | 50 / 50 |
| VXLAN, outer DF set | allowed | ok | 2.58 | 1 / 0 |
| VXLAN, outer DF set | **dropped** | ok | **0, stalled** | 50 / 50 |
| ↳ fix: `vx0 mtu 1350` | dropped | ok | 2.65 | 0 / 0 |
| ↳ fix: outer DF off (Linux default) | dropped | ok | 1.82 | 0 / 0 |
| GRE (DF always set) | allowed | ok | 3.46 | 1 / 0 |
| GRE | **dropped** | ok | **0, stalled** | 50 / 50 |
| ↳ fix: `gre1 mtu 1376` | dropped | ok | 3.17 | 0 / 0 |
| IPsec ESP | allowed | ok | 0.75 | 1 / 0 |
| IPsec ESP | **dropped** | ok | **0, stalled** | 48 / 48 |

The symptom looks the same for every tunnel: small packets, including the TCP handshake, get through, and bulk data never does. Allowing a single ICMP message is enough for PMTU discovery to fix it. Sizing the tunnel MTU for the real path fixes it without any ICMP. Letting the router fragment also works, but at about 0.7× the throughput of the MTU fix.

How I'd diagnose this: `ping -M do -s <size>` to binary-search the path MTU, then compare the router's `OutDestUnreachs` counter with the firewall's drop counter.

### 3. The checksum bug: TCP stalled through my VTEP while ping worked

The first time I ran iperf3 through `vxlan_tun`, ping worked, but TCP never got past the handshake.

**Cause.** b's kernel leaves the inner TCP checksum for the NIC to fill in (`CHECKSUM_PARTIAL`), because `vx0` advertises TX checksum offload. A veth never serialises the packet, so nobody ever fills it in. When the receiver is the kernel's VXLAN, the skb's checksum state crosses the veth with the packet and the kernel never checks it. My VTEP reads plain bytes from a UDP socket and writes them to a TAP, so a's TCP sees a bad checksum on every segment and drops it. ICMP checksums are always computed in software, which is why ping worked.

Scapy checked inner TCP checksums on packets going b → a at r:

| b → a | receiver at a | inner TCP segments | bad checksum | TCP |
|---|---|---:|---:|---|
| kernel VXLAN → kernel VXLAN | kernel | 91 | **91** | works: the kernel never checks |
| kernel VXLAN → `vxlan_tun` | user space | 5 | 5 | **stalled** (SYN-ACK retries) |
| same, `ethtool -K vx0 tx off` on b | user space | 747 | 0 | works |

**Fix.** Turn off TX checksum offload on the sending VXLAN device. `mode_uvxlan` now does this, and `mode_uvxlan keep-offload` reproduces the bug. A user-space receiver can't repair the checksum itself, because it doesn't know where the checksum field starts or which bytes it should cover.

### 4. Correctness

- **Codec vs Scapy:** 296 checks. Encap output is byte-identical to Scapy's `VXLAN()/frame` over 10 VNIs (including 0 and 2²⁴−1) and 9 frame shapes. Decap rejects a wrong VNI, a clear I flag and every truncation from 0 to 21 bytes. Reserved bits are ignored on receive and zero on send.
- **Live interop (release and ASan/UBSan builds):** Scapy at r parses every VXLAN packet in both directions (mine a→b, the kernel's b→a) and requires flags 0x08, VNI 42 and zero reserved fields. A 1422-byte DF ping (full 1450 MTU) passes and 1423 is refused. Four injected bad packets (wrong VNI, I flag clear, truncated, spoofed peer) each increment exactly one drop counter.
- **IKEv2:** `results/wsl/ike_sas.txt` shows the negotiated SA (`AES_GCM_16-128/PRF_HMAC_SHA2_256/CURVE_25519`) and the kernel XFRM states strongSwan installed.

## Running it

```bash
cmake -S . -B build && cmake --build build
python3 -m venv .venv && .venv/bin/pip install scapy
.venv/bin/python tests/test_codec.py build/vxlan_codec
sudo scripts/run.sh scripts/smoke.sh          # all six overlays ping
sudo PY=$PWD/.venv/bin/python scripts/run.sh tests/test_live.sh
sudo scripts/run.sh scripts/bench.sh          # results/bench.csv
sudo scripts/run.sh scripts/blackhole.sh      # results/blackhole.csv
sudo PY=$PWD/.venv/bin/python scripts/run.sh scripts/csum.sh
python3 tools/report.py results
```

Needs `iproute2`, `ethtool`, `iperf3`, `strongswan-charon`, `strongswan-swanctl` and `libstrongswan-standard-plugins`. On Ubuntu, unload the AppArmor profiles for charon and swanctl (see `.github/workflows/ci.yml`), because the lab keeps its configs under `/tmp`.

### Running without sudo

`scripts/run.sh` uses `unshare --user --map-root-user --net --mount` when you aren't root. The lab's root is confined to namespaces the lab created and never touches the host network.

If strongSwan and iperf3 can't be installed, unpack their .debs with `dpkg -x` and set `OL_DEPS=<that dir>`. charon has `/usr/lib/ipsec` compiled in, so `run.sh` mounts a tmpfs of symlinks over `/usr/lib` inside the mount namespace and adds the extra `ipsec` entry there. Unprivileged overlayfs was refused on the WSL kernel; `--rbind` works where a plain `--bind` doesn't.

## Not covered

- IPv6 underlay, VXLAN flood-and-learn / FDB, multicast, and NAT-T (ESP never crosses a NAT here). IKE uses PSK only, not certificates. There's no rekey test.
- No physical NICs: every link is a veth, so offload behaviour is veth behaviour. Section 3 exists because of exactly that.
- The ESP slowdown is measured but not profiled.

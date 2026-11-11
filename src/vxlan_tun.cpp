// A user-space VXLAN tunnel endpoint (VTEP).
//
// It bridges a TAP device and a UDP socket on port 4789:
//   TAP -> add the VXLAN header -> UDP to the remote VTEP
//   UDP -> check flags and VNI, strip the header -> TAP
//
// It is point-to-point only: one remote, no flood-and-learn and no FDB.
// That is enough to interoperate with a Linux kernel `vxlan` device
// configured with a single `remote`.
//
//   vxlan_tun --tap uvx0 --local 10.0.1.1 --remote 10.0.2.1 --vni 42 [--mtu 1450]
//
// SIGINT/SIGTERM prints the counters as one JSON line on stdout and exits.
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "vxlan.hpp"

namespace {

volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

struct Counters {
    unsigned long tx_frames = 0, tx_bytes = 0, tx_errors = 0, tx_emsgsize = 0;
    unsigned long rx_frames = 0, rx_bytes = 0, rx_too_short = 0, rx_no_i_flag = 0,
                  rx_wrong_vni = 0, rx_wrong_peer = 0;
};

[[noreturn]] void die(const char* what) {
    std::fprintf(stderr, "vxlan_tun: %s: %s\n", what, std::strerror(errno));
    std::exit(1);
}

int open_tap(const std::string& name, int mtu) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) die("open /dev/net/tun");
    ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;  // raw Ethernet frames, no 4-byte packet-info prefix
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) die("TUNSETIFF");

    // Set the MTU on the TAP. A TAP starts at 1500, but each frame grows by
    // 50 bytes on the wire, so the default would push 1550-byte packets into
    // a 1500-byte underlay.
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) die("socket");
    ifreq m{};
    std::strncpy(m.ifr_name, name.c_str(), IFNAMSIZ - 1);
    m.ifr_mtu = mtu;
    if (ioctl(s, SIOCSIFMTU, &m) < 0) die("SIOCSIFMTU");
    close(s);
    return fd;
}

void print_counters(const Counters& c) {
    std::printf(
        "{\"tx_frames\":%lu,\"tx_bytes\":%lu,\"tx_errors\":%lu,\"tx_emsgsize\":%lu,"
        "\"rx_frames\":%lu,\"rx_bytes\":%lu,\"rx_too_short\":%lu,\"rx_no_i_flag\":%lu,"
        "\"rx_wrong_vni\":%lu,\"rx_wrong_peer\":%lu}\n",
        c.tx_frames, c.tx_bytes, c.tx_errors, c.tx_emsgsize, c.rx_frames, c.rx_bytes,
        c.rx_too_short, c.rx_no_i_flag, c.rx_wrong_vni, c.rx_wrong_peer);
    std::fflush(stdout);
}

}  // namespace

int main(int argc, char** argv) {
    std::string tap = "uvx0", local, remote;
    unsigned long vni = 42;
    int port = 4789, mtu = 1500 - static_cast<int>(vxlan::kIpv4Overhead);
    for (int i = 1; i + 1 < argc; i += 2) {
        std::string k = argv[i], v = argv[i + 1];
        if (k == "--tap") tap = v;
        else if (k == "--local") local = v;
        else if (k == "--remote") remote = v;
        else if (k == "--vni") vni = std::strtoul(v.c_str(), nullptr, 0);
        else if (k == "--port") port = std::atoi(v.c_str());
        else if (k == "--mtu") mtu = std::atoi(v.c_str());
        else { std::fprintf(stderr, "unknown option %s\n", k.c_str()); return 1; }
    }
    if (local.empty() || remote.empty() || vni > vxlan::kMaxVni) {
        std::fprintf(stderr, "usage: %s --local IP --remote IP [--tap NAME] [--vni N] [--port P] [--mtu M]\n", argv[0]);
        return 1;
    }

    int tfd = open_tap(tap, mtu);

    int ufd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (ufd < 0) die("socket");
    sockaddr_in la{}, ra{};
    la.sin_family = ra.sin_family = AF_INET;
    la.sin_port = ra.sin_port = htons(static_cast<std::uint16_t>(port));
    if (inet_pton(AF_INET, local.c_str(), &la.sin_addr) != 1) { std::fprintf(stderr, "bad --local\n"); return 1; }
    if (inet_pton(AF_INET, remote.c_str(), &ra.sin_addr) != 1) { std::fprintf(stderr, "bad --remote\n"); return 1; }
    if (bind(ufd, reinterpret_cast<sockaddr*>(&la), sizeof la) < 0) die("bind");
    int big = 4 << 20;
    setsockopt(ufd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    setsockopt(ufd, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);

    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    std::fprintf(stderr, "vxlan_tun: %s mtu %d, %s:%d -> %s:%d, vni %lu\n", tap.c_str(), mtu,
                 local.c_str(), port, remote.c_str(), port, vni);

    Counters c;
    // 64 KiB covers any frame the TAP can hand us at MTU <= 9000.
    static std::uint8_t frame[65536], dgram[65536 + vxlan::kHeaderLen];
    pollfd pf[2] = {{tfd, POLLIN, 0}, {ufd, POLLIN, 0}};

    while (!g_stop) {
        int n = poll(pf, 2, 200);
        if (n < 0) {
            if (errno == EINTR) continue;
            die("poll");
        }
        if (pf[0].revents & POLLIN) {
            ssize_t len = read(tfd, frame, sizeof frame);
            if (len > 0) {
                std::size_t out = vxlan::encap(static_cast<std::uint32_t>(vni), frame,
                                               static_cast<std::size_t>(len), dgram);
                ssize_t s = sendto(ufd, dgram, out, 0, reinterpret_cast<sockaddr*>(&ra), sizeof ra);
                if (s < 0) {
                    if (errno == EMSGSIZE) ++c.tx_emsgsize;
                    else ++c.tx_errors;
                } else {
                    ++c.tx_frames;
                    c.tx_bytes += static_cast<unsigned long>(len);
                }
            }
        }
        if (pf[1].revents & POLLIN) {
            sockaddr_in from{};
            socklen_t fl = sizeof from;
            ssize_t len = recvfrom(ufd, dgram, sizeof dgram, 0, reinterpret_cast<sockaddr*>(&from), &fl);
            if (len > 0) {
                if (from.sin_addr.s_addr != ra.sin_addr.s_addr) {
                    ++c.rx_wrong_peer;  // only the configured VTEP may inject frames
                    continue;
                }
                const std::uint8_t* inner = nullptr;
                std::size_t inner_len = 0;
                switch (vxlan::decap(dgram, static_cast<std::size_t>(len), static_cast<std::uint32_t>(vni),
                                     &inner, &inner_len)) {
                    case vxlan::Decap::Ok:
                        if (write(tfd, inner, inner_len) == static_cast<ssize_t>(inner_len)) {
                            ++c.rx_frames;
                            c.rx_bytes += inner_len;
                        }
                        break;
                    case vxlan::Decap::TooShort: ++c.rx_too_short; break;
                    case vxlan::Decap::NoIFlag: ++c.rx_no_i_flag; break;
                    case vxlan::Decap::WrongVni: ++c.rx_wrong_vni; break;
                }
            }
        }
    }
    print_counters(c);
    return 0;
}

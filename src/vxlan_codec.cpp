// Stdin/stdout wrapper around vxlan.hpp so Scapy can test the codec directly.
//   vxlan_codec encap <vni>   raw Ethernet frame on stdin -> VXLAN payload on stdout
//   vxlan_codec decap <vni>   VXLAN payload on stdin -> inner frame on stdout
// decap exits 0 on success; otherwise it exits 2 and prints the reason on stderr.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "vxlan.hpp"

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s encap|decap <vni>\n", argv[0]);
        return 1;
    }
    std::string mode = argv[1];
    unsigned long vni = std::strtoul(argv[2], nullptr, 0);
    if (vni > vxlan::kMaxVni) {
        std::fprintf(stderr, "vni out of range\n");
        return 1;
    }
    std::freopen(nullptr, "rb", stdin);
    std::freopen(nullptr, "wb", stdout);
    std::vector<std::uint8_t> in((std::istreambuf_iterator<char>(std::cin)),
                                 std::istreambuf_iterator<char>());
    if (mode == "encap") {
        std::vector<std::uint8_t> out(vxlan::kHeaderLen + in.size());
        std::size_t n = vxlan::encap(static_cast<std::uint32_t>(vni), in.data(), in.size(), out.data());
        std::fwrite(out.data(), 1, n, stdout);
        return 0;
    }
    if (mode == "decap") {
        const std::uint8_t* inner = nullptr;
        std::size_t inner_len = 0;
        auto r = vxlan::decap(in.data(), in.size(), static_cast<std::uint32_t>(vni), &inner, &inner_len);
        if (r != vxlan::Decap::Ok) {
            std::fprintf(stderr, "%s\n", vxlan::to_string(r));
            return 2;
        }
        std::fwrite(inner, 1, inner_len, stdout);
        return 0;
    }
    std::fprintf(stderr, "unknown mode %s\n", mode.c_str());
    return 1;
}

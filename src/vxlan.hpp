// VXLAN header codec (RFC 7348, section 5).
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |R|R|R|R|I|R|R|R|            Reserved                           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                VXLAN Network Identifier (VNI) |   Reserved    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// The header sits inside a UDP datagram (dst port 4789) and is followed by
// the full inner Ethernet frame, without its FCS.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace vxlan {

constexpr std::size_t kHeaderLen = 8;
constexpr std::size_t kMinInnerFrame = 14;      // an Ethernet header, nothing else
constexpr std::uint8_t kFlagI = 0x08;           // "VNI is valid"
constexpr std::uint32_t kMaxVni = (1u << 24) - 1;

// Outer bytes added to every inner frame on an IPv4 underlay:
// outer IP (20) + UDP (8) + VXLAN (8) + inner Ethernet header (14) = 50.
// That is why a VXLAN device on a 1500-byte link gets MTU 1450.
constexpr std::size_t kIpv4Overhead = 20 + 8 + kHeaderLen + 14;

inline void write_header(std::uint8_t* out, std::uint32_t vni) {
    out[0] = kFlagI;
    out[1] = out[2] = out[3] = 0;
    out[4] = static_cast<std::uint8_t>(vni >> 16);
    out[5] = static_cast<std::uint8_t>(vni >> 8);
    out[6] = static_cast<std::uint8_t>(vni);
    out[7] = 0;
}

// Encapsulate: out must hold kHeaderLen + frame_len bytes. Returns bytes written.
inline std::size_t encap(std::uint32_t vni, const std::uint8_t* frame, std::size_t frame_len,
                         std::uint8_t* out) {
    write_header(out, vni);
    std::memcpy(out + kHeaderLen, frame, frame_len);
    return kHeaderLen + frame_len;
}

enum class Decap { Ok, TooShort, NoIFlag, WrongVni };

inline const char* to_string(Decap d) {
    switch (d) {
        case Decap::Ok: return "ok";
        case Decap::TooShort: return "too_short";
        case Decap::NoIFlag: return "no_i_flag";
        case Decap::WrongVni: return "wrong_vni";
    }
    return "?";
}

// Decapsulate one UDP payload. On Ok, *inner / *inner_len point into buf.
// Reserved bits are ignored on receive, as RFC 7348 requires.
inline Decap decap(const std::uint8_t* buf, std::size_t len, std::uint32_t want_vni,
                   const std::uint8_t** inner, std::size_t* inner_len) {
    if (len < kHeaderLen + kMinInnerFrame) return Decap::TooShort;
    if (!(buf[0] & kFlagI)) return Decap::NoIFlag;
    std::uint32_t vni = (std::uint32_t(buf[4]) << 16) | (std::uint32_t(buf[5]) << 8) | buf[6];
    if (vni != want_vni) return Decap::WrongVni;
    *inner = buf + kHeaderLen;
    *inner_len = len - kHeaderLen;
    return Decap::Ok;
}

}  // namespace vxlan

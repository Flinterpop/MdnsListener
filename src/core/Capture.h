// Reads the mDNS datagrams out of a capture file: classic pcap (either byte
// order, microsecond or nanosecond timestamps) and pcapng (any number of
// sections and interfaces, each with its own timestamp resolution).
//
// Link layers: Ethernet (up to two VLAN tags), BSD null/loopback, raw IP,
// Linux cooked (SLL and SLL2). Kept: unfragmented IPv4 or IPv6 UDP to or
// from port 5353. Everything else is counted and skipped.
#pragma once

#include "Listener.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mdns {

struct CaptureResult {
    std::string format;             // "pcap" or "pcapng"
    std::vector<Packet> packets;    // the mDNS datagrams, in file order
    uint64_t frames = 0;            // every packet record in the file
    uint64_t notMdns = 0;           // not UDP port 5353, or not IP at all
    uint64_t fragments = 0;         // IP fragments, which are not reassembled
    uint64_t unsupportedLink = 0;   // frames on a link type this reader does not know
    uint64_t overLimit = 0;         // mDNS datagrams past `maxPackets`
    std::string warning;            // the file ended early or a block was bad
};

constexpr size_t kMaxCaptureBytes = size_t{1} << 30;   // 1 GiB
constexpr uint64_t kMaxCaptureFrames = 50000000;

// Parses a capture held in memory. Returns false, with `error` set, when the
// data is not a capture at all; a capture that is damaged part way through
// returns true with what came before the damage and `warning` set.
bool ReadCapture(const uint8_t* data, size_t size, size_t maxPackets, CaptureResult& out, std::string& error);

// Reads a whole file (up to kMaxCaptureBytes) and parses it.
bool ReadCaptureFile(const std::wstring& path, size_t maxPackets, CaptureResult& out, std::string& error);

} // namespace mdns

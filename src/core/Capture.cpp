#include "Capture.h"

#include <windows.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cassert>

namespace mdns {
namespace {

constexpr uint16_t kMdnsPort = 5353;
constexpr uint64_t kUnixEpochTicks = 116444736000000000ull;   // 1970-01-01 as FILETIME
constexpr uint64_t kTicksPerSecond = 10000000ull;
constexpr uint64_t kMaxUnixSeconds = 32503680000ull;          // year 3000: past it, a time is garbage
constexpr size_t kMaxInterfaces = 1024;                         // per pcapng section
constexpr int kMaxOptions = 256;                                // per pcapng block
constexpr int kMaxExtensionHeaders = 8;
constexpr uint32_t kShb = 0x0A0D0D0Au;

uint16_t Get16(const uint8_t* p, bool be)
{
    assert(p != nullptr);
    return be ? static_cast<uint16_t>((p[0] << 8) | p[1]) : static_cast<uint16_t>((p[1] << 8) | p[0]);
}

uint32_t Get32(const uint8_t* p, bool be)
{
    assert(p != nullptr);
    const uint32_t a = p[0], b = p[1], c = p[2], d = p[3];
    return be ? (a << 24) | (b << 16) | (c << 8) | d : (d << 24) | (c << 16) | (b << 8) | a;
}

uint64_t Get64(const uint8_t* p, bool be)
{
    assert(p != nullptr);
    const uint64_t first = Get32(p, be), second = Get32(p + 4, be);
    return be ? (first << 32) | second : (second << 32) | first;
}

uint16_t Be16(const uint8_t* p) { return Get16(p, true); }

// Seconds and a fraction in `unitsPerSecond` since 1970, to FILETIME ticks;
// 0 when the time is implausible.
uint64_t ToTicks(uint64_t seconds, uint64_t fraction, uint64_t unitsPerSecond)
{
    assert(unitsPerSecond > 0);
    if (seconds > kMaxUnixSeconds || fraction >= unitsPerSecond) {
        return 0;
    }
    const uint64_t frac = (unitsPerSecond <= 1000000000000ull)
                              ? fraction * kTicksPerSecond / unitsPerSecond
                              : fraction / (unitsPerSecond / kTicksPerSecond);
    assert(frac < kTicksPerSecond);
    return kUnixEpochTicks + seconds * kTicksPerSecond + frac;
}

struct Frame {
    const uint8_t* data = nullptr;
    size_t size = 0;            // captured bytes
    uint32_t link = 0;
    uint64_t time = 0;
    uint32_t ifIndex = 0;
    const std::string* ifName = nullptr;
};

enum class Verdict { Kept, NotMdns, Fragment, UnknownLink };

// Where the IP header starts in a frame of link type `link`, and which IP
// version it is (0 when the frame carries something else).
bool LinkPayload(uint32_t link, const uint8_t* f, size_t n, size_t& off, int& version)
{
    assert(f != nullptr || n == 0);
    off = 0;
    version = 0;
    auto byType = [](uint16_t t) { return t == 0x0800 ? 4 : (t == 0x86DD ? 6 : 0); };
    auto byFamily = [](uint32_t fam) { return fam == 2 ? 4 : ((fam == 24 || fam == 28 || fam == 30) ? 6 : 0); };
    switch (link) {
    case 1: {   // Ethernet
        if (n < 14) {
            return true;
        }
        uint16_t type = Be16(f + 12);
        off = 14;
        for (int i = 0; i < 2 && (type == 0x8100 || type == 0x88A8 || type == 0x9100) && off + 4 <= n; ++i) {
            type = Be16(f + off + 2);
            off += 4;
        }
        version = byType(type);
        return true;
    }
    case 0:     // BSD null: the family in the capturing host's byte order
    case 108:   // OpenBSD loop: the family in network order
        if (n >= 4) {
            const uint32_t le = Get32(f, false);
            version = byFamily(link == 108 ? Get32(f, true) : (le > 0xFFFF ? Get32(f, true) : le));
            off = 4;
        }
        return true;
    case 12: case 14: case 101:   // raw IP
        version = n > 0 ? (f[0] >> 4) : 0;
        return true;
    case 228: version = 4; return true;
    case 229: version = 6; return true;
    case 113:   // Linux cooked v1
        if (n >= 16) {
            version = byType(Be16(f + 14));
            off = 16;
        }
        return true;
    case 276:   // Linux cooked v2
        if (n >= 20) {
            version = byType(Be16(f));
            off = 20;
        }
        return true;
    default: return false;
    }
}

std::string Address(int family, const uint8_t* bytes)
{
    assert(bytes != nullptr);
    char buf[INET6_ADDRSTRLEN] = {};
    return inet_ntop(family, bytes, buf, sizeof(buf)) != nullptr ? std::string(buf) : std::string("?");
}

struct IpView {
    size_t udp = 0;         // offset of the UDP header
    size_t end = 0;         // end of the IP datagram, within the captured bytes
    bool ipv6 = false;
    std::string source, destination;
};

Verdict ParseIpv4(const uint8_t* f, size_t n, size_t off, IpView& ip)
{
    assert(f != nullptr && off <= n);
    const uint8_t* h = f + off;
    const size_t avail = n - off;
    if (avail < 20 || (h[0] >> 4) != 4) {
        return Verdict::NotMdns;
    }
    const size_t ihl = static_cast<size_t>(h[0] & 0x0F) * 4;
    const size_t total = Be16(h + 2);
    if (ihl < 20 || ihl > avail || total < ihl) {
        return Verdict::NotMdns;
    }
    if ((Be16(h + 6) & 0x3FFF) != 0) {   // more fragments, or an offset
        return Verdict::Fragment;
    }
    if (h[9] != 17) {
        return Verdict::NotMdns;
    }
    ip.udp = off + ihl;
    ip.end = off + std::min(total, avail);
    assert(ip.udp <= ip.end && ip.end <= n);   // ihl <= total and ihl <= avail
    ip.ipv6 = false;
    ip.source = Address(AF_INET, h + 12);
    ip.destination = Address(AF_INET, h + 16);
    return Verdict::Kept;
}

Verdict ParseIpv6(const uint8_t* f, size_t n, size_t off, IpView& ip)
{
    assert(f != nullptr && off <= n);
    const uint8_t* h = f + off;
    const size_t avail = n - off;
    if (avail < 40 || (h[0] >> 4) != 6) {
        return Verdict::NotMdns;
    }
    const size_t end = off + 40 + std::min(static_cast<size_t>(Be16(h + 4)), avail - 40);
    uint8_t next = h[6];
    size_t p = off + 40;
    for (int i = 0; i < kMaxExtensionHeaders; ++i) {
        if ((next == 0 || next == 43 || next == 60) && p + 2 <= end) {
            const size_t len = (static_cast<size_t>(f[p + 1]) + 1) * 8;
            next = f[p];
            p += len;
        } else if (next == 44 && p + 8 <= end) {
            if ((Be16(f + p + 2) & 0xFFF9) != 0) {   // an offset, or more fragments
                return Verdict::Fragment;
            }
            next = f[p];
            p += 8;
        } else {
            break;
        }
    }
    if (next != 17 || p > end) {
        return Verdict::NotMdns;
    }
    ip.udp = p;
    ip.end = end;
    assert(ip.udp <= ip.end && ip.end <= n);
    ip.ipv6 = true;
    ip.source = Address(AF_INET6, h + 8);
    ip.destination = Address(AF_INET6, h + 24);
    return Verdict::Kept;
}

Verdict Extract(const Frame& fr, Packet& pkt)
{
    size_t off = 0;
    int version = 0;
    if (!LinkPayload(fr.link, fr.data, fr.size, off, version)) {
        return Verdict::UnknownLink;
    }
    assert(off <= fr.size);   // a link header is only skipped when it fits
    IpView ip;
    const Verdict v = version == 4   ? ParseIpv4(fr.data, fr.size, off, ip)
                      : version == 6 ? ParseIpv6(fr.data, fr.size, off, ip)
                                     : Verdict::NotMdns;
    if (v != Verdict::Kept) {
        return v;
    }
    assert(ip.end <= fr.size);
    if (ip.udp + 8 > ip.end) {
        return Verdict::NotMdns;
    }
    const uint8_t* u = fr.data + ip.udp;
    const uint16_t sport = Be16(u), dport = Be16(u + 2);
    const size_t ulen = Be16(u + 4);
    if ((sport != kMdnsPort && dport != kMdnsPort) || ulen < 8) {
        return Verdict::NotMdns;
    }
    const size_t want = ulen - 8;
    const size_t have = std::min(want, ip.end - ip.udp - 8);
    assert(ip.udp + 8 + have <= fr.size);
    pkt.time = fr.time;
    pkt.ipv6 = ip.ipv6;
    pkt.source = std::move(ip.source);
    pkt.sourcePort = sport;
    pkt.destination = std::move(ip.destination);
    pkt.ifIndex = fr.ifIndex;
    pkt.ifName = (fr.ifName != nullptr) ? *fr.ifName : std::string();
    pkt.truncated = have < want;
    pkt.data.assign(u + 8, u + 8 + have);
    return Verdict::Kept;
}

void Account(const Frame& fr, size_t maxPackets, CaptureResult& out)
{
    assert(fr.data != nullptr || fr.size == 0);
    assert(out.packets.size() <= maxPackets);
    ++out.frames;
    Packet pkt;
    switch (Extract(fr, pkt)) {
    case Verdict::Kept:
        if (out.packets.size() < maxPackets) {
            out.packets.push_back(std::move(pkt));
        } else {
            ++out.overLimit;
        }
        break;
    case Verdict::Fragment: ++out.fragments; break;
    case Verdict::UnknownLink: ++out.unsupportedLink; break;
    default: ++out.notMdns; break;
    }
}

// --------------------------------------------------------------------------
// Classic pcap
// --------------------------------------------------------------------------

bool ReadPcap(const uint8_t* d, size_t n, size_t maxPackets, CaptureResult& out, std::string& error)
{
    assert(d != nullptr && n >= 4);   // ReadCapture has seen the magic
    const uint32_t magic = Get32(d, false);
    const bool be = (magic == 0xD4C3B2A1u || magic == 0x4D3CB2A1u);
    const bool nano = (magic == 0xA1B23C4Du || magic == 0x4D3CB2A1u);
    if (n < 24) {
        error = "The pcap file header is cut short.";
        return false;
    }
    out.format = nano ? "pcap (nanosecond)" : "pcap";
    static const std::string kName = "capture";
    Frame fr;
    fr.link = Get32(d + 20, be) & 0xFFFFu;   // the upper bits carry FCS flags
    fr.ifName = &kName;
    size_t off = 24;
    while (off < n && out.frames < kMaxCaptureFrames) {
        if (n - off < 16) {
            out.warning = "The file ends part way through a packet header.";
            break;
        }
        const uint32_t sec = Get32(d + off, be);
        const uint32_t frac = Get32(d + off + 4, be);
        const size_t incl = Get32(d + off + 8, be);
        if (incl > n - off - 16) {
            out.warning = "The file ends part way through packet " + std::to_string(out.frames + 1) + ".";
            break;
        }
        fr.time = ToTicks(sec, frac, nano ? 1000000000ull : 1000000ull);
        fr.data = d + off + 16;
        fr.size = incl;
        Account(fr, maxPackets, out);
        off += 16 + incl;
    }
    assert(off <= n);   // each record was checked to fit before it was stepped over
    return true;
}

// --------------------------------------------------------------------------
// pcapng
// --------------------------------------------------------------------------

struct Interface {
    uint32_t link = 0;
    uint64_t unitsPerSecond = 1000000;
    int64_t offsetSeconds = 0;
    std::string name;
};

uint64_t Resolution(uint8_t r)
{
    const int exp = r & 0x7F;
    if ((r & 0x80) != 0) {
        return uint64_t{1} << std::min(exp, 63);
    }
    uint64_t u = 1;
    for (int i = 0; i < std::min(exp, 19); ++i) {
        u *= 10;
    }
    assert(u >= 1);   // 10^19 still fits, so it never wraps to 0 (NgTime divides by it)
    return u;
}

Interface ReadIdb(const uint8_t* body, size_t len, bool be, uint32_t index)
{
    assert(body != nullptr && len >= 8);
    Interface ifc;
    std::string description;
    ifc.link = Get16(body, be);
    size_t p = 8;
    for (int i = 0; i < kMaxOptions && p + 4 <= len; ++i) {
        const uint16_t code = Get16(body + p, be);
        const size_t olen = Get16(body + p + 2, be);
        p += 4;
        if (code == 0 || olen > len - p) {
            break;
        }
        if (code == 2 || code == 3) {   // if_name, if_description
            std::string s(reinterpret_cast<const char*>(body + p), olen);
            s.resize(std::min(s.find('\0'), s.size()));
            (code == 2 ? ifc.name : description).swap(s);
        } else if (code == 9 && olen >= 1) {
            ifc.unitsPerSecond = Resolution(body[p]);
        } else if (code == 14 && olen >= 8) {
            ifc.offsetSeconds = static_cast<int64_t>(Get64(body + p, be));
        }
        p += (olen + 3) & ~size_t{3};
        assert(p <= len + 3);   // olen fitted, and padding adds at most 3
    }
    // dumpcap's if_name is a device path ("\Device\NPF_{...}") and its
    // description the adapter's own name, which is the one people know.
    if (!description.empty()) {
        ifc.name.swap(description);
    }
    if (ifc.name.empty()) {
        ifc.name = "interface " + std::to_string(index);
    }
    return ifc;
}

uint64_t NgTime(const Interface& ifc, uint32_t high, uint32_t low)
{
    assert(ifc.unitsPerSecond > 0);
    const uint64_t ts = (uint64_t{high} << 32) | low;
    const uint64_t sec = ts / ifc.unitsPerSecond;
    const int64_t shifted = static_cast<int64_t>(std::min(sec, kMaxUnixSeconds + 1)) + ifc.offsetSeconds;
    if (shifted < 0) {
        return 0;
    }
    return ToTicks(static_cast<uint64_t>(shifted), ts % ifc.unitsPerSecond, ifc.unitsPerSecond);
}

// One packet block (enhanced, simple or the obsolete one) into `out`.
void ReadPacketBlock(uint32_t type, const uint8_t* body, size_t len, bool be,
                     const std::vector<Interface>& ifs, size_t maxPackets, CaptureResult& out)
{
    assert(type == 2 || type == 3 || type == 6);
    assert(body != nullptr);
    const size_t head = (type == 3) ? 4 : 20;
    if (len < head) {
        out.warning = "A packet block is shorter than its header.";
        return;
    }
    const uint32_t id = (type == 6) ? Get32(body, be) : (type == 2 ? Get16(body, be) : 0);
    const size_t cap = (type == 3) ? std::min(static_cast<size_t>(Get32(body, be)), len - 4)
                                   : static_cast<size_t>(Get32(body + 12, be));
    if (id >= ifs.size() || cap > len - head) {
        ++out.frames;
        ++out.unsupportedLink;
        out.warning = "A packet names an interface the file never declared, or overruns its block.";
        return;
    }
    Frame fr;
    fr.link = ifs[id].link;
    fr.time = (type == 3) ? 0 : NgTime(ifs[id], Get32(body + 4, be), Get32(body + 8, be));
    fr.ifIndex = id;
    fr.ifName = &ifs[id].name;
    fr.data = body + head;
    fr.size = cap;
    Account(fr, maxPackets, out);
}

bool ReadPcapng(const uint8_t* d, size_t n, size_t maxPackets, CaptureResult& out, std::string& error)
{
    assert(d != nullptr && n >= 4);   // ReadCapture has seen the magic
    out.format = "pcapng";
    std::vector<Interface> ifs;
    bool be = false;
    size_t off = 0;
    for (uint64_t blocks = 0; off < n && blocks < 2 * kMaxCaptureFrames; ++blocks) {
        if (n - off < 12) {
            out.warning = "The file ends part way through a block.";
            break;
        }
        const uint32_t type = Get32(d + off, be);
        if (type == kShb) {
            const uint32_t bom = Get32(d + off + 8, false);
            if (bom != 0x1A2B3C4Du && bom != 0x4D3C2B1Au) {
                error = "A pcapng section header has no byte-order magic.";
                return blocks > 0;
            }
            be = (bom == 0x4D3C2B1Au);
            ifs.clear();
        }
        const size_t len = Get32(d + off + 4, be);
        if (len < 12 || len % 4 != 0 || len > n - off || Get32(d + off + len - 4, be) != len) {
            out.warning = "A block's length is damaged; the rest of the file was not read.";
            break;
        }
        const uint8_t* body = d + off + 8;
        const size_t blen = len - 12;
        if (type == 1 && blen >= 8 && ifs.size() < kMaxInterfaces) {
            ifs.push_back(ReadIdb(body, blen, be, static_cast<uint32_t>(ifs.size())));
        } else if ((type == 2 || type == 3 || type == 6) && out.frames < kMaxCaptureFrames) {
            ReadPacketBlock(type, body, blen, be, ifs, maxPackets, out);
        }
        off += len;
    }
    assert(off <= n && ifs.size() <= kMaxInterfaces);
    return true;
}

} // namespace

bool ReadCapture(const uint8_t* data, size_t size, size_t maxPackets, CaptureResult& out, std::string& error)
{
    out = CaptureResult{};
    error.clear();
    if (data == nullptr || size < 4) {
        error = "The file is too short to be a capture.";
        return false;
    }
    if (size > kMaxCaptureBytes) {
        error = "The capture is larger than 1 GiB.";
        return false;
    }
    const uint32_t magic = Get32(data, false);
    bool ok = false;
    if (magic == kShb) {
        ok = ReadPcapng(data, size, maxPackets, out, error);
    } else if (magic == 0xA1B2C3D4u || magic == 0xD4C3B2A1u || magic == 0xA1B23C4Du || magic == 0x4D3CB2A1u) {
        ok = ReadPcap(data, size, maxPackets, out, error);
    } else {
        error = "This is not a pcap or pcapng file.";
    }
    assert(out.packets.size() <= maxPackets);
    assert(ok || !error.empty());   // a refusal always says why
    return ok;
}

bool ReadCaptureFile(const std::wstring& path, size_t maxPackets, CaptureResult& out, std::string& error)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = "The file could not be opened (error " + std::to_string(GetLastError()) + ").";
        return false;
    }
    LARGE_INTEGER size{};
    std::vector<uint8_t> buf;
    bool ok = GetFileSizeEx(h, &size) != 0;
    bool partial = false;
    if (ok && static_cast<uint64_t>(size.QuadPart) > kMaxCaptureBytes) {
        error = "The capture is larger than 1 GiB.";
        ok = false;
    } else if (ok) {
        buf.resize(static_cast<size_t>(size.QuadPart));
        size_t got = 0;
        for (int i = 0; i < 1024 && got < buf.size(); ++i) {   // 64 MiB reads: 1 GiB takes 16, short reads more
            DWORD n = 0;
            const DWORD want = static_cast<DWORD>(std::min<size_t>(buf.size() - got, 64u << 20));
            if (!ReadFile(h, buf.data() + got, want, &n, nullptr) || n == 0) {
                break;
            }
            got += n;
            assert(got <= buf.size());
        }
        partial = got < buf.size();
        buf.resize(got);
    }
    (void)CloseHandle(h);   // read-only: nothing is lost if closing fails
    if (!ok) {
        if (error.empty()) {
            error = "The file's size could not be read.";
        }
        return false;
    }
    const bool read = ReadCapture(buf.data(), buf.size(), maxPackets, out, error);
    if (read && partial && out.warning.empty()) {
        out.warning = "Only part of the file could be read.";
    }
    return read;
}

} // namespace mdns

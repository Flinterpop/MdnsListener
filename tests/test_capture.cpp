// Unit tests for the capture reader: classic pcap in both byte orders and
// both resolutions, pcapng with several interfaces and sections, every link
// type it claims, what it must skip, damaged files, and a fuzz pass.
// Addresses are the documentation ranges (RFC 5737, RFC 3849).
#include "Capture.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

#define CHECK(cond)                                                                 \
    do {                                                                            \
        ++g_checks;                                                                 \
        if (!(cond)) {                                                              \
            ++g_failures;                                                           \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);             \
        }                                                                           \
    } while (0)

using Bytes = std::vector<uint8_t>;

constexpr uint64_t kEpoch = 116444736000000000ull;
constexpr uint32_t kSec = 1700000000u;   // 2023-11-14 22:13:20 UTC

// Writes integers in a chosen byte order.
struct Out {
    Bytes b;
    bool be = true;
    void U8(unsigned v) { b.push_back(static_cast<uint8_t>(v)); }
    void U16(unsigned v) {
        if (be) { U8(v >> 8); U8(v & 0xFF); } else { U8(v & 0xFF); U8(v >> 8); }
    }
    void U32(uint32_t v) {
        if (be) { U16(v >> 16); U16(v & 0xFFFF); } else { U16(v & 0xFFFF); U16(v >> 16); }
    }
    void Put(const Bytes& x) { b.insert(b.end(), x.begin(), x.end()); }
    void Pad4() { while (b.size() % 4 != 0) U8(0); }
};

const Bytes kPayload = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x05, 'p', 'r', 'o', 'b', 'e', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00, 0x00, 0x01, 0x00, 0x01};

Bytes Udp(unsigned sport, unsigned dport, const Bytes& payload)
{
    Out o;
    o.U16(sport); o.U16(dport); o.U16(static_cast<unsigned>(8 + payload.size())); o.U16(0);
    o.Put(payload);
    return o.b;
}

Bytes Ipv4(const Bytes& udp, unsigned flagsOffset = 0, unsigned proto = 17)
{
    Out o;
    o.U8(0x45); o.U8(0); o.U16(static_cast<unsigned>(20 + udp.size())); o.U16(1); o.U16(flagsOffset);
    o.U8(255); o.U8(proto); o.U16(0);
    o.Put({192, 0, 2, 10});
    o.Put({224, 0, 0, 251});
    o.Put(udp);
    return o.b;
}

// IPv6 with a hop-by-hop header in front of UDP, or a fragment header.
Bytes Ipv6(const Bytes& udp, bool fragment = false)
{
    Out o;
    o.U32(0x60000000u);
    o.U16(static_cast<unsigned>(8 + udp.size()));
    o.U8(fragment ? 44 : 0);
    o.U8(255);
    o.Put({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a});
    o.Put({0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb});
    if (fragment) {
        o.U8(17); o.U8(0); o.U16(0x0001); o.U32(7);   // first fragment, more to come
    } else {
        o.U8(17); o.U8(0); o.U16(0); o.U32(0);        // hop-by-hop, 8 bytes of padding
    }
    o.Put(udp);
    return o.b;
}

Bytes Ethernet(const Bytes& ip, unsigned type, int vlans = 0)
{
    Out o;
    o.Put({0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
    for (int i = 0; i < vlans; ++i) {
        o.U16(i == 0 && vlans == 2 ? 0x88A8 : 0x8100);
        o.U16(100 + static_cast<unsigned>(i));
    }
    o.U16(type);
    o.Put(ip);
    while (o.b.size() < 60) o.U8(0);   // Ethernet padding the IP length must ignore
    return o.b;
}

Bytes PcapHeader(bool be, bool nano, uint32_t link)
{
    Out o;
    o.be = be;
    o.U32(nano ? 0xA1B23C4Du : 0xA1B2C3D4u);
    o.U16(2); o.U16(4); o.U32(0); o.U32(0); o.U32(65535); o.U32(link);
    return o.b;
}

void PcapRecord(Out& o, uint32_t sec, uint32_t frac, const Bytes& frame, size_t captured)
{
    o.U32(sec); o.U32(frac); o.U32(static_cast<uint32_t>(captured)); o.U32(static_cast<uint32_t>(frame.size()));
    o.b.insert(o.b.end(), frame.begin(), frame.begin() + static_cast<ptrdiff_t>(captured));
}

Bytes BuildPcap(bool be, bool nano)
{
    Out o;
    o.be = be;
    o.Put(PcapHeader(be, nano, 1));
    const Bytes mdns = Ethernet(Ipv4(Udp(5353, 5353, kPayload)), 0x0800);
    PcapRecord(o, kSec, nano ? 500000000u : 500000u, mdns, mdns.size());
    const Bytes dns = Ethernet(Ipv4(Udp(40000, 53, kPayload)), 0x0800);
    PcapRecord(o, kSec + 1, 0, dns, dns.size());
    const Bytes tagged = Ethernet(Ipv6(Udp(5353, 5353, kPayload)), 0x86DD, 2);
    PcapRecord(o, kSec + 2, 0, tagged, tagged.size());
    const Bytes frag = Ethernet(Ipv4(Udp(5353, 5353, kPayload), 0x2000), 0x0800);
    PcapRecord(o, kSec + 3, 0, frag, frag.size());
    const Bytes arp = Ethernet(Bytes(28, 0), 0x0806);
    PcapRecord(o, kSec + 4, 0, arp, arp.size());
    const Bytes cut = Ethernet(Ipv4(Udp(5353, 5353, kPayload)), 0x0800);
    PcapRecord(o, kSec + 5, 0, cut, 14 + 20 + 8 + 10);   // snapped inside the payload
    return o.b;
}

void TestPcap(bool be, bool nano)
{
    const Bytes file = BuildPcap(be, nano);
    mdns::CaptureResult r;
    std::string error;
    CHECK(mdns::ReadCapture(file.data(), file.size(), 1000, r, error));
    CHECK(error.empty());
    CHECK(r.warning.empty());
    CHECK(r.frames == 6);
    CHECK(r.packets.size() == 3);
    CHECK(r.notMdns == 2);
    CHECK(r.fragments == 1);
    CHECK(r.format == (nano ? "pcap (nanosecond)" : "pcap"));
    if (r.packets.size() != 3) {
        return;
    }
    const mdns::Packet& a = r.packets[0];
    CHECK(a.source == "192.0.2.10");
    CHECK(a.destination == "224.0.0.251");
    CHECK(a.sourcePort == 5353);
    CHECK(!a.ipv6);
    CHECK(a.data == kPayload);
    CHECK(!a.truncated);
    CHECK(a.time == kEpoch + uint64_t{kSec} * 10000000ull + 5000000ull);
    CHECK(a.ifName == "capture");
    const mdns::Packet& b = r.packets[1];
    CHECK(b.ipv6);
    CHECK(b.source == "2001:db8::a");
    CHECK(b.destination == "ff02::fb");
    CHECK(b.data == kPayload);
    const mdns::Packet& c = r.packets[2];
    CHECK(c.truncated);
    CHECK(c.data.size() == 10);
}

void TestPcapDamaged()
{
    Bytes file = BuildPcap(false, false);
    file.resize(file.size() - 5);   // the last record loses its tail
    mdns::CaptureResult r;
    std::string error;
    CHECK(mdns::ReadCapture(file.data(), file.size(), 1000, r, error));
    CHECK(!r.warning.empty());
    CHECK(r.frames == 5);
    CHECK(r.packets.size() == 2);

    const Bytes junk = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
    CHECK(!mdns::ReadCapture(junk.data(), junk.size(), 1000, r, error));
    CHECK(!error.empty());
    CHECK(!mdns::ReadCapture(junk.data(), 2, 1000, r, error));
    const Bytes header = PcapHeader(false, false, 1);
    CHECK(!mdns::ReadCapture(header.data(), 10, 1000, r, error));   // header cut short
    CHECK(mdns::ReadCapture(header.data(), header.size(), 1000, r, error));   // empty but valid
    CHECK(r.frames == 0 && r.warning.empty());

    // Limit: only the first `maxPackets` are kept, the rest counted.
    file = BuildPcap(false, false);
    CHECK(mdns::ReadCapture(file.data(), file.size(), 1, r, error));
    CHECK(r.packets.size() == 1 && r.overLimit == 2);
}

void TestOtherLinks()
{
    struct Case { uint32_t link; Bytes frame; bool kept; };
    const Bytes ip4 = Ipv4(Udp(5353, 5353, kPayload));
    const Bytes ip6 = Ipv6(Udp(5353, 5353, kPayload));
    Bytes nullV4 = {2, 0, 0, 0}; nullV4.insert(nullV4.end(), ip4.begin(), ip4.end());
    Bytes nullV6Be = {0, 0, 0, 30}; nullV6Be.insert(nullV6Be.end(), ip6.begin(), ip6.end());
    Bytes loopV4 = {0, 0, 0, 2}; loopV4.insert(loopV4.end(), ip4.begin(), ip4.end());
    Bytes sll(16, 0); sll[14] = 0x08; sll.insert(sll.end(), ip4.begin(), ip4.end());
    Bytes sll2(20, 0); sll2[0] = 0x86; sll2[1] = 0xDD; sll2.insert(sll2.end(), ip6.begin(), ip6.end());
    const Case cases[] = {
        {0, nullV4, true},  {0, nullV6Be, true}, {108, loopV4, true}, {101, ip4, true}, {12, ip6, true},
        {228, ip4, true},   {229, ip6, true},    {113, sll, true},    {276, sll2, true}, {105, ip4, false},
        {101, Ipv4(Udp(5353, 5353, kPayload), 0, 6), false},   // TCP
        {101, Ipv6(Udp(5353, 5353, kPayload), true), false},   // IPv6 fragment
    };
    int i = 0;
    for (const Case& c : cases) {
        Out o;
        o.be = false;
        o.Put(PcapHeader(false, false, c.link));
        PcapRecord(o, kSec, 0, c.frame, c.frame.size());
        mdns::CaptureResult r;
        std::string error;
        const bool ok = mdns::ReadCapture(o.b.data(), o.b.size(), 10, r, error);
        CHECK(ok);
        const bool kept = r.packets.size() == 1 && r.packets[0].data == kPayload;
        if (kept != c.kept) {
            std::printf("  link case %d (link type %u)\n", i, c.link);
        }
        CHECK(kept == c.kept);
        ++i;
    }
}

// pcapng: one block, with its length written at both ends.
void Block(Out& o, uint32_t type, const Bytes& body)
{
    Out pad;
    pad.Put(body);
    pad.Pad4();
    const uint32_t len = static_cast<uint32_t>(12 + pad.b.size());
    o.U32(type); o.U32(len); o.Put(pad.b); o.U32(len);
}

void Shb(Out& o)
{
    Out b;
    b.be = o.be;
    b.U32(0x1A2B3C4Du); b.U16(1); b.U16(0); b.U32(0xFFFFFFFFu); b.U32(0xFFFFFFFFu);
    Block(o, 0x0A0D0D0Au, b.b);
}

void Idb(Out& o, unsigned link, const char* name, int tsresol, const char* description = nullptr)
{
    Out b;
    b.be = o.be;
    b.U16(link); b.U16(0); b.U32(0);
    const struct { unsigned code; const char* text; } strings[] = {{2, name}, {3, description}};
    for (const auto& s : strings) {
        if (s.text != nullptr) {
            b.U16(s.code); b.U16(static_cast<unsigned>(std::strlen(s.text)));
            b.b.insert(b.b.end(), s.text, s.text + std::strlen(s.text));
            b.Pad4();
        }
    }
    if (tsresol >= 0) {
        b.U16(9); b.U16(1); b.U8(static_cast<unsigned>(tsresol)); b.Pad4();
    }
    b.U16(0); b.U16(0);
    Block(o, 1, b.b);
}

void Epb(Out& o, uint32_t ifc, uint64_t ts, const Bytes& frame)
{
    Out b;
    b.be = o.be;
    b.U32(ifc); b.U32(static_cast<uint32_t>(ts >> 32)); b.U32(static_cast<uint32_t>(ts));
    b.U32(static_cast<uint32_t>(frame.size())); b.U32(static_cast<uint32_t>(frame.size()));
    b.Put(frame);
    Block(o, 6, b.b);
}

Bytes BuildPcapng()
{
    Out o;
    o.be = false;
    Shb(o);
    Idb(o, 1, "eth0", 9);          // nanoseconds
    Idb(o, 113, nullptr, -1);      // Linux cooked, default microseconds
    Epb(o, 0, uint64_t{kSec} * 1000000000ull + 250000000ull, Ethernet(Ipv6(Udp(5353, 5353, kPayload)), 0x86DD));
    Bytes sll(16, 0);
    sll[14] = 0x08;
    const Bytes ip4 = Ipv4(Udp(5353, 5353, kPayload));
    sll.insert(sll.end(), ip4.begin(), ip4.end());
    Epb(o, 1, uint64_t{kSec} * 1000000ull + 1, sll);
    Out spb;
    spb.be = false;
    const Bytes eth = Ethernet(ip4, 0x0800);
    spb.U32(static_cast<uint32_t>(eth.size()));
    spb.Put(eth);
    Block(o, 3, spb.b);                                       // simple: interface 0, no time
    Epb(o, 7, 0, eth);                                        // undeclared interface
    Block(o, 5, Bytes(8, 0));                                 // a statistics block: skipped
    // A second section, big-endian, whose interface 0 is raw IP.
    o.be = true;
    Shb(o);
    Idb(o, 101, "\\Device\\NPF_{0}", -1, "Wi-Fi");   // dumpcap's shape: a device path and a description
    Epb(o, 0, uint64_t{kSec + 9} * 1000000ull, ip4);
    return o.b;
}

void TestPcapng()
{
    const Bytes file = BuildPcapng();
    mdns::CaptureResult r;
    std::string error;
    CHECK(mdns::ReadCapture(file.data(), file.size(), 1000, r, error));
    CHECK(error.empty());
    CHECK(r.format == "pcapng");
    CHECK(r.frames == 5);
    CHECK(r.packets.size() == 4);
    CHECK(r.unsupportedLink == 1);
    if (r.packets.size() != 4) {
        return;
    }
    CHECK(r.packets[0].ipv6 && r.packets[0].ifName == "eth0" && r.packets[0].ifIndex == 0);
    CHECK(r.packets[0].time == kEpoch + uint64_t{kSec} * 10000000ull + 2500000ull);
    CHECK(r.packets[1].ifName == "interface 1" && r.packets[1].source == "192.0.2.10");
    CHECK(r.packets[1].time == kEpoch + uint64_t{kSec} * 10000000ull + 10ull);
    CHECK(r.packets[2].time == 0 && r.packets[2].ifName == "eth0");
    CHECK(r.packets[3].ifName == "Wi-Fi");
    CHECK(r.packets[3].time == kEpoch + uint64_t{kSec + 9} * 10000000ull);
    for (const mdns::Packet& p : r.packets) {
        CHECK(p.data == kPayload);
    }

    // A block length that disagrees with its trailer stops the read there.
    Bytes bad = file;
    bad[bad.size() - 1] ^= 0x01;
    CHECK(mdns::ReadCapture(bad.data(), bad.size(), 1000, r, error));
    CHECK(!r.warning.empty() && r.packets.size() == 3);
}

// if_tsoffset (option 14) moves every time on that interface by whole
// seconds. It comes from the file, so the extremes must give "no time"
// rather than overflow the sum.
void TestTimeOffset()
{
    const int64_t offsets[] = {3600, -3600, INT64_MAX, INT64_MIN, -int64_t{kSec} - 1};
    const uint64_t want[] = {kEpoch + uint64_t{kSec + 3600} * 10000000ull,
                             kEpoch + uint64_t{kSec - 3600} * 10000000ull, 0, 0, 0};
    for (size_t i = 0; i < 5; ++i) {
        Out o;
        o.be = false;
        Shb(o);
        Out b;
        b.be = false;
        b.U16(101); b.U16(0); b.U32(0);
        b.U16(14); b.U16(8);
        b.U32(static_cast<uint32_t>(static_cast<uint64_t>(offsets[i])));
        b.U32(static_cast<uint32_t>(static_cast<uint64_t>(offsets[i]) >> 32));
        b.U16(0); b.U16(0);
        Block(o, 1, b.b);
        Epb(o, 0, uint64_t{kSec} * 1000000ull, Ipv4(Udp(5353, 5353, kPayload)));
        mdns::CaptureResult r;
        std::string error;
        CHECK(mdns::ReadCapture(o.b.data(), o.b.size(), 10, r, error));
        CHECK(r.packets.size() == 1);
        if (r.packets.size() == 1 && r.packets[0].time != want[i]) {
            std::printf("  offset case %zu\n", i);
            CHECK(false);
        }
    }
}

// Random corruptions of both files: no crash, no assertion, nothing kept
// that is longer than the file it came from.
void TestFuzz()
{
    uint32_t state = 777;
    auto next = [&state]() { state = state * 1664525u + 1013904223u; return state >> 8; };
    const Bytes seeds[] = {BuildPcap(false, false), BuildPcap(true, true), BuildPcapng()};
    int oversize = 0;
    for (int i = 0; i < 100000; ++i) {
        Bytes f = seeds[i % 3];
        const int flips = 1 + static_cast<int>(next() % 8);
        for (int k = 0; k < flips; ++k) {
            f[4 + next() % (f.size() - 4)] = static_cast<uint8_t>(next());
        }
        if (next() % 4 == 0) {
            f.resize(4 + next() % (f.size() - 4));
        }
        mdns::CaptureResult r;
        std::string error;
        (void)mdns::ReadCapture(f.data(), f.size(), 50, r, error);
        for (const mdns::Packet& p : r.packets) {
            oversize += p.data.size() > f.size() ? 1 : 0;
        }
    }
    CHECK(oversize == 0);
}

} // namespace

// test_capture --read <file>...: what the reader makes of real captures, for
// comparing with another tool's count.
int ReadFiles(int argc, char** argv)
{
    int bad = 0;
    for (int i = 2; i < argc; ++i) {
        const std::string narrow(argv[i]);
        const std::wstring path(narrow.begin(), narrow.end());
        mdns::CaptureResult r;
        std::string error;
        if (!mdns::ReadCaptureFile(path, SIZE_MAX, r, error)) {
            std::printf("%s: %s\n", argv[i], error.c_str());
            ++bad;
            continue;
        }
        size_t v6 = 0, truncated = 0;
        for (const mdns::Packet& p : r.packets) {
            v6 += p.ipv6 ? 1 : 0;
            truncated += p.truncated ? 1 : 0;
        }
        std::printf("%s: %s, %llu frames, %zu mDNS (%zu IPv6, %zu truncated), %llu not mDNS, %llu fragments, "
                    "%llu unsupported link%s%s\n",
                    argv[i], r.format.c_str(), static_cast<unsigned long long>(r.frames), r.packets.size(), v6,
                    truncated, static_cast<unsigned long long>(r.notMdns), static_cast<unsigned long long>(r.fragments),
                    static_cast<unsigned long long>(r.unsupportedLink), r.warning.empty() ? "" : "; ",
                    r.warning.c_str());
    }
    return bad == 0 ? 0 : 1;
}

int main(int argc, char** argv)
{
    if (argc > 2 && std::strcmp(argv[1], "--read") == 0) {
        return ReadFiles(argc, argv);
    }
    TestPcap(false, false);
    TestPcap(true, true);
    TestPcap(false, true);
    TestPcapDamaged();
    TestOtherLinks();
    TestPcapng();
    TestTimeOffset();
    TestFuzz();
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

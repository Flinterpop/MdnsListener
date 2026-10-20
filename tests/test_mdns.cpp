// Unit tests for mdnscore: decoder, hex dump mapping, conversation table,
// and a deterministic fuzz pass over the decoder.
#include "Conversations.h"
#include "Dns.h"
#include "HexDump.h"
#include "Sequence.h"

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

bool Contains(const std::string& s, const char* part) { return s.find(part) != std::string::npos; }

struct Builder {
    std::vector<uint8_t> b;
    void U8(unsigned v) { b.push_back(static_cast<uint8_t>(v)); }
    void U16(unsigned v) { U8(v >> 8); U8(v & 0xFF); }
    void U32(uint32_t v) { U16(v >> 16); U16(v & 0xFFFF); }
    void Label(const char* s) {
        const size_t n = std::strlen(s);
        U8(static_cast<unsigned>(n));
        b.insert(b.end(), s, s + n);
    }
    void End() { U8(0); }
    void Ptr(unsigned off) { U16(0xC000u | off); }
    size_t Pos() const { return b.size(); }
    void Header(unsigned flags, unsigned qd, unsigned an, unsigned ns, unsigned ar) {
        U16(0); U16(flags); U16(qd); U16(an); U16(ns); U16(ar);
    }
    // Writes RDLENGTH placeholder; returns its position for Patch().
    size_t BeginRdata() { const size_t p = Pos(); U16(0); return p; }
    void Patch(size_t at) {
        const size_t len = Pos() - at - 2;
        b[at] = static_cast<uint8_t>(len >> 8);
        b[at + 1] = static_cast<uint8_t>(len & 0xFF);
    }
};

void TestQuery()
{
    Builder q;
    q.Header(0x0000, 1, 0, 0, 0);
    q.Label("_airplay"); q.Label("_tcp"); q.Label("local"); q.End();
    q.U16(12); q.U16(0x8001);
    mdns::Message m;
    CHECK(mdns::Decode(q.b.data(), q.b.size(), m));
    CHECK(m.complete && m.error.empty());
    CHECK(!m.IsResponse());
    CHECK(m.questions.size() == 1);
    CHECK(m.questions[0].name == "_airplay._tcp.local");
    CHECK(m.questions[0].type == 12 && m.questions[0].qclass == 1 && m.questions[0].unicastResponse);
    CHECK(mdns::Summarize(m) == "Query PTR _airplay._tcp.local (QU)");
}

// A typical DNS-SD announcement, with compression everywhere it is legal.
std::vector<uint8_t> BuildResponse()
{
    Builder r;
    r.Header(0x8400, 0, 4, 0, 1);
    const size_t service = r.Pos();                 // 12
    r.Label("_airplay"); r.Label("_tcp");
    const size_t local = r.Pos();                   // 26
    r.Label("local"); r.End();
    r.U16(12); r.U16(1); r.U32(4500);
    size_t rd = r.BeginRdata();
    const size_t instance = r.Pos();
    r.Label("Living Room"); r.Ptr(static_cast<unsigned>(service));
    r.Patch(rd);
    // SRV
    r.Ptr(static_cast<unsigned>(instance)); r.U16(33); r.U16(0x8001); r.U32(120);
    rd = r.BeginRdata();
    r.U16(0); r.U16(0); r.U16(7000);
    const size_t host = r.Pos();
    r.Label("lr"); r.Ptr(static_cast<unsigned>(local));
    r.Patch(rd);
    // TXT
    r.Ptr(static_cast<unsigned>(instance)); r.U16(16); r.U16(0x8001); r.U32(4500);
    rd = r.BeginRdata();
    r.Label("model=AppleTV3,2"); r.Label("pw=0");
    r.Patch(rd);
    // A
    r.Ptr(static_cast<unsigned>(host)); r.U16(1); r.U16(0x8001); r.U32(120);
    rd = r.BeginRdata();
    r.U8(192); r.U8(168); r.U8(1); r.U8(20);
    r.Patch(rd);
    // NSEC (additional): A and AAAA exist
    r.Ptr(static_cast<unsigned>(host)); r.U16(47); r.U16(0x8001); r.U32(120);
    rd = r.BeginRdata();
    r.Ptr(static_cast<unsigned>(host)); r.U8(0); r.U8(4); r.U8(0x40); r.U8(0); r.U8(0); r.U8(0x08);
    r.Patch(rd);
    return r.b;
}

void TestResponse()
{
    const std::vector<uint8_t> pkt = BuildResponse();
    mdns::Message m;
    CHECK(mdns::Decode(pkt.data(), pkt.size(), m));
    CHECK(m.IsResponse());
    CHECK(m.records.size() == 5);
    if (m.records.size() != 5) {
        std::printf("  error: %s\n", m.error.c_str());
        return;
    }
    CHECK(m.records[0].type == 12 && m.records[0].data == "Living Room._airplay._tcp.local");
    CHECK(!m.records[0].cacheFlush);
    CHECK(m.records[1].name == "Living Room._airplay._tcp.local");
    CHECK(m.records[1].data == "lr.local:7000 (priority 0, weight 0)");
    CHECK(m.records[1].cacheFlush && m.records[1].rclass == 1);
    CHECK(m.records[2].data == "\"model=AppleTV3,2\" \"pw=0\"");
    CHECK(m.records[3].name == "lr.local" && m.records[3].data == "192.168.1.20");
    CHECK(m.records[4].section == mdns::Section::Additional);
    CHECK(m.records[4].data == "lr.local (A AAAA)");
    CHECK(Contains(mdns::Summarize(m), "Response PTR _airplay._tcp.local = Living Room._airplay._tcp.local"));
    CHECK(Contains(mdns::Summarize(m), "(+1 more)"));
    // Every tree line must lie inside the packet.
    bool inside = true;
    for (const mdns::Node& n : m.tree) {
        inside = inside && (static_cast<size_t>(n.offset) + n.length <= pkt.size());
    }
    CHECK(inside);
    CHECK(m.tree.size() > 30);
}

void TestOpt()
{
    Builder r;
    r.Header(0x0000, 0, 0, 0, 1);
    r.End(); r.U16(41); r.U16(1440); r.U32(0);
    const size_t rd = r.BeginRdata();
    r.U16(4); r.U16(8); r.U8(0); r.U8(7); r.U8(0x00); r.U8(0x11); r.U8(0x22); r.U8(0x33); r.U8(0x44); r.U8(0x55);
    r.Patch(rd);
    mdns::Message m;
    CHECK(mdns::Decode(r.b.data(), r.b.size(), m));
    CHECK(m.records.size() == 1 && m.records[0].rclass == 1440 && !m.records[0].cacheFlush);
    bool found = false;
    for (const mdns::Node& n : m.tree) {
        found = found || Contains(n.text, "MAC 00:11:22:33:44:55");
    }
    CHECK(found);
}

void TestUtf8Name()
{
    Builder q;
    q.Header(0, 1, 0, 0, 0);
    q.Label("Alex\xE2\x80\x99s iPhone"); q.Label("local"); q.End();
    q.U16(255); q.U16(1);
    mdns::Message m;
    CHECK(mdns::Decode(q.b.data(), q.b.size(), m));
    CHECK(!m.questions.empty() && m.questions[0].name == "Alex\xE2\x80\x99s iPhone.local");
}

void ExpectMalformed(const std::vector<uint8_t>& pkt, const char* why)
{
    mdns::Message m;
    const bool ok = mdns::Decode(pkt.data(), pkt.size(), m);
    CHECK(!ok);
    CHECK(!m.error.empty() && !m.complete);
    if (ok || !Contains(m.error, why)) {
        std::printf("  expected error containing '%s', got '%s'\n", why, m.error.c_str());
        ++g_failures;
    }
}

void TestMalformed()
{
    ExpectMalformed({0, 0, 0}, "shorter than the 12-byte header");

    Builder self;   // pointer to itself
    self.Header(0, 1, 0, 0, 0); self.Ptr(12); self.U16(1); self.U16(1);
    ExpectMalformed(self.b, "points forward");

    Builder loop;   // label, then a pointer back to that label: a backward loop
    loop.Header(0, 1, 0, 0, 0); loop.Label("a"); loop.Ptr(12);
    ExpectMalformed(loop.b, "labels and pointers");

    Builder longName;   // 5 x 63-byte labels = 321 bytes on the wire
    longName.Header(0, 1, 0, 0, 0);
    const std::string label63(63, 'x');
    for (int i = 0; i < 5; ++i) longName.Label(label63.c_str());
    longName.End(); longName.U16(1); longName.U16(1);
    ExpectMalformed(longName.b, "longer than 255");

    Builder ext;    // extended label type
    ext.Header(0, 1, 0, 0, 0); ext.U8(0x41); ext.U8(0); ext.U16(1); ext.U16(1);
    ExpectMalformed(ext.b, "label type 0x40");

    Builder trunc;  // header promises an answer that is not there
    trunc.Header(0x8400, 0, 1, 0, 0);
    ExpectMalformed(trunc.b, "packet ends after 0");

    Builder many;   // 65535 questions claimed in a 12-byte packet
    many.Header(0, 0xFFFF, 0, 0, 0);
    ExpectMalformed(many.b, "packet ends after 0");

    Builder rdlen;  // RDLENGTH past the end
    rdlen.Header(0x8400, 0, 1, 0, 0); rdlen.End(); rdlen.U16(1); rdlen.U16(1); rdlen.U32(1); rdlen.U16(50);
    ExpectMalformed(rdlen.b, "runs past the end");

    Builder badA;   // A record with five bytes
    badA.Header(0x8400, 0, 1, 0, 0); badA.End(); badA.U16(1); badA.U16(1); badA.U32(1); badA.U16(5);
    for (int i = 0; i < 5; ++i) badA.U8(1);
    ExpectMalformed(badA.b, "expected 4");

    // A partial decode keeps what came before the fault.
    std::vector<uint8_t> cut = BuildResponse();
    cut.resize(cut.size() - 3);
    mdns::Message m;
    CHECK(!mdns::Decode(cut.data(), cut.size(), m));
    CHECK(m.records.size() == 4);
    CHECK(Contains(mdns::Summarize(m), "[MALFORMED:"));
}

void TestHexDump()
{
    std::vector<uint8_t> d(20);
    for (size_t i = 0; i < d.size(); ++i) d[i] = static_cast<uint8_t>(0xA0 + i);
    const std::string dump = mdns::HexDump(d.data(), d.size());
    CHECK(dump.substr(0, 9) == "0000  A0 ");
    CHECK(dump.substr(mdns::kHexLineChars, 4) == "0010");
    size_t first = 0, last = 0;
    CHECK(mdns::HexSelection(d.size(), 16, 2, first, last));
    CHECK(dump.substr(first, last - first) == "B0 B1");
    CHECK(mdns::HexSelection(d.size(), 0, 1, first, last));
    CHECK(dump.substr(first, last - first) == "A0");
    CHECK(mdns::HexSelection(d.size(), 15, 2, first, last));
    CHECK(dump.substr(first, 2) == "AF" && dump.substr(last - 2, 2) == "B0");
    CHECK(!mdns::HexSelection(d.size(), 20, 1, first, last));
    CHECK(!mdns::HexSelection(d.size(), 3, 0, first, last));
    CHECK(mdns::HexDump(nullptr, 0).empty());
}

void TestConversations()
{
    mdns::ConversationTable t;
    const std::vector<uint8_t> resp = BuildResponse();
    mdns::Message r;
    mdns::Decode(resp.data(), resp.size(), r);
    Builder q;
    q.Header(0, 1, 0, 0, 0); q.Label("_hap"); q.Label("_tcp"); q.Label("local"); q.End(); q.U16(12); q.U16(1);
    mdns::Message qm;
    mdns::Decode(q.b.data(), q.b.size(), qm);

    CHECK(t.Add("192.168.1.20", 5353, r, resp.size(), 100) == 0);
    CHECK(t.Add("192.168.1.20", 5353, qm, q.b.size(), 200) == 0);
    CHECK(t.Add("fe80::1%12", 49152, qm, q.b.size(), 300) == 1);
    CHECK(t.Items().size() == 2);
    const mdns::Conversation& a = t.Items()[0];
    CHECK(a.packets == 2 && a.queries == 1 && a.responses == 1);
    CHECK(a.bytes == resp.size() + q.b.size());
    CHECK(a.firstSeen == 100 && a.lastSeen == 200);
    CHECK(a.hostName == "lr.local");
    CHECK(mdns::JoinNames(a.announced) == "Living Room._airplay._tcp.local, lr.local");
    CHECK(mdns::JoinNames(a.asked) == "_hap._tcp.local");
    CHECK(t.Items()[1].ports.size() == 1 && t.Items()[1].ports[0] == "49152");
    t.Clear();
    CHECK(t.Items().empty());
}

std::vector<uint8_t> PtrQuery(const char* service)
{
    Builder q;
    q.Header(0, 1, 0, 0, 0);
    q.Label(service); q.Label("_tcp"); q.Label("local"); q.End();
    q.U16(12); q.U16(1);
    return q.b;
}

std::vector<uint8_t> PtrAnswer(const char* service, uint32_t ttl)
{
    Builder r;
    r.Header(0x8400, 0, 1, 0, 0);
    r.Label(service); r.Label("_tcp"); r.Label("LOCAL"); r.End();   // case differs on purpose
    r.U16(12); r.U16(1); r.U32(ttl);
    const size_t rd = r.BeginRdata();
    r.Label("Thing"); r.Ptr(12);
    r.Patch(rd);
    return r.b;
}

void TestSequence()
{
    const std::vector<uint8_t> q = PtrQuery("_probe");
    const std::vector<uint8_t> a = PtrAnswer("_probe", 120);
    const std::vector<uint8_t> bye = PtrAnswer("_probe", 0);
    mdns::Message mq, ma, mbye;
    CHECK(mdns::Decode(q.data(), q.size(), mq));
    CHECK(mdns::Decode(a.data(), a.size(), ma));
    CHECK(mdns::Decode(bye.data(), bye.size(), mbye));
    CHECK(mdns::Shares(mdns::CollectNames(mq), mdns::CollectNames(ma)));
    CHECK(mdns::CollectNames(ma).targets.size() == 1 && mdns::CollectNames(ma).targets[0] == "thing._probe._tcp.local");

    const uint64_t ms = 10000;
    auto msg = [](uint64_t seq, uint64_t t, const char* src, const char* dst, const mdns::Message& m) {
        mdns::SeqMessage s;
        s.seq = seq; s.time = t; s.source = src; s.destination = dst; s.msg = &m;
        s.names = mdns::CollectNames(m);
        return s;
    };
    std::vector<mdns::SeqMessage> in = {
        msg(1, 1000 * ms, "10.0.0.1", "224.0.0.251", mq),
        msg(2, 1100 * ms, "10.0.0.2", "224.0.0.251", ma),     // answers #1 after 100 ms
        msg(3, 3500 * ms, "10.0.0.2", "224.0.0.251", ma),     // 2.4 s later: unsolicited
        msg(4, 3600 * ms, "10.0.0.2", "224.0.0.251", mbye),
        msg(5, 3700 * ms, "10.0.0.2", "10.0.0.9", ma),        // unicast
        msg(6, 3750 * ms, "10.0.0.1", "?", ma),               // the querier answering: no match to itself
    };
    const mdns::SeqChart c = mdns::BuildSequence(in);
    CHECK(c.arrows.size() == 6);
    CHECK(c.lifelines.size() == 4 && c.lifelines.back() == mdns::kGroupLifeline);
    if (c.arrows.size() != 6 || c.lifelines.size() != 4) {
        return;
    }
    const int group = 3;
    CHECK(c.arrows[0].kind == mdns::ArrowKind::Query && c.arrows[0].from == 0 && c.arrows[0].to == group);
    CHECK(c.arrows[1].kind == mdns::ArrowKind::Response && c.arrows[1].from == 1 && c.arrows[1].to == 0);
    CHECK(Contains(c.arrows[1].note, "answers #1 after 100 ms"));
    CHECK(c.arrows[2].kind == mdns::ArrowKind::Announcement && c.arrows[2].to == group);
    CHECK(c.arrows[3].kind == mdns::ArrowKind::Goodbye && c.arrows[3].to == group);
    CHECK(c.arrows[4].kind == mdns::ArrowKind::Unicast && c.lifelines[static_cast<size_t>(c.arrows[4].to)] == "10.0.0.9");
    CHECK(c.arrows[5].kind == mdns::ArrowKind::Announcement);

    // More hosts than lifelines: the overflow shares "(other hosts)".
    std::vector<std::string> hosts;
    std::vector<mdns::SeqMessage> crowd;
    for (int i = 0; i < 30; ++i) {
        hosts.push_back("10.1.0." + std::to_string(i));
    }
    for (int i = 0; i < 30; ++i) {
        crowd.push_back(msg(static_cast<uint64_t>(i + 1), static_cast<uint64_t>(i) * 5000 * ms,
                            hosts[static_cast<size_t>(i)].c_str(), "224.0.0.251", mq));
    }
    const mdns::SeqChart big = mdns::BuildSequence(crowd);
    CHECK(static_cast<int>(big.lifelines.size()) == mdns::kMaxLifelines);
    CHECK(big.lifelines[big.lifelines.size() - 2] == mdns::kOtherLifeline);
    CHECK(big.arrows.back().from == mdns::kMaxLifelines - 2);
    CHECK(mdns::BuildSequence({}).lifelines.size() == 1);
}

// Deterministic fuzz: random packets, and random corruptions of a valid one.
// Passing means no crash, no assertion, and every tree line inside the packet.
void TestFuzz()
{
    uint32_t state = 12345;
    auto next = [&state]() { state = state * 1664525u + 1013904223u; return state >> 8; };
    const std::vector<uint8_t> good = BuildResponse();
    int outside = 0;
    for (int i = 0; i < 200000; ++i) {
        std::vector<uint8_t> p;
        if (i % 2 == 0) {
            p.resize(next() % 300);
            for (uint8_t& b : p) b = static_cast<uint8_t>(next());
        } else {
            p = good;
            const int flips = 1 + static_cast<int>(next() % 6);
            for (int f = 0; f < flips; ++f) p[next() % p.size()] = static_cast<uint8_t>(next());
            if (next() % 4 == 0) p.resize(next() % p.size());
        }
        mdns::Message m;
        mdns::Decode(p.data(), p.size(), m);
        (void)mdns::Summarize(m);
        for (const mdns::Node& n : m.tree) {
            outside += (static_cast<size_t>(n.offset) + n.length > p.size()) ? 1 : 0;
        }
    }
    CHECK(outside == 0);
}

} // namespace

int main()
{
    TestQuery();
    TestResponse();
    TestOpt();
    TestUtf8Name();
    TestMalformed();
    TestHexDump();
    TestConversations();
    TestSequence();
    TestFuzz();
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

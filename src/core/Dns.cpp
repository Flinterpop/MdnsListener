#include "Dns.h"

#include <ws2tcpip.h>

#include <cassert>
#include <cstdarg>
#include <cstdio>

namespace mdns {
namespace {

// ---------------------------------------------------------------------------
// Bounds-checked reads
// ---------------------------------------------------------------------------

bool ReadU16(const uint8_t* d, size_t n, size_t pos, uint16_t& v)
{
    assert(d != nullptr);
    if (pos + 2 > n) {
        return false;
    }
    v = static_cast<uint16_t>((d[pos] << 8) | d[pos + 1]);
    return true;
}

bool ReadU32(const uint8_t* d, size_t n, size_t pos, uint32_t& v)
{
    assert(d != nullptr);
    if (pos + 4 > n) {
        return false;
    }
    v = (static_cast<uint32_t>(d[pos]) << 24) | (static_cast<uint32_t>(d[pos + 1]) << 16) |
        (static_cast<uint32_t>(d[pos + 2]) << 8) | static_cast<uint32_t>(d[pos + 3]);
    return true;
}

std::string Format(const char* fmt, ...)
{
    assert(fmt != nullptr);
    char buf[512];
    va_list args;
    va_start(args, fmt);
    const int r = std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    assert(r >= 0);
    return r < 0 ? std::string() : std::string(buf);
}

// Appends one byte in presentation form: control bytes as \DDD (RFC 1035
// 5.1), the given specials backslash-escaped, and everything else as is.
// Bytes above 0x7F pass through, because mDNS names are UTF-8 (RFC 6762
// 16) and "Alex\226\128\153s iPhone" helps nobody; the GUI converts them.
void AppendEscaped(std::string& out, uint8_t c, const char* specials)
{
    assert(specials != nullptr);
    if (c < 0x20 || c == 0x7F) {
        out += Format("\\%03u", static_cast<unsigned>(c));
        return;
    }
    for (const char* s = specials; *s != '\0'; ++s) {
        if (static_cast<char>(c) == *s) {
            out += '\\';
            break;
        }
    }
    out += static_cast<char>(c);
}

void AppendLabel(std::string& name, const uint8_t* label, size_t len)
{
    assert(label != nullptr);
    assert(len <= 63);
    if (!name.empty()) {
        name += '.';
    }
    for (size_t i = 0; i < len; ++i) {
        AppendEscaped(name, label[i], ".\\");
    }
}

// Reads a possibly compressed name at `pos`. `end` receives the position
// just after the name as it sits at `pos` (after the first pointer, if any).
// Iterative; pointers must point strictly backwards and the step count is
// bounded, so a pointer loop terminates.
bool ReadName(const uint8_t* d, size_t n, size_t pos, std::string& name, size_t& end,
              std::string& err)
{
    assert(d != nullptr);
    name.clear();
    size_t cur = pos;
    size_t wireLen = 1;
    bool jumped = false;
    for (int step = 0; step < kMaxNameSteps; ++step) {
        if (cur >= n) {
            err = Format("name at offset %zu runs past the end of the packet", pos);
            return false;
        }
        const uint8_t len = d[cur];
        if (len == 0) {
            if (!jumped) {
                end = cur + 1;
            }
            if (name.empty()) {
                name = ".";
            }
            return true;
        }
        const uint8_t kind = static_cast<uint8_t>(len & 0xC0);
        if (kind == 0xC0) {
            if (cur + 1 >= n) {
                err = Format("compression pointer at offset %zu is truncated", cur);
                return false;
            }
            const size_t target = (static_cast<size_t>(len & 0x3F) << 8) | d[cur + 1];
            if (target >= cur) {
                err = Format("compression pointer at offset %zu points forward to %zu", cur, target);
                return false;
            }
            if (!jumped) {
                end = cur + 2;
                jumped = true;
            }
            cur = target;
            continue;
        }
        if (kind != 0) {
            err = Format("label type 0x%02X at offset %zu is not supported", kind, cur);
            return false;
        }
        if (cur + 1 + len > n) {
            err = Format("label at offset %zu runs past the end of the packet", cur);
            return false;
        }
        wireLen += 1u + len;
        if (wireLen > kMaxNameLength) {
            err = Format("name at offset %zu is longer than %zu bytes", pos, kMaxNameLength);
            return false;
        }
        AppendLabel(name, d + cur + 1, len);
        cur += 1u + len;
    }
    err = Format("name at offset %zu has more than %d labels and pointers", pos, kMaxNameSteps);
    return false;
}

// ---------------------------------------------------------------------------
// Decoding context
// ---------------------------------------------------------------------------

struct Ctx {
    const uint8_t* d;
    size_t n;
    Message& m;
};

size_t AddNode(Ctx& c, int depth, size_t offset, size_t length, std::string text)
{
    assert(depth >= 0 && depth < 8);
    assert(offset <= c.n);
    Node node;
    node.depth = static_cast<uint8_t>(depth);
    node.offset = static_cast<uint16_t>(offset > 0xFFFF ? 0xFFFF : offset);
    node.length = static_cast<uint16_t>(length > 0xFFFF ? 0xFFFF : length);
    node.text = std::move(text);
    c.m.tree.push_back(std::move(node));
    return c.m.tree.size() - 1;
}

void SetNodeLength(Ctx& c, size_t index, size_t length)
{
    assert(index < c.m.tree.size());
    c.m.tree[index].length = static_cast<uint16_t>(length > 0xFFFF ? 0xFFFF : length);
}

bool Fail(Ctx& c, int depth, size_t offset, const std::string& err)
{
    assert(!err.empty());
    if (c.m.error.empty()) {
        c.m.error = err;
    }
    AddNode(c, depth, offset > c.n ? c.n : offset, 0, "Malformed: " + err);
    return false;
}

const char* OpcodeName(unsigned op)
{
    switch (op) {
    case 0: return "Standard query";
    case 1: return "Inverse query";
    case 2: return "Server status";
    case 4: return "Notify";
    case 5: return "Update";
    default: return "Unassigned";
    }
}

const char* RcodeName(unsigned rc)
{
    switch (rc) {
    case 0: return "No error";
    case 1: return "Format error";
    case 2: return "Server failure";
    case 3: return "No such name";
    case 4: return "Not implemented";
    case 5: return "Refused";
    default: return "Other";
    }
}

std::string BitLine(uint16_t flags, int bit, const char* name, const char* set, const char* clear)
{
    assert(bit >= 0 && bit < 16);
    assert(name != nullptr && set != nullptr && clear != nullptr);
    std::string pattern;
    for (int i = 15; i >= 0; --i) {
        pattern += (i == bit) ? (((flags >> i) & 1u) ? '1' : '0') : '.';
        if (i % 4 == 0 && i != 0) {
            pattern += ' ';
        }
    }
    const bool on = ((flags >> bit) & 1u) != 0;
    return pattern + " = " + name + ": " + (on ? set : clear);
}

void DecodeFlags(Ctx& c, uint16_t f)
{
    const unsigned op = (f >> 11) & 0xFu;
    const unsigned rc = f & 0xFu;
    AddNode(c, 1, 2, 2, Format("Flags: 0x%04X (%s %s)", f, OpcodeName(op),
                               (f & 0x8000u) ? "response" : "query"));
    AddNode(c, 2, 2, 2, BitLine(f, 15, "Response", "message is a response", "message is a query"));
    AddNode(c, 2, 2, 2, Format(".%c%c%c %c... .... .... = Opcode: %u (%s)", (op & 8) ? '1' : '0',
                               (op & 4) ? '1' : '0', (op & 2) ? '1' : '0', (op & 1) ? '1' : '0', op,
                               OpcodeName(op)));
    AddNode(c, 2, 2, 2, BitLine(f, 10, "Authoritative", "yes", "no"));
    AddNode(c, 2, 2, 2, BitLine(f, 9, "Truncated", "more known answers follow", "no"));
    AddNode(c, 2, 2, 2, BitLine(f, 8, "Recursion desired", "yes", "no"));
    AddNode(c, 2, 2, 2, BitLine(f, 7, "Recursion available", "yes", "no"));
    AddNode(c, 2, 2, 2, BitLine(f, 6, "Z", "set (should be zero)", "reserved (0)"));
    AddNode(c, 2, 2, 2, BitLine(f, 5, "Authentic data", "yes", "no"));
    AddNode(c, 2, 2, 2, BitLine(f, 4, "Checking disabled", "yes", "no"));
    AddNode(c, 2, 2, 2, Format(".... .... .... %c%c%c%c = Reply code: %u (%s)", (rc & 8) ? '1' : '0',
                               (rc & 4) ? '1' : '0', (rc & 2) ? '1' : '0', (rc & 1) ? '1' : '0', rc,
                               RcodeName(rc)));
}

void DecodeHeader(Ctx& c)
{
    assert(c.n >= kHeaderSize);
    Message& m = c.m;
    const bool ok = ReadU16(c.d, c.n, 0, m.id) && ReadU16(c.d, c.n, 2, m.flags) &&
                    ReadU16(c.d, c.n, 4, m.counts[0]) && ReadU16(c.d, c.n, 6, m.counts[1]) &&
                    ReadU16(c.d, c.n, 8, m.counts[2]) && ReadU16(c.d, c.n, 10, m.counts[3]);
    assert(ok);
    (void)ok;
    AddNode(c, 0, 0, kHeaderSize, "Header");
    AddNode(c, 1, 0, 2, Format("Transaction ID: 0x%04X%s", m.id, m.id == 0 ? " (mDNS multicast)" : ""));
    DecodeFlags(c, m.flags);
    AddNode(c, 1, 4, 2, Format("Questions: %u", m.counts[0]));
    AddNode(c, 1, 6, 2, Format("Answer RRs: %u", m.counts[1]));
    AddNode(c, 1, 8, 2, Format("Authority RRs: %u", m.counts[2]));
    AddNode(c, 1, 10, 2, Format("Additional RRs: %u", m.counts[3]));
}

// Reads a name and adds its tree line. Returns false (and records the error)
// on a malformed name.
bool NameField(Ctx& c, int depth, size_t pos, const char* label, std::string& name, size_t& end)
{
    assert(label != nullptr);
    std::string err;
    if (!ReadName(c.d, c.n, pos, name, end, err)) {
        return Fail(c, depth, pos, err);
    }
    assert(end > pos);
    AddNode(c, depth, pos, end - pos, Format("%s: %s", label, name.c_str()));
    return true;
}

// ---------------------------------------------------------------------------
// RDATA
// ---------------------------------------------------------------------------

// One <character-string> (RFC 1035 3.3) at `pos`, which must lie before `end`.
bool CharString(Ctx& c, size_t pos, size_t end, std::string& text, size_t& next)
{
    assert(pos < end && end <= c.n);
    const size_t len = c.d[pos];
    if (pos + 1 + len > end) {
        return false;
    }
    text.clear();
    for (size_t i = 0; i < len; ++i) {
        AppendEscaped(text, c.d[pos + 1 + i], "\"\\");
    }
    next = pos + 1 + len;
    return true;
}

bool RdataAddress(Ctx& c, int depth, uint16_t type, size_t pos, size_t len, std::string& out)
{
    const size_t want = (type == 1) ? 4u : 16u;
    if (len != want) {
        return Fail(c, depth, pos, Format("%s record has %zu data bytes, expected %zu",
                                          type == 1 ? "A" : "AAAA", len, want));
    }
    char buf[INET6_ADDRSTRLEN] = {};
    const int family = (type == 1) ? AF_INET : AF_INET6;
    const char* r = inet_ntop(family, c.d + pos, buf, sizeof(buf));
    out = (r != nullptr) ? buf : "?";
    AddNode(c, depth, pos, len, Format("Address: %s", out.c_str()));
    return true;
}

bool RdataName(Ctx& c, int depth, size_t pos, size_t len, const char* label, std::string& out)
{
    size_t end = 0;
    if (!NameField(c, depth, pos, label, out, end)) {
        return false;
    }
    if (end > pos + len) {
        return Fail(c, depth, pos, "name runs past the record's data length");
    }
    return true;
}

bool RdataSrv(Ctx& c, int depth, size_t pos, size_t len, std::string& out)
{
    uint16_t prio = 0, weight = 0, port = 0;
    if (len < 7 || !ReadU16(c.d, c.n, pos, prio) || !ReadU16(c.d, c.n, pos + 2, weight) ||
        !ReadU16(c.d, c.n, pos + 4, port)) {
        return Fail(c, depth, pos, "SRV record is too short");
    }
    AddNode(c, depth, pos, 2, Format("Priority: %u", prio));
    AddNode(c, depth, pos + 2, 2, Format("Weight: %u", weight));
    AddNode(c, depth, pos + 4, 2, Format("Port: %u", port));
    std::string target;
    if (!RdataName(c, depth, pos + 6, len - 6, "Target", target)) {
        return false;
    }
    out = Format("%s:%u (priority %u, weight %u)", target.c_str(), port, prio, weight);
    return true;
}

bool RdataMx(Ctx& c, int depth, size_t pos, size_t len, std::string& out)
{
    uint16_t pref = 0;
    if (len < 3 || !ReadU16(c.d, c.n, pos, pref)) {
        return Fail(c, depth, pos, "MX record is too short");
    }
    AddNode(c, depth, pos, 2, Format("Preference: %u", pref));
    std::string host;
    if (!RdataName(c, depth, pos + 2, len - 2, "Mail exchange", host)) {
        return false;
    }
    out = Format("%u %s", pref, host.c_str());
    return true;
}

bool RdataTxt(Ctx& c, int depth, size_t pos, size_t len, std::string& out)
{
    const size_t end = pos + len;
    size_t cur = pos;
    size_t count = 0;
    for (size_t i = 0; i < len && cur < end; ++i) {   // each string uses >= 1 byte
        std::string s;
        size_t next = 0;
        if (!CharString(c, cur, end, s, next)) {
            return Fail(c, depth, cur, "TXT string runs past the record's data length");
        }
        AddNode(c, depth, cur, next - cur, s.empty() ? "(empty string)" : s);
        if (!s.empty()) {
            out += (count == 0 ? "" : " ") + ("\"" + s + "\"");
            ++count;
        }
        cur = next;
    }
    if (count == 0) {
        out = "(empty)";
    }
    return true;
}

bool RdataHinfo(Ctx& c, int depth, size_t pos, size_t len, std::string& out)
{
    std::string cpu, os;
    size_t mid = 0, end = 0;
    if (len < 2 || !CharString(c, pos, pos + len, cpu, mid) || mid >= pos + len ||
        !CharString(c, mid, pos + len, os, end)) {
        return Fail(c, depth, pos, "HINFO record is malformed");
    }
    AddNode(c, depth, pos, mid - pos, "CPU: " + cpu);
    AddNode(c, depth, mid, end - mid, "OS: " + os);
    out = "\"" + cpu + "\" \"" + os + "\"";
    return true;
}

bool RdataSoa(Ctx& c, int depth, size_t pos, size_t len, std::string& out)
{
    std::string mname, rname;
    size_t p1 = 0, p2 = 0;
    if (!NameField(c, depth, pos, "Primary name server", mname, p1) ||
        !NameField(c, depth, p1, "Responsible mailbox", rname, p2)) {
        return false;
    }
    static const char* const kFields[5] = {"Serial", "Refresh", "Retry", "Expire", "Minimum TTL"};
    uint32_t v[5] = {};
    for (size_t i = 0; i < 5; ++i) {
        if (p2 + 4 * (i + 1) > pos + len || !ReadU32(c.d, c.n, p2 + 4 * i, v[i])) {
            return Fail(c, depth, p2, "SOA record is too short");
        }
        AddNode(c, depth, p2 + 4 * i, 4, Format("%s: %u", kFields[i], v[i]));
    }
    out = Format("%s %s %u", mname.c_str(), rname.c_str(), v[0]);
    return true;
}

bool RdataNsec(Ctx& c, int depth, size_t pos, size_t len, std::string& out)
{
    std::string next;
    size_t cur = 0;
    if (!NameField(c, depth, pos, "Next domain name", next, cur)) {
        return false;
    }
    if (cur > pos + len) {
        return Fail(c, depth, pos, "name runs past the record's data length");
    }
    out = next + " (";
    const size_t end = pos + len;
    for (int w = 0; w < 256 && cur + 2 <= end; ++w) {
        const unsigned window = c.d[cur];
        const size_t blen = c.d[cur + 1];
        if (blen == 0 || blen > 32 || cur + 2 + blen > end) {
            return Fail(c, depth, cur, "NSEC type bitmap is malformed");
        }
        std::string types;
        for (size_t b = 0; b < blen * 8; ++b) {
            if ((c.d[cur + 2 + b / 8] >> (7 - b % 8)) & 1u) {
                types += (types.empty() ? "" : " ") + TypeName(static_cast<uint16_t>(window * 256 + b));
            }
        }
        AddNode(c, depth, cur, 2 + blen, Format("Types (window %u): %s", window, types.c_str()));
        out += (out.back() == '(' ? "" : " ") + types;
        cur += 2 + blen;
    }
    out += ")";
    return true;
}

std::string HexBytes(const uint8_t* d, size_t len, size_t max)
{
    assert(d != nullptr || len == 0);
    std::string s;
    const size_t shown = len < max ? len : max;
    for (size_t i = 0; i < shown; ++i) {
        s += Format("%02X", d[i]);
    }
    if (shown < len) {
        s += "...";
    }
    return s;
}

const char* EdnsOptionName(uint16_t code)
{
    switch (code) {
    case 3: return "NSID";
    case 4: return "Owner (Sleep Proxy)";
    case 5: return "DAU";
    case 8: return "Client subnet";
    case 10: return "Cookie";
    case 12: return "Padding";
    default: return "Unknown";
    }
}

bool RdataOpt(Ctx& c, int depth, size_t pos, size_t len, std::string& out)
{
    const size_t end = pos + len;
    size_t cur = pos;
    for (size_t i = 0; i < len && cur < end; ++i) {
        uint16_t code = 0, olen = 0;
        if (cur + 4 > end || !ReadU16(c.d, c.n, cur, code) || !ReadU16(c.d, c.n, cur + 2, olen) ||
            cur + 4 + olen > end) {
            return Fail(c, depth, cur, "EDNS option runs past the record's data length");
        }
        std::string detail = HexBytes(c.d + cur + 4, olen, 32);
        if (code == 4 && olen >= 8) {   // draft-cheshire-edns0-owner-option
            const uint8_t* o = c.d + cur + 4;
            detail = Format("version %u, sequence %u, MAC %02X:%02X:%02X:%02X:%02X:%02X", o[0], o[1],
                            o[2], o[3], o[4], o[5], o[6], o[7]);
        }
        AddNode(c, depth, cur, 4u + olen,
                Format("Option %u %s (%u bytes): %s", code, EdnsOptionName(code), olen, detail.c_str()));
        out += (out.empty() ? "" : "; ") + std::string(EdnsOptionName(code));
        cur += 4u + olen;
    }
    if (out.empty()) {
        out = "(no options)";
    }
    return true;
}

bool DecodeRdata(Ctx& c, int depth, uint16_t type, size_t pos, size_t len, std::string& out)
{
    assert(pos + len <= c.n);
    switch (type) {
    case 1:
    case 28: return RdataAddress(c, depth, type, pos, len, out);
    case 2: return RdataName(c, depth, pos, len, "Name server", out);
    case 5: return RdataName(c, depth, pos, len, "Canonical name", out);
    case 12: return RdataName(c, depth, pos, len, "Domain name", out);
    case 39: return RdataName(c, depth, pos, len, "Target", out);
    case 6: return RdataSoa(c, depth, pos, len, out);
    case 13: return RdataHinfo(c, depth, pos, len, out);
    case 15: return RdataMx(c, depth, pos, len, out);
    case 16: return RdataTxt(c, depth, pos, len, out);
    case 33: return RdataSrv(c, depth, pos, len, out);
    case 41: return RdataOpt(c, depth, pos, len, out);
    case 47: return RdataNsec(c, depth, pos, len, out);
    default:
        out = HexBytes(c.d + pos, len, 64);
        AddNode(c, depth, pos, len, "Data: " + out);
        return true;
    }
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

bool DecodeQuestion(Ctx& c, size_t& pos, unsigned index)
{
    const size_t start = pos;
    const size_t line = AddNode(c, 1, start, 0, "");
    Question q;
    size_t end = 0;
    if (!NameField(c, 2, pos, "Name", q.name, end)) {
        return false;
    }
    uint16_t cls = 0;
    if (!ReadU16(c.d, c.n, end, q.type) || !ReadU16(c.d, c.n, end + 2, cls)) {
        return Fail(c, 2, end, "question is truncated");
    }
    q.unicastResponse = (cls & 0x8000u) != 0;
    q.qclass = static_cast<uint16_t>(cls & 0x7FFFu);
    AddNode(c, 2, end, 2, Format("Type: %s (%u)", TypeName(q.type).c_str(), q.type));
    AddNode(c, 2, end + 2, 2, Format("Class: %s (0x%04X)%s", ClassName(q.qclass).c_str(), q.qclass,
                                     q.unicastResponse ? ", unicast response requested (QU)" : ", QM"));
    pos = end + 4;
    c.m.tree[line].text = Format("%u. %s: type %s, class %s%s", index, q.name.c_str(),
                                 TypeName(q.type).c_str(), ClassName(q.qclass).c_str(),
                                 q.unicastResponse ? ", QU" : "");
    SetNodeLength(c, line, pos - start);
    c.m.questions.push_back(std::move(q));
    return true;
}

void RecordClassLine(Ctx& c, size_t at, const Record& r, uint16_t rawClass)
{
    if (r.type == 41) {
        AddNode(c, 2, at, 2, Format("UDP payload size: %u", rawClass));
        return;
    }
    AddNode(c, 2, at, 2, Format("Class: %s (0x%04X)%s", ClassName(r.rclass).c_str(), r.rclass,
                                r.cacheFlush ? ", cache flush" : ""));
}

std::string RecordHeadline(unsigned index, const Record& r)
{
    if (r.type == 41) {
        return Format("%u. OPT (EDNS0): %s", index, r.data.c_str());
    }
    return Format("%u. %s: type %s, class %s%s, ttl %u, %s", index, r.name.c_str(),
                  TypeName(r.type).c_str(), ClassName(r.rclass).c_str(),
                  r.cacheFlush ? " (flush)" : "", r.ttl, r.data.c_str());
}

bool DecodeRecord(Ctx& c, size_t& pos, Section section, unsigned index)
{
    const size_t start = pos;
    const size_t line = AddNode(c, 1, start, 0, "");
    Record r;
    r.section = section;
    size_t end = 0;
    if (!NameField(c, 2, pos, "Name", r.name, end)) {
        return false;
    }
    uint16_t cls = 0, rdlen = 0;
    if (!ReadU16(c.d, c.n, end, r.type) || !ReadU16(c.d, c.n, end + 2, cls) ||
        !ReadU32(c.d, c.n, end + 4, r.ttl) || !ReadU16(c.d, c.n, end + 8, rdlen)) {
        return Fail(c, 2, end, "resource record header is truncated");
    }
    r.cacheFlush = (r.type != 41) && (cls & 0x8000u) != 0;
    r.rclass = (r.type == 41) ? cls : static_cast<uint16_t>(cls & 0x7FFFu);
    AddNode(c, 2, end, 2, Format("Type: %s (%u)", TypeName(r.type).c_str(), r.type));
    RecordClassLine(c, end + 2, r, cls);
    AddNode(c, 2, end + 4, 4, Format("Time to live: %u s", r.ttl));
    AddNode(c, 2, end + 8, 2, Format("Data length: %u", rdlen));
    const size_t rd = end + 10;
    if (rd + rdlen > c.n) {
        return Fail(c, 2, rd, Format("record data (%u bytes) runs past the end of the packet", rdlen));
    }
    if (!DecodeRdata(c, 2, r.type, rd, rdlen, r.data)) {
        return false;
    }
    pos = rd + rdlen;
    c.m.tree[line].text = RecordHeadline(index, r);
    SetNodeLength(c, line, pos - start);
    c.m.records.push_back(std::move(r));
    return true;
}

const char* SectionTitle(Section s)
{
    switch (s) {
    case Section::Question: return "Questions";
    case Section::Answer: return "Answers";
    case Section::Authority: return "Authority";
    default: return "Additional records";
    }
}

bool DecodeSection(Ctx& c, size_t& pos, Section s)
{
    const unsigned count = c.m.counts[static_cast<int>(s)];
    if (count == 0) {
        return true;
    }
    const size_t start = pos;
    const size_t line = AddNode(c, 0, start, 0, Format("%s (%u)", SectionTitle(s), count));
    bool ok = true;
    for (unsigned i = 0; i < count && ok; ++i) {
        if (c.m.questions.size() + c.m.records.size() >= kMaxRecords) {
            ok = Fail(c, 1, pos, Format("more than %zu entries; decoding stopped", kMaxRecords));
        } else if (pos >= c.n) {
            ok = Fail(c, 1, pos, Format("header claims %u %s but the packet ends after %u", count,
                                        SectionTitle(s), i));
        } else {
            ok = (s == Section::Question) ? DecodeQuestion(c, pos, i + 1) : DecodeRecord(c, pos, s, i + 1);
        }
    }
    SetNodeLength(c, line, pos - start);
    return ok;
}

std::string Truncate(const std::string& s, size_t max)
{
    assert(max > 3);
    return s.size() <= max ? s : s.substr(0, max - 3) + "...";
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::string TypeName(uint16_t type)
{
    switch (type) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 13: return "HINFO";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 39: return "DNAME";
    case 41: return "OPT";
    case 47: return "NSEC";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    case 255: return "ANY";
    default: return Format("TYPE%u", type);
    }
}

std::string ClassName(uint16_t rclass)
{
    switch (rclass) {
    case 1: return "IN";
    case 3: return "CH";
    case 4: return "HS";
    case 255: return "ANY";
    default: return Format("CLASS%u", rclass);
    }
}

bool Decode(const uint8_t* data, size_t size, Message& out)
{
    out = Message{};
    if (data == nullptr || size < kHeaderSize) {
        out.error = Format("packet is %zu bytes, shorter than the 12-byte header", size);
        return false;
    }
    Ctx c{data, size, out};
    DecodeHeader(c);
    size_t pos = kHeaderSize;
    const Section order[4] = {Section::Question, Section::Answer, Section::Authority, Section::Additional};
    bool ok = true;
    for (int i = 0; i < 4 && ok; ++i) {
        ok = DecodeSection(c, pos, order[i]);
    }
    if (ok && pos < size) {
        AddNode(c, 0, pos, size - pos, Format("Trailing bytes: %zu", size - pos));
    }
    out.complete = ok;
    assert(ok == out.error.empty());
    return ok;
}

std::string Summarize(const Message& msg)
{
    std::string s = msg.IsResponse() ? "Response" : "Query";
    size_t shown = 0;
    size_t total = 0;
    if (msg.IsResponse()) {
        for (const Record& r : msg.records) {
            if (r.section != Section::Answer) {
                continue;
            }
            if (shown < 3) {
                s += (shown == 0 ? " " : "; ") + TypeName(r.type) + " " + r.name + " = " + Truncate(r.data, 60);
                ++shown;
            }
            ++total;
        }
        if (total == 0) {
            s += Format(" (no answers; %zu other records)", msg.records.size());
        }
    } else {
        for (const Question& q : msg.questions) {
            if (shown < 4) {
                s += (shown == 0 ? " " : ", ") + TypeName(q.type) + " " + q.name + (q.unicastResponse ? " (QU)" : "");
                ++shown;
            }
            ++total;
        }
        if (msg.counts[1] > 0) {
            s += Format(" [%u known answers]", msg.counts[1]);
        }
    }
    if (total > shown) {
        s += Format(" (+%zu more)", total - shown);
    }
    if (!msg.error.empty()) {
        s += " [MALFORMED: " + msg.error + "]";
    }
    return s;
}

} // namespace mdns

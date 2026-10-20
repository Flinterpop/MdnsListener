// DNS / mDNS wire-format decoder (RFC 1035, RFC 6762, RFC 6763).
//
// Decode() never trusts the packet: every read is bounds-checked, name
// decompression is iterative with a fixed step limit, and a malformed packet
// produces a partial decode plus an error string rather than a crash.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mdns {

constexpr uint16_t kPort = 5353;
constexpr size_t kHeaderSize = 12;
constexpr size_t kMaxNameLength = 255;   // RFC 1035 3.1, presentation form
constexpr int kMaxNameSteps = 128;       // labels + pointers followed per name
constexpr size_t kMaxRecords = 1024;     // per message, all sections together

enum class Section : uint8_t { Question, Answer, Authority, Additional };

// One line of the decode tree, flattened: depth gives the nesting, so the
// GUI builds the tree with a parent stack instead of recursion.
struct Node {
    uint8_t depth = 0;
    uint16_t offset = 0;   // first byte in the packet this line describes
    uint16_t length = 0;   // bytes covered; 0 for a purely descriptive line
    std::string text;
};

struct Question {
    std::string name;
    uint16_t type = 0;
    uint16_t qclass = 0;          // class with the QU bit removed
    bool unicastResponse = false; // RFC 6762 5.4, top bit of QCLASS
};

struct Record {
    Section section = Section::Answer;
    std::string name;
    uint16_t type = 0;
    uint16_t rclass = 0;          // class with the cache-flush bit removed
    bool cacheFlush = false;      // RFC 6762 10.2, top bit of RRCLASS
    uint32_t ttl = 0;
    std::string data;             // RDATA in presentation form, one line
};

struct Message {
    uint16_t id = 0;
    uint16_t flags = 0;
    uint16_t counts[4] = {0, 0, 0, 0}; // QD, AN, NS, AR as the header claims
    std::vector<Question> questions;
    std::vector<Record> records;
    std::vector<Node> tree;
    bool complete = false;        // every claimed entry decoded, no error
    std::string error;            // first problem found, empty when complete

    bool IsResponse() const { return (flags & 0x8000u) != 0; }
};

// Decodes one UDP payload. Returns false when the packet is malformed;
// whatever was decoded before the fault is still in `out`.
bool Decode(const uint8_t* data, size_t size, Message& out);

// One-line description for the log, e.g. "Query PTR _airplay._tcp.local".
std::string Summarize(const Message& msg);

// Mnemonic for an RR type ("PTR"), or "TYPE65" (RFC 3597) when unknown.
std::string TypeName(uint16_t type);

// Mnemonic for a class ("IN"), or "CLASS7".
std::string ClassName(uint16_t rclass);

} // namespace mdns

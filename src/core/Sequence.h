// Message sequence chart model for one mDNS exchange.
//
// Every multicast mDNS message is addressed to the group, so a chart of
// "who sent what to whom" is only meaningful per name: the messages that ask
// about, or answer for, the names of one selected message. Queries are drawn
// to the group; a multicast response is drawn to the host whose query it
// answers when one asked for the same name within kMatchWindow before it
// (an inference, and labelled as one), otherwise to the group as an
// announcement or goodbye. Unicast messages go to their real destination.
#pragma once

#include "Dns.h"

#include <cstdint>
#include <string>
#include <vector>

namespace mdns {

constexpr size_t kMaxSeqNames = 64;          // per list
constexpr int kMaxLifelines = 16;            // including the group and "other hosts"
constexpr uint64_t kMatchWindow = 10000000;  // 1 s in FILETIME ticks (RFC 6762 6: <= 500 ms normally)

// Names a message is about, lower-cased (DNS names compare case-insensitively).
struct NameSet {
    std::vector<std::string> asked;    // question names
    std::vector<std::string> owners;   // answer-section owner names
    std::vector<std::string> targets;  // answer-section PTR targets (service instances)
};

NameSet CollectNames(const Message& msg);

// True when any name in `a` appears in any list of `b`.
bool Shares(const NameSet& a, const NameSet& b);

// True for 224.0.0.251, ff02::fb, or an unknown destination ("?").
bool IsGroupAddress(const std::string& address);

struct SeqMessage {
    uint64_t seq = 0;
    uint64_t time = 0;
    std::string source;
    std::string destination;
    const Message* msg = nullptr;
    NameSet names;
};

enum class ArrowKind : uint8_t { Query, Response, Announcement, Goodbye, Unicast };

struct SeqArrow {
    uint64_t seq = 0;
    uint64_t time = 0;
    int from = 0;
    int to = 0;
    ArrowKind kind = ArrowKind::Query;
    std::string label;    // what was sent
    std::string note;     // why it is drawn where it is
};

struct SeqChart {
    std::vector<std::string> lifelines;   // addresses; the last is the group
    std::vector<SeqArrow> arrows;
};

// `msgs` must be in arrival order. Lifelines are hosts in order of first
// appearance, capped at kMaxLifelines with the overflow merged into one
// "(other hosts)" lifeline, then the group.
SeqChart BuildSequence(const std::vector<SeqMessage>& msgs);

constexpr char kGroupLifeline[] = "mDNS group";
constexpr char kOtherLifeline[] = "(other hosts)";

} // namespace mdns

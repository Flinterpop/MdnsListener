// Per-host summary of the mDNS traffic seen. A "conversation" is everything
// one source address has sent to the group: in mDNS every message goes to
// the same multicast address, so the sender is the only useful key.
#pragma once

#include "Dns.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace mdns {

struct Conversation {
    std::string address;               // source address, IPv6 with %zone
    std::string hostName;              // first A/AAAA owner it announced
    uint32_t packets = 0;
    uint32_t queries = 0;
    uint32_t responses = 0;
    uint32_t malformed = 0;
    uint64_t bytes = 0;
    uint64_t firstSeen = 0;            // FILETIME ticks (100 ns, UTC)
    uint64_t lastSeen = 0;
    std::vector<std::string> ports;    // distinct source ports, bounded
    std::vector<std::string> announced;// hosts and service instances it answered for
    std::vector<std::string> asked;    // names it asked about
};

class ConversationTable {
public:
    static constexpr size_t kMaxConversations = 4096;
    static constexpr size_t kMaxNames = 64;   // per list, per conversation

    // Folds one message into the table. Returns the conversation's index,
    // or -1 when the table is full and the address is new.
    int Add(const std::string& address, uint16_t port, const Message& msg, size_t bytes, uint64_t time);

    const std::vector<Conversation>& Items() const { return items_; }

    // Index of an address's conversation, or -1.
    int Find(const std::string& address) const
    {
        const auto it = index_.find(address);
        return it == index_.end() ? -1 : static_cast<int>(it->second);
    }
    void Clear();

private:
    std::vector<Conversation> items_;
    std::unordered_map<std::string, size_t> index_;
};

// Joins a name list for display: "a, b, c".
std::string JoinNames(const std::vector<std::string>& names);

} // namespace mdns

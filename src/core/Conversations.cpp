#include "Conversations.h"

#include <algorithm>
#include <cassert>

namespace mdns {
namespace {

void AddDistinct(std::vector<std::string>& list, const std::string& name)
{
    assert(list.size() <= ConversationTable::kMaxNames);
    if (name.empty() || list.size() >= ConversationTable::kMaxNames) {
        return;
    }
    if (std::find(list.begin(), list.end(), name) == list.end()) {
        list.push_back(name);
    }
}

void FoldResponse(Conversation& conv, const Message& msg)
{
    for (const Record& r : msg.records) {
        if (r.section == Section::Authority) {
            continue;   // probe tiebreak data, not a claim
        }
        if (r.type == 1 || r.type == 28) {
            if (conv.hostName.empty()) {
                conv.hostName = r.name;
            }
            AddDistinct(conv.announced, r.name);
        } else if (r.type == 33) {
            AddDistinct(conv.announced, r.name);
        } else if (r.type == 12 && !r.name.empty() && r.name[0] == '_' &&
                   r.name.rfind("_services._dns-sd._udp.", 0) != 0) {
            AddDistinct(conv.announced, r.data);
        }
    }
}

} // namespace

int ConversationTable::Add(const std::string& address, uint16_t port, const Message& msg, size_t bytes,
                           uint64_t time)
{
    assert(!address.empty());
    assert(items_.size() == index_.size());
    size_t i = 0;
    const auto it = index_.find(address);
    if (it != index_.end()) {
        i = it->second;
    } else {
        if (items_.size() >= kMaxConversations) {
            return -1;
        }
        i = items_.size();
        Conversation fresh;
        fresh.address = address;
        fresh.firstSeen = time;
        items_.push_back(std::move(fresh));
        index_.emplace(address, i);
    }
    Conversation& conv = items_[i];
    ++conv.packets;
    conv.bytes += bytes;
    conv.lastSeen = time;
    AddDistinct(conv.ports, std::to_string(port));
    if (!msg.error.empty()) {
        ++conv.malformed;
    }
    if (msg.IsResponse()) {
        ++conv.responses;
        FoldResponse(conv, msg);
    } else {
        ++conv.queries;
        for (const Question& q : msg.questions) {
            AddDistinct(conv.asked, q.name);
        }
    }
    assert(i < items_.size());
    return static_cast<int>(i);
}

void ConversationTable::Clear()
{
    items_.clear();
    index_.clear();
    assert(items_.empty() && index_.empty());
}

std::string JoinNames(const std::vector<std::string>& names)
{
    std::string s;
    for (const std::string& n : names) {
        if (!s.empty()) {
            s += ", ";
        }
        s += n;
    }
    if (names.size() >= ConversationTable::kMaxNames) {
        s += ", ...";
    }
    return s;
}

} // namespace mdns

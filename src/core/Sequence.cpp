#include "Sequence.h"

#include <algorithm>
#include <cassert>
#include <cstdio>

namespace mdns {
namespace {

std::string Lower(const std::string& s)
{
    std::string out = s;
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

void AddName(std::vector<std::string>& list, const std::string& name)
{
    assert(list.size() <= kMaxSeqNames);
    if (name.empty() || list.size() >= kMaxSeqNames) {
        return;
    }
    const std::string key = Lower(name);
    if (std::find(list.begin(), list.end(), key) == list.end()) {
        list.push_back(key);
    }
    assert(list.size() <= kMaxSeqNames);
}

bool InAny(const std::string& name, const NameSet& set)
{
    assert(!name.empty());   // AddName never stores one
    assert(set.asked.size() <= kMaxSeqNames && set.owners.size() <= kMaxSeqNames &&
           set.targets.size() <= kMaxSeqNames);   // bounds the three searches
    const auto has = [&name](const std::vector<std::string>& l) {
        return std::find(l.begin(), l.end(), name) != l.end();
    };
    return has(set.asked) || has(set.owners) || has(set.targets);
}

bool Intersects(const std::vector<std::string>& a, const std::vector<std::string>& b)
{
    assert(a.size() <= kMaxSeqNames && b.size() <= kMaxSeqNames);   // at most 64 x 64 compares
    for (const std::string& n : a) {
        if (std::find(b.begin(), b.end(), n) != b.end()) {
            return true;
        }
    }
    return false;
}

std::string Shorten(const std::string& s, size_t max)
{
    assert(max > 3);
    std::string t = s.size() <= max ? s : s.substr(0, max - 3) + "...";
    assert(t.size() <= max);
    return t;
}

std::string Millis(uint64_t ticks)
{
    char buf[32];
    const int r = std::snprintf(buf, sizeof(buf), "%llu ms", static_cast<unsigned long long>(ticks / 10000));
    assert(r > 0 && r < static_cast<int>(sizeof(buf)));   // at most 20 digits and " ms"
    return r > 0 ? std::string(buf) : std::string("? ms");
}

bool IsGoodbye(const Message& m)
{
    assert(m.IsResponse());   // MakeArrow asks only of responses
    assert(m.records.size() <= kMaxRecords);
    bool any = false;
    for (const Record& r : m.records) {
        if (r.section != Section::Answer) {
            continue;
        }
        if (r.ttl != 0) {
            return false;
        }
        any = true;
    }
    return any;
}

class Lifelines {
public:
    explicit Lifelines(SeqChart& chart) : chart_(chart) {}

    int For(const std::string& address)
    {
        assert(!address.empty());
        const auto& l = chart_.lifelines;
        const auto it = std::find(l.begin(), l.end(), address);
        if (it != l.end()) {
            return static_cast<int>(it - l.begin());
        }
        // Keep room for "(other hosts)" and the group.
        if (static_cast<int>(l.size()) < kMaxLifelines - 2) {
            chart_.lifelines.push_back(address);
            return static_cast<int>(l.size()) - 1;
        }
        if (other_ < 0) {
            chart_.lifelines.push_back(kOtherLifeline);
            other_ = static_cast<int>(l.size()) - 1;
        }
        return other_;
    }

private:
    SeqChart& chart_;
    int other_ = -1;
};

constexpr int kGroupPending = -1;   // replaced by the group's index at the end

// Index of the latest query, before `i` and within the window, from another
// host, asking for a name `i` answers. -1 when there is none.
int FindQuery(const std::vector<SeqMessage>& msgs, size_t i)
{
    assert(i < msgs.size());
    assert(msgs[i].msg != nullptr && msgs[i].msg->IsResponse());   // only a response answers
    const SeqMessage& r = msgs[i];
    for (size_t k = i; k-- > 0;) {
        const SeqMessage& q = msgs[k];
        if (r.time - q.time > kMatchWindow || q.time > r.time) {
            break;
        }
        if (q.msg != nullptr && !q.msg->IsResponse() && q.source != r.source &&
            Intersects(r.names.owners, q.names.asked)) {
            return static_cast<int>(k);
        }
    }
    return -1;
}

SeqArrow MakeArrow(const std::vector<SeqMessage>& msgs, size_t i, Lifelines& lanes)
{
    assert(i < msgs.size());
    const SeqMessage& m = msgs[i];
    assert(m.msg != nullptr);
    SeqArrow a;
    a.seq = m.seq;
    a.time = m.time;
    a.from = lanes.For(m.source);
    a.label = Shorten(Summarize(*m.msg), 90);
    if (!IsGroupAddress(m.destination)) {
        a.kind = ArrowKind::Unicast;
        a.to = lanes.For(m.destination);
        a.note = "unicast to " + m.destination;
    } else if (!m.msg->IsResponse()) {
        a.kind = ArrowKind::Query;
        a.to = kGroupPending;
        a.note = "multicast query";
    } else if (IsGoodbye(*m.msg)) {
        a.kind = ArrowKind::Goodbye;
        a.to = kGroupPending;
        a.note = "goodbye: TTL 0, withdraws the records";
    } else {
        const int q = FindQuery(msgs, i);
        if (q >= 0) {
            a.kind = ArrowKind::Response;
            a.to = lanes.For(msgs[static_cast<size_t>(q)].source);
            a.note = "multicast; answers #" + std::to_string(msgs[static_cast<size_t>(q)].seq) + " after " +
                     Millis(m.time - msgs[static_cast<size_t>(q)].time) + " (inferred)";
        } else {
            a.kind = ArrowKind::Announcement;
            a.to = kGroupPending;
            a.note = "unsolicited: announcement or answer to an unseen query";
        }
    }
    assert(a.from >= 0 && (a.to >= 0 || a.to == kGroupPending));
    return a;
}

} // namespace

NameSet CollectNames(const Message& msg)
{
    assert(msg.questions.size() + msg.records.size() <= kMaxRecords);   // Decode stops there
    NameSet s;
    for (const Question& q : msg.questions) {
        AddName(s.asked, q.name);
    }
    for (const Record& r : msg.records) {
        if (r.section != Section::Answer || r.type == 41) {
            continue;
        }
        AddName(s.owners, r.name);
        if (r.type == 12) {
            AddName(s.targets, r.data);
        }
    }
    assert(s.asked.size() <= kMaxSeqNames && s.owners.size() <= kMaxSeqNames &&
           s.targets.size() <= kMaxSeqNames);
    return s;
}

bool Shares(const NameSet& a, const NameSet& b)
{
    assert(a.asked.size() <= kMaxSeqNames && a.owners.size() <= kMaxSeqNames &&
           a.targets.size() <= kMaxSeqNames);   // InAny checks b's
    for (const auto* list : {&a.asked, &a.owners, &a.targets}) {
        for (const std::string& n : *list) {
            if (InAny(n, b)) {
                return true;
            }
        }
    }
    return false;
}

bool IsGroupAddress(const std::string& address)
{
    return address == "?" || address == "224.0.0.251" || Lower(address) == "ff02::fb" || address.empty();
}

SeqChart BuildSequence(const std::vector<SeqMessage>& msgs)
{
    SeqChart chart;
    Lifelines lanes(chart);
    for (size_t i = 0; i < msgs.size(); ++i) {
        if (msgs[i].msg != nullptr) {
            chart.arrows.push_back(MakeArrow(msgs, i, lanes));
        }
    }
    chart.lifelines.push_back(kGroupLifeline);
    const int group = static_cast<int>(chart.lifelines.size()) - 1;
    for (SeqArrow& a : chart.arrows) {
        if (a.to == kGroupPending) {
            a.to = group;
        }
        assert(a.from >= 0 && a.from < group && a.to >= 0 && a.to <= group);
    }
    assert(static_cast<int>(chart.lifelines.size()) <= kMaxLifelines);
    return chart;
}

} // namespace mdns

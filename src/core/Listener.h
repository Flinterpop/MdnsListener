// Passive mDNS receiver: binds UDP 5353 (shared, SO_REUSEADDR) on IPv4 and
// IPv6, joins 224.0.0.251 and ff02::fb on every interface that is up, and
// queues every datagram it hears. It never transmits.
#pragma once

#include <winsock2.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace mdns {

struct Packet {
    uint64_t time = 0;          // FILETIME ticks (100 ns, UTC)
    bool ipv6 = false;
    std::string source;         // address only; IPv6 carries %zone
    uint16_t sourcePort = 0;
    std::string destination;    // from IP_PKTINFO; "?" when not delivered
    uint32_t ifIndex = 0;
    std::string ifName;         // set for packets read from a capture file
    bool truncated = false;     // only part of the datagram was received or captured
    std::vector<uint8_t> data;
};

class Listener {
public:
    static constexpr size_t kMaxQueued = 20000;     // packets awaiting Drain
    static constexpr size_t kReceiveBuffer = 65536;

    Listener() = default;
    ~Listener();
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

    // Opens the sockets, joins the groups and starts the receive thread.
    // `status` describes what was joined, or why nothing could be.
    bool Start(std::string& status);
    void Stop();
    bool Running() const { return thread_.joinable(); }

    // Moves every queued packet onto the end of `out`.
    void Drain(std::vector<Packet>& out);

    // Packets thrown away because the queue was full.
    uint64_t Dropped() const { return dropped_.load(); }

    // Friendly name of an interface index, as of the last Start().
    std::string InterfaceName(uint32_t ifIndex) const;

private:
    bool OpenV4(std::string& status);
    bool OpenV6(std::string& status);
    bool LoadRecvMsg(SOCKET s);
    void EnumerateInterfaces();
    void Run();
    void ReceiveOne(SOCKET s, bool ipv6);
    void CloseSockets();

    struct Adapter {
        uint32_t ifIndex = 0;       // IPv4 index
        uint32_t ipv6IfIndex = 0;
        in_addr ipv4{};             // first unicast IPv4 address
        bool hasIpv4 = false;
        std::string name;
    };

    SOCKET v4_ = INVALID_SOCKET;
    SOCKET v6_ = INVALID_SOCKET;
    // WSARecvMsg is only reachable as an extension function pointer; this is
    // the one function pointer in the program (Power of 10 deviation).
    void* recvMsg_ = nullptr;
    std::vector<Adapter> adapters_;
    std::map<uint32_t, std::string> ifNames_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::atomic<uint64_t> dropped_{0};
    std::mutex lock_;
    std::vector<Packet> queue_;
    std::vector<char> rx_;
};

} // namespace mdns

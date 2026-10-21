#include "Listener.h"

#include "Dns.h"

#include <iphlpapi.h>
#include <mswsock.h>
#include <ws2tcpip.h>

#include <cassert>
#include <cstdio>

namespace mdns {
namespace {

constexpr int kMaxAdapters = 256;
constexpr int kMaxControlHeaders = 16;

std::string Narrow(const wchar_t* w)
{
    if (w == nullptr || *w == L'\0') {
        return std::string();
    }
    char buf[512] = {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, sizeof(buf), nullptr, nullptr);
    return n > 0 ? std::string(buf) : std::string();
}

std::string WsaError(const char* what)
{
    assert(what != nullptr);
    char buf[160];
    const int r = std::snprintf(buf, sizeof(buf), "%s failed (WSA error %d)", what, WSAGetLastError());
    assert(r > 0);   // a literal and an int; truncation at 160 is acceptable
    return r > 0 ? std::string(buf) : std::string(what);
}

std::string AddressText(const sockaddr* sa)
{
    assert(sa != nullptr);
    assert(sa->sa_family == AF_INET || sa->sa_family == AF_INET6);   // from our own two sockets
    char buf[INET6_ADDRSTRLEN + 16] = {};
    if (sa->sa_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
        return inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf)) != nullptr ? buf : "?";
    }
    const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
    if (inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf)) == nullptr) {
        return "?";
    }
    std::string s = buf;
    if (in6->sin6_scope_id != 0) {
        s += "%" + std::to_string(in6->sin6_scope_id);
    }
    return s;
}

uint16_t PortOf(const sockaddr* sa)
{
    assert(sa != nullptr);
    assert(sa->sa_family == AF_INET || sa->sa_family == AF_INET6);
    if (sa->sa_family == AF_INET) {
        return ntohs(reinterpret_cast<const sockaddr_in*>(sa)->sin_port);
    }
    return ntohs(reinterpret_cast<const sockaddr_in6*>(sa)->sin6_port);
}

uint64_t Now()
{
    FILETIME ft{};
    GetSystemTimePreciseAsFileTime(&ft);
    const uint64_t t = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    assert(t != 0);   // 0 means "no time" to the capture reader and the GUI
    return t;
}

bool SetInt(SOCKET s, int level, int name, DWORD value)
{
    assert(s != INVALID_SOCKET);
    assert(level == SOL_SOCKET || level == IPPROTO_IP || level == IPPROTO_IPV6);
    return setsockopt(s, level, name, reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
}

} // namespace

Listener::~Listener()
{
    Stop();
    assert(!Running());
    assert(v4_ == INVALID_SOCKET && v6_ == INVALID_SOCKET);
}

void Listener::EnumerateInterfaces()
{
    assert(!Running());   // the receive thread must not see the lists change
    adapters_.clear();
    ifNames_.clear();
    ULONG size = 32 * 1024;
    std::vector<uint8_t> buf;
    ULONG r = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && r == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf.assign(size, 0);
        r = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                 GAA_FLAG_SKIP_DNS_SERVER, nullptr,
                                 reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    }
    if (r != NO_ERROR) {
        return;
    }
    const auto* a = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buf.data());
    for (int i = 0; a != nullptr && i < kMaxAdapters; a = a->Next, ++i) {
        Adapter ad;
        ad.ifIndex = a->IfIndex;
        ad.ipv6IfIndex = a->Ipv6IfIndex;
        ad.name = Narrow(a->FriendlyName);
        if (ad.ifIndex != 0) {
            ifNames_[ad.ifIndex] = ad.name;
        }
        if (ad.ipv6IfIndex != 0) {
            ifNames_[ad.ipv6IfIndex] = ad.name;
        }
        if (a->OperStatus != IfOperStatusUp) {
            continue;
        }
        const IP_ADAPTER_UNICAST_ADDRESS* u = a->FirstUnicastAddress;
        for (int j = 0; u != nullptr && j < 64 && !ad.hasIpv4; u = u->Next, ++j) {
            if (u->Address.lpSockaddr->sa_family == AF_INET) {
                ad.ipv4 = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr)->sin_addr;
                ad.hasIpv4 = true;
            }
        }
        adapters_.push_back(ad);
    }
    assert(adapters_.size() <= static_cast<size_t>(kMaxAdapters));
}

bool Listener::LoadRecvMsg(SOCKET s)
{
    assert(s != INVALID_SOCKET);
    if (recvMsg_ != nullptr) {
        return true;
    }
    GUID guid = WSAID_WSARECVMSG;
    LPFN_WSARECVMSG fn = nullptr;
    DWORD bytes = 0;
    if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &fn, sizeof(fn), &bytes,
                 nullptr, nullptr) != 0 || fn == nullptr) {
        return false;
    }
    recvMsg_ = reinterpret_cast<void*>(fn);
    assert(recvMsg_ != nullptr);   // ReceiveOne calls through it
    return true;
}

bool Listener::OpenV4(std::string& status)
{
    assert(v4_ == INVALID_SOCKET);   // a second open would leak the first socket
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        status += "IPv4: " + WsaError("socket") + ". ";
        return false;
    }
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(kPort);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (!SetInt(s, SOL_SOCKET, SO_REUSEADDR, 1) || !SetInt(s, IPPROTO_IP, IP_PKTINFO, 1) ||
        bind(s, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0 || !LoadRecvMsg(s)) {
        status += "IPv4: " + WsaError("bind to UDP 5353") + ". ";
        (void)closesocket(s);   // abandoning it; the bind failure is what gets reported
        return false;
    }
    assert(recvMsg_ != nullptr);
    in_addr group{};
    const int parsed = inet_pton(AF_INET, "224.0.0.251", &group);
    assert(parsed == 1);   // a constant
    int joined = 0;
    for (const Adapter& a : adapters_) {
        if (!a.hasIpv4 || parsed != 1) {
            continue;
        }
        ip_mreq mreq{};
        mreq.imr_multiaddr = group;
        mreq.imr_interface = a.ipv4;
        if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, reinterpret_cast<const char*>(&mreq),
                       sizeof(mreq)) == 0) {
            ++joined;
        }
    }
    status += "IPv4 224.0.0.251 on " + std::to_string(joined) + " interfaces. ";
    v4_ = s;
    return joined > 0;
}

bool Listener::OpenV6(std::string& status)
{
    assert(v6_ == INVALID_SOCKET);   // a second open would leak the first socket
    SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        status += "IPv6: " + WsaError("socket") + ". ";
        return false;
    }
    sockaddr_in6 local{};
    local.sin6_family = AF_INET6;
    local.sin6_port = htons(kPort);
    local.sin6_addr = in6addr_any;
    if (!SetInt(s, IPPROTO_IPV6, IPV6_V6ONLY, 1) || !SetInt(s, SOL_SOCKET, SO_REUSEADDR, 1) ||
        !SetInt(s, IPPROTO_IPV6, IPV6_PKTINFO, 1) ||
        bind(s, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0 || !LoadRecvMsg(s)) {
        status += "IPv6: " + WsaError("bind to UDP 5353") + ". ";
        (void)closesocket(s);   // abandoning it; the bind failure is what gets reported
        return false;
    }
    assert(recvMsg_ != nullptr);
    in6_addr group{};
    const int parsed = inet_pton(AF_INET6, "ff02::fb", &group);
    assert(parsed == 1);   // a constant
    int joined = 0;
    for (const Adapter& a : adapters_) {
        if (a.ipv6IfIndex == 0 || parsed != 1) {
            continue;
        }
        ipv6_mreq mreq{};
        mreq.ipv6mr_multiaddr = group;
        mreq.ipv6mr_interface = a.ipv6IfIndex;
        if (setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, reinterpret_cast<const char*>(&mreq),
                       sizeof(mreq)) == 0) {
            ++joined;
        }
    }
    status += "IPv6 ff02::fb on " + std::to_string(joined) + " interfaces.";
    v6_ = s;
    return joined > 0;
}

bool Listener::Start(std::string& status)
{
    assert(!Running());
    status.clear();
    if (Running()) {
        return true;
    }
    EnumerateInterfaces();
    rx_.assign(kReceiveBuffer, 0);
    const bool ok4 = OpenV4(status);
    const bool ok6 = OpenV6(status);
    if (!ok4 && !ok6) {
        CloseSockets();
        return false;
    }
    stop_ = false;
    thread_ = std::thread([this] { Run(); });
    assert(Running());
    return true;
}

void Listener::CloseSockets()
{
    assert(!Running());   // the receive thread selects on these
    if (v4_ != INVALID_SOCKET) {
        (void)closesocket(v4_);   // teardown: nothing to do if closing fails
        v4_ = INVALID_SOCKET;
    }
    if (v6_ != INVALID_SOCKET) {
        (void)closesocket(v6_);
        v6_ = INVALID_SOCKET;
    }
    assert(v4_ == INVALID_SOCKET && v6_ == INVALID_SOCKET);
}

void Listener::Stop()
{
    stop_ = true;
    if (thread_.joinable()) {
        thread_.join();
    }
    assert(!Running());
    CloseSockets();
    assert(v4_ == INVALID_SOCKET && v6_ == INVALID_SOCKET);
}

// The receive loop runs until Stop(); it is the one unbounded loop in the
// program, by design (Power of 10 rule 2 deviation, as for any event pump).
void Listener::Run()
{
    assert(v4_ != INVALID_SOCKET || v6_ != INVALID_SOCKET);   // Start opened at least one
    assert(recvMsg_ != nullptr);
    while (!stop_) {
        fd_set rd;
        FD_ZERO(&rd);
        if (v4_ != INVALID_SOCKET) {
            FD_SET(v4_, &rd);
        }
        if (v6_ != INVALID_SOCKET) {
            FD_SET(v6_, &rd);
        }
        timeval tv{0, 200 * 1000};
        const int r = select(0, &rd, nullptr, nullptr, &tv);
        if (r == SOCKET_ERROR) {
            Sleep(200);
            continue;
        }
        if (r > 0 && v4_ != INVALID_SOCKET && FD_ISSET(v4_, &rd)) {
            ReceiveOne(v4_, false);
        }
        if (r > 0 && v6_ != INVALID_SOCKET && FD_ISSET(v6_, &rd)) {
            ReceiveOne(v6_, true);
        }
    }
}

void Listener::ReceiveOne(SOCKET s, bool ipv6)
{
    assert(recvMsg_ != nullptr);
    assert(rx_.size() == kReceiveBuffer);
    sockaddr_storage from{};
    char control[256] = {};
    WSABUF buf{static_cast<ULONG>(rx_.size()), rx_.data()};
    WSAMSG msg{};
    msg.name = reinterpret_cast<LPSOCKADDR>(&from);
    msg.namelen = sizeof(from);
    msg.lpBuffers = &buf;
    msg.dwBufferCount = 1;
    msg.Control.buf = control;
    msg.Control.len = sizeof(control);
    DWORD got = 0;
    const auto fn = reinterpret_cast<LPFN_WSARECVMSG>(recvMsg_);
    if (fn(s, &msg, &got, nullptr, nullptr) != 0 && WSAGetLastError() != WSAEMSGSIZE) {
        return;
    }
    Packet p;
    p.time = Now();
    p.ipv6 = ipv6;
    p.source = AddressText(reinterpret_cast<const sockaddr*>(&from));
    p.sourcePort = PortOf(reinterpret_cast<const sockaddr*>(&from));
    p.destination = "?";
    p.truncated = (msg.dwFlags & MSG_TRUNC) != 0;
    char dst[INET6_ADDRSTRLEN] = {};
    WSACMSGHDR* h = WSA_CMSG_FIRSTHDR(&msg);
    for (int i = 0; h != nullptr && i < kMaxControlHeaders; h = WSA_CMSG_NXTHDR(&msg, h), ++i) {
        if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_PKTINFO) {
            const auto* pi = reinterpret_cast<const IN_PKTINFO*>(WSA_CMSG_DATA(h));
            p.ifIndex = pi->ipi_ifindex;
            p.destination = inet_ntop(AF_INET, &pi->ipi_addr, dst, sizeof(dst)) ? dst : "?";
        } else if (h->cmsg_level == IPPROTO_IPV6 && h->cmsg_type == IPV6_PKTINFO) {
            const auto* pi = reinterpret_cast<const IN6_PKTINFO*>(WSA_CMSG_DATA(h));
            p.ifIndex = pi->ipi6_ifindex;
            p.destination = inet_ntop(AF_INET6, &pi->ipi6_addr, dst, sizeof(dst)) ? dst : "?";
        }
    }
    const size_t n = got > rx_.size() ? rx_.size() : got;
    p.data.assign(rx_.begin(), rx_.begin() + static_cast<ptrdiff_t>(n));
    std::lock_guard<std::mutex> guard(lock_);
    if (queue_.size() >= kMaxQueued) {
        ++dropped_;
        return;
    }
    queue_.push_back(std::move(p));
}

void Listener::Drain(std::vector<Packet>& out)
{
    std::lock_guard<std::mutex> guard(lock_);
    assert(queue_.size() <= kMaxQueued);
    for (Packet& p : queue_) {
        out.push_back(std::move(p));
    }
    queue_.clear();
    assert(queue_.empty());
}

std::string Listener::InterfaceName(uint32_t ifIndex) const
{
    const auto it = ifNames_.find(ifIndex);
    if (it != ifNames_.end() && !it->second.empty()) {
        return it->second;
    }
    return ifIndex == 0 ? std::string("?") : "#" + std::to_string(ifIndex);
}

} // namespace mdns

#include "transport.h"
#include <winsock2.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>
#include <cstring>
#include "../log.h"

namespace {

#pragma pack(push, 1)
struct PktHdr {
    uint8_t  magic[2]; // 'E', 'P'
    int16_t  channel;
    uint64_t sender_sid;
};
#pragma pack(pop)

struct InPkt {
    uint64_t sid;
    std::vector<uint8_t> data;
};

SOCKET g_sock = INVALID_SOCKET;
uint16_t g_bound_port = 0;
std::atomic<uint64_t> g_local_sid{0};

std::mutex g_mu;
std::unordered_map<uint64_t, sockaddr_in> g_peers;
std::unordered_map<int, std::deque<InPkt>> g_inq;
std::unordered_set<uint64_t> g_seen_peers;
std::deque<uint64_t> g_new_peers;
sockaddr_in g_default{};
bool g_has_default = false;
std::atomic<bool> g_run{false};

void recv_loop() {
    uint8_t buf[2048];
    while (g_run) {
        sockaddr_in from{};
        int fl = sizeof(from);
        int n = recvfrom(g_sock, (char*)buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
        if (n <= 0) continue;
        if (n >= (int)sizeof(PktHdr) && buf[0] == 'E' && buf[1] == 'P') {
            PktHdr h;
            memcpy(&h, buf, sizeof(h));
            const uint8_t* pay = buf + sizeof(PktHdr);
            int plen = n - (int)sizeof(PktHdr);
            std::lock_guard<std::mutex> lk(g_mu);
            g_peers[h.sender_sid] = from;
            g_default = from;
            g_has_default = true;
            if (g_seen_peers.insert(h.sender_sid).second) {
                g_new_peers.push_back(h.sender_sid);
                log::info("transport: first pkt from sid=0x%llx (%u.%u.%u.%u:%u) ch=%d len=%d",
                          (unsigned long long)h.sender_sid,
                          from.sin_addr.S_un.S_un_b.s_b1, from.sin_addr.S_un.S_un_b.s_b2,
                          from.sin_addr.S_un.S_un_b.s_b3, from.sin_addr.S_un.S_un_b.s_b4,
                          ntohs(from.sin_port), (int)h.channel, plen);
            }
            g_inq[(int)h.channel].push_back({h.sender_sid, std::vector<uint8_t>(pay, pay + plen)});
        }
    }
}

} // namespace

bool transport::init(uint16_t listen_port) {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd)) return false;
    g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_sock == INVALID_SOCKET) return false;

    bool bound = false;
    for (uint16_t off = 0; off < 32; ++off) {
        uint16_t p = (uint16_t)(listen_port + off);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(p);
        a.sin_addr.s_addr = INADDR_ANY;
        if (bind(g_sock, (sockaddr*)&a, sizeof(a)) == 0) {
            g_bound_port = p;
            bound = true;
            break;
        }
    }
    if (!bound) {
        log::err("transport bind failed on %u..%u err=%d", listen_port, listen_port + 31, WSAGetLastError());
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
        return false;
    }
    g_run = true;
    std::thread(recv_loop).detach();
    log::info("transport listening udp :%u", g_bound_port);
    return true;
}

void transport::shutdown() {
    g_run = false;
    if (g_sock != INVALID_SOCKET) closesocket(g_sock);
    g_sock = INVALID_SOCKET;
}

uint16_t transport::bound_port() {
    return g_bound_port;
}

void transport::set_local_steam_id(uint64_t sid) {
    g_local_sid.store(sid);
}

void transport::bind_peer(uint64_t key, uint32_t ip_nbo, uint16_t port_host) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = ip_nbo;
    a.sin_port = htons(port_host);
    bool changed = false;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_peers.find(key);
        changed = (it == g_peers.end() ||
                   it->second.sin_addr.s_addr != a.sin_addr.s_addr ||
                   it->second.sin_port != a.sin_port);
        g_peers[key] = a;
        g_default = a;
        g_has_default = true;
    }
    if (changed) {
        log::info("transport: peer bound sid=0x%llx -> %u.%u.%u.%u:%u",
                  (unsigned long long)key,
                  a.sin_addr.S_un.S_un_b.s_b1, a.sin_addr.S_un.S_un_b.s_b2,
                  a.sin_addr.S_un.S_un_b.s_b3, a.sin_addr.S_un.S_un_b.s_b4,
                  port_host);
    }
}

void transport::send_to(uint64_t key, int channel, const void* data, int len) {
    if (g_sock == INVALID_SOCKET || len < 0 || len > 1900) return;
    sockaddr_in a{};
    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_peers.find(key);
        if (it != g_peers.end()) {
            a = it->second;
        } else if (g_has_default) {
            a = g_default;
        } else {
            log::err("transport: send_to no peer sid=0x%llx ch=%d len=%d",
                     (unsigned long long)key, channel, len);
            return;
        }
    }
    uint8_t pkt[2048];
    PktHdr h{{'E', 'P'}, (int16_t)channel, g_local_sid.load()};
    memcpy(pkt, &h, sizeof(h));
    if (len > 0 && data) memcpy(pkt + sizeof(h), data, len);
    sendto(g_sock, (const char*)pkt, (int)sizeof(h) + len, 0, (sockaddr*)&a, sizeof(a));
}

int transport::recv_peek(int channel) {
    std::lock_guard<std::mutex> lk(g_mu);
    auto it = g_inq.find(channel);
    if (it == g_inq.end() || it->second.empty()) return 0;
    return (int)it->second.front().data.size();
}

bool transport::recv(int channel, void* buf, uint32_t cap, uint32_t* out_len, uint64_t* out_key) {
    std::lock_guard<std::mutex> lk(g_mu);
    auto it = g_inq.find(channel);
    if (it == g_inq.end() || it->second.empty()) return false;
    auto& front = it->second.front();
    uint32_t sz = (uint32_t)front.data.size();
    if (out_len) *out_len = sz;
    if (out_key) *out_key = front.sid;
    if (sz > cap) {
        if (buf && cap > 0) memcpy(buf, front.data.data(), cap);
        it->second.pop_front();
        return false;
    }
    if (buf && sz > 0) memcpy(buf, front.data.data(), sz);
    it->second.pop_front();
    return true;
}

void transport::close_channel(uint64_t peer_key, int channel) {
    std::lock_guard<std::mutex> lk(g_mu);
    auto it = g_inq.find(channel);
    if (it == g_inq.end()) return;
    auto& q = it->second;
    for (auto qi = q.begin(); qi != q.end();) {
        if (qi->sid == peer_key) qi = q.erase(qi);
        else ++qi;
    }
}

void transport::close_peer(uint64_t peer_key) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_seen_peers.erase(peer_key);
    for (auto& kv : g_inq) {
        auto& q = kv.second;
        for (auto qi = q.begin(); qi != q.end();) {
            if (qi->sid == peer_key) qi = q.erase(qi);
            else ++qi;
        }
    }
}

bool transport::pop_new_peer(uint64_t* out_peer) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_new_peers.empty()) return false;
    *out_peer = g_new_peers.front();
    g_new_peers.pop_front();
    return true;
}

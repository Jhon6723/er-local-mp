// Probe de ws2_32: stubs transparentes (log + passthrough) para saber si
// el login usa TCP crudo en vez de WinHTTP. FRONTERA BINARIO.
#include "ws2_probe.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "../log.h"

static void* res(const char* n) {
    return (void*)GetProcAddress(GetModuleHandleA("ws2_32.dll"), n);
}
using getaddrinfo_t = int(WINAPI*)(const char*, const char*, const ADDRINFOA*, ADDRINFOA**);
static getaddrinfo_t p_gai;
static int WINAPI h_getaddrinfo(const char* node, const char* svc, const ADDRINFOA* h, ADDRINFOA** r) {
    int rc = p_gai(node, svc, h, r);
    log::info("ws2: getaddrinfo(%s,%s) -> %d", node ? node : "?", svc ? svc : "?", rc);
    return rc;
}
using socket_t = SOCKET(WINAPI*)(int, int, int);
static socket_t p_socket;
static SOCKET WINAPI h_socket(int af, int ty, int pr) {
    SOCKET s = p_socket(af, ty, pr);
    log::info("ws2: socket(af=%d ty=%d pr=%d) -> %llu", af, ty, pr, (unsigned long long)s);
    return s;
}
using WSASocketW_t = SOCKET(WINAPI*)(int, int, int, void*, unsigned, DWORD);
static WSASocketW_t p_wsasock;
static SOCKET WINAPI h_WSASocketW(int af, int ty, int pr, void* pi, unsigned g, DWORD f) {
    SOCKET s = p_wsasock(af, ty, pr, pi, g, f);
    log::info("ws2: WSASocketW(af=%d ty=%d pr=%d) -> %llu", af, ty, pr, (unsigned long long)s);
    return s;
}
static void log_addr(const sockaddr* a) {
    if (!a) return;
    if (a->sa_family == AF_INET) {
        const auto* in = (const sockaddr_in*)a;
        log::info("ws2:   addr %u.%u.%u.%u:%u",
                  in->sin_addr.S_un.S_un_b.s_b1, in->sin_addr.S_un.S_un_b.s_b2,
                  in->sin_addr.S_un.S_un_b.s_b3, in->sin_addr.S_un.S_un_b.s_b4,
                  ntohs(in->sin_port));
    } else log::info("ws2:   addr family=%d", a->sa_family);
}
using connect_t = int(WINAPI*)(SOCKET, const sockaddr*, int);
static connect_t p_connect;
static int WINAPI h_connect(SOCKET s, const sockaddr* a, int n) {
    log::info("ws2: connect s=%llu", (unsigned long long)s);
    log_addr(a);
    int rc = p_connect(s, a, n);
    log::info("ws2:   connect -> %d (err=%d)", rc, WSAGetLastError());
    return rc;
}
using send_t = int(WINAPI*)(SOCKET, const char*, int, int);
static send_t p_send;
static int WINAPI h_send(SOCKET s, const char* b, int n, int f) {
    int rc = p_send(s, b, n, f);
    char hex[48] = {0}; int k = 0;
    for (int i = 0; i < n && i < 12; ++i) k += snprintf(hex + k, sizeof(hex) - k, "%02x", (uint8_t)b[i]);
    log::info("ws2: send s=%llu n=%d -> %d  [%s]", (unsigned long long)s, n, rc, hex);
    return rc;
}
using recv_t = int(WINAPI*)(SOCKET, char*, int, int);
static recv_t p_recv;
static int WINAPI h_recv(SOCKET s, char* b, int n, int f) {
    int rc = p_recv(s, b, n, f);
    char hex[48] = {0}; int k = 0;
    if (rc > 0) for (int i = 0; i < rc && i < 12; ++i) k += snprintf(hex + k, sizeof(hex) - k, "%02x", (uint8_t)b[i]);
    log::info("ws2: recv s=%llu -> %d  [%s]", (unsigned long long)s, rc, hex);
    return rc;
}

struct Ent { uint32_t rva; void* fn; void** orig; const char* name; };
static Ent TBL[] = {
    {0x4c0ce4c, (void*)h_socket,      (void**)&p_socket,  "socket"},
    {0x4c0cdc4, (void*)h_WSASocketW,  (void**)&p_wsasock, "WSASocketW"},
    {0x4c0cdec, (void*)h_connect,     (void**)&p_connect, "connect"},
    {0x4c0cecc, (void*)h_getaddrinfo, (void**)&p_gai,     "getaddrinfo"},
    {0x4c0cdb4, (void*)h_send,        (void**)&p_send,    "send"},
    {0x4c0cd9c, (void*)h_recv,        (void**)&p_recv,    "recv"},
};

bool ws2p::install() {
    auto* base = (uint8_t*)GetModuleHandleA(nullptr);
    int patched = 0;
    for (auto& e : TBL) {
        *e.orig = res(e.name);
        if (!*e.orig) { log::err("ws2p: resolve %s failed", e.name); continue; }
        auto* slot = (void**)(base + e.rva);
        DWORD old;
        VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old);
        *slot = e.fn;
        VirtualProtect(slot, sizeof(void*), old, &old);
        ++patched;
    }
    log::info("ws2p: %d/6 probes installed", patched);
    return patched > 0;
}

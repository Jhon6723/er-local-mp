#include "client.h"
#include <winsock2.h>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <atomic>
#include "../log.h"
#include "../transport/transport.h"

static SOCKET g_s = INVALID_SOCKET;
static sockaddr_in g_srv;
static char g_srv_ip[64] = "127.0.0.1";
static uint32_t g_peer = 0;
static std::atomic<bool> g_run{false};

// respuesta pendiente: un solo request en vuelo (protocolo secuencial)
static std::mutex g_req_mu;
static uint8_t g_want = 0;
static uint8_t g_resp[1400];
static int g_resp_len = -1;
static std::atomic<uint16_t> g_seq{0};

// header wire: "MR" + ver u8 + type u8 + seq u16 LE (6 bytes) — matchbox/proto.py
static void put_hdr(uint8_t* p, uint8_t type, uint16_t seq) {
    p[0]='M'; p[1]='R'; p[2]=1; p[3]=type; p[4]=seq&0xff; p[5]=seq>>8;
}

static void on_notify_join(const uint8_t* p, int n) {
    // {session_id u32, joiner_peer_id u32, joiner_ip u32, joiner_port u16, mode u8}
    if (n < 15) return;
    uint32_t sid, jpid, jip; uint16_t jport; uint8_t mode;
    memcpy(&sid,p,4); memcpy(&jpid,p+4,4); memcpy(&jip,p+8,4);
    memcpy(&jport,p+12,2); mode=p[14];
    log::info("NOTIFY_JOIN session=%u peer=%u ip=%08x port=%u mode=%u",sid,jpid,jip,jport,mode);
    transport::bind_peer(jpid, jip, jport);   // modo direct: peer = su endpoint
    // TODO(session): fabricar PlayerNetworkSession para el joiner
}

static void rx_loop() {
    uint8_t buf[1500];
    while (g_run) {
        int n = recv(g_s, (char*)buf, sizeof buf, 0);
        if (n < 6 || buf[0] != 'M' || buf[1] != 'R') continue;
        uint8_t type = buf[3];
        if (type == 0x0D) { on_notify_join(buf+6, n-6); continue; }
        std::lock_guard lk(g_req_mu);
        if (type == g_want || type == 0x7f) {
            int dl = n < (int)sizeof g_resp ? n : (int)sizeof g_resp;
            memcpy(g_resp, buf, dl); g_resp_len = dl;
            g_want = 0;
        }
    }
}

static void keepalive_loop() {
    while (g_run) {
        Sleep(15000);
        if (!g_run || !g_peer) continue;
        uint8_t p[4]; memcpy(p, &g_peer, 4);
        uint8_t pkt[10]; put_hdr(pkt, 0x0A, ++g_seq);
        memcpy(pkt+6, p, 4);
        sendto(g_s, (const char*)pkt, 10, 0, (sockaddr*)&g_srv, sizeof g_srv);
    }
}

int mb::request(uint8_t type, const void* payload, int plen, uint8_t want, void* out, int cap) {
    { std::lock_guard lk(g_req_mu); g_want = want; g_resp_len = -1; }
    uint8_t pkt[1500]; put_hdr(pkt, type, ++g_seq);
    memcpy(pkt+6, payload, plen);
    sendto(g_s, (const char*)pkt, plen+6, 0, (sockaddr*)&g_srv, sizeof g_srv);
    for (int i = 0; i < 40; i++) {           // 2s timeout en pasos de 50ms
        Sleep(50);
        std::lock_guard lk(g_req_mu);
        if (g_resp_len >= 0) {
            if (g_resp[3] == 0x7f) {
                log::err("matchbox err req=%u code=%u", g_resp[6], g_resp[7]);
                g_resp_len = -1; return -2;
            }
            int dl = g_resp_len-6;
            if (dl < 0) dl = 0;
            if (dl > cap) dl = cap;
            memcpy(out, g_resp+6, dl);
            g_resp_len = -1;
            return dl;
        }
    }
    { std::lock_guard lk(g_req_mu); g_want = 0; }
    return -1;
}

bool mb::init(const Config& cfg) {
    strncpy(g_srv_ip, cfg.matchbox_ip, sizeof(g_srv_ip) - 1);
    g_s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    g_srv.sin_family = AF_INET;
    g_srv.sin_port = htons(cfg.matchbox_port);
    g_srv.sin_addr.s_addr = inet_addr(cfg.matchbox_ip);
    g_run = true;
    std::thread(rx_loop).detach();
    std::thread(keepalive_loop).detach();
    log::info("mb threads up");
    // REGISTER: {name_len u8, name, ip u32, port u16, game_hash u32}
    uint8_t buf[1500]; uint8_t* p = buf;
    uint8_t nl = (uint8_t)strlen(cfg.player_name);
    *p++ = nl; memcpy(p, cfg.player_name, nl); p += nl;
    uint32_t ip = 0; memcpy(p, &ip, 4); p += 4;
    uint16_t port = transport::bound_port() ? transport::bound_port() : cfg.listen_port;
    memcpy(p, &port, 2); p += 2;
    uint32_t gh = 0x5d0b85d2; memcpy(p, &gh, 4); p += 4;
    uint8_t out[64];
    log::info("mb register send plen=%d", (int)(p-buf));
    int r = request(0x01, buf, (int)(p-buf), 0x02, out, sizeof out);
    log::info("mb register r=%d", r);
    if (r == 4) { memcpy(&g_peer, out, 4); log::info("matchbox registered peer=%u", g_peer); return true; }
    log::err("matchbox register failed r=%d", r);
    return false;
}
void mb::shutdown() { g_run = false; if (g_s != INVALID_SOCKET) closesocket(g_s); g_s = INVALID_SOCKET; }
uint32_t mb::peer_id() { return g_peer; }
const char* mb::server_ip() { return g_srv_ip; }

bool mb::sign_up(uint32_t area, uint32_t ch, uint32_t* sid) {
    uint8_t p[12]; memcpy(p,&g_peer,4); memcpy(p+4,&area,4); memcpy(p+8,&ch,4);
    uint8_t o[8];
    if (request(0x03, p, 12, 0x0b, o, 4) == 4) { memcpy(sid,o,4); return true; }
    return false;
}
bool mb::join(uint32_t sign, uint32_t* session, uint32_t* hip, uint16_t* hport, uint8_t* mode) {
    uint8_t p[9]; memcpy(p,&g_peer,4); memcpy(p+4,&sign,4); p[8]=0; // want_mode=direct
    uint8_t o[20];
    int r = request(0x07, p, 9, 0x08, o, sizeof o);
    if (r < 15) return false;
    memcpy(hip, o+4, 4); memcpy(hport, o+8, 2); memcpy(mode, o+10, 1); memcpy(session, o+11, 4);
    transport::bind_peer(*hip /*peer del host*/, *hip, *hport);
    // NOTE: la key del peer deberia ser el steamID que el juego use — TBD sesion
    return true;
}

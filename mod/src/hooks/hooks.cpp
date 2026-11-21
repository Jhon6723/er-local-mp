// FRONTERA BINARIO: todas las direcciones/offsets del exe viven aqui.
// Build: eldenring.exe sha256 f9118fea...b328 (v1.17.2, ver analysis/09..10)
// Re-derivacion de offsets: analysis/probe*_1172.py
#include "hooks.h"
#include "eos_shim.h"
#include "winhttp_shim.h"
#include "ws2_probe.h"
#include <winsock2.h>
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "../detour.h"
#include "../log.h"
#include "../transport/transport.h"

namespace {

uint8_t* g_exe_base = nullptr;
uint32_t g_net_acct = 0;
uint64_t g_net_sid  = 0;
char     g_ctl_ip[64] = "127.0.0.1";
uint16_t g_ctl_port   = 37017;
// [net]session=direct|steam — direct = transporte UDP propio + lobbies sinteticos;
// steam = delegar interfaces a steam_api64.dll (OnlineFix emu) sin wrapping.
bool     g_steam_mode = false;

// ---- Callbacks & CallResults sinteticos de Steamworks -----------------------
constexpr uint64_t SYNTH_CALL_PREFIX = 0x57EA000000000000ULL;
constexpr uint64_t SYNTH_CALL_MASK   = 0xFFFF000000000000ULL;

struct RegCb {
    void* obj;
    int   id;
};

struct SynthEvent {
    int cb_id;
    std::vector<uint8_t> data;
};

struct PendingCallResult {
    void*    cb_obj;
    uint64_t api_call;
};

struct ApiResultEntry {
    int cb_id;
    std::vector<uint8_t> data;
};

std::mutex g_cb_mtx;
std::vector<RegCb> g_reg_cbs;
std::vector<SynthEvent> g_pending_events;
std::vector<PendingCallResult> g_pending_crs;
std::unordered_map<uint64_t, ApiResultEntry> g_api_results;
std::atomic<uint32_t> g_call_seq{0};
std::atomic<uint32_t> g_auth_seq{0};

uint64_t alloc_api_call(int cb_id, const void* payload, size_t len) {
    uint64_t h = SYNTH_CALL_PREFIX | (++g_call_seq);
    std::lock_guard<std::mutex> lk(g_cb_mtx);
    const uint8_t* p = (const uint8_t*)payload;
    g_api_results[h] = {cb_id, std::vector<uint8_t>(p, p + len)};
    return h;
}

void push_event(int cb_id, const void* payload, size_t len) {
    std::lock_guard<std::mutex> lk(g_cb_mtx);
    const uint8_t* p = (const uint8_t*)payload;
    g_pending_events.push_back({cb_id, std::vector<uint8_t>(p, p + len)});
}

// ---- Cliente UDP ligero hacia fnserver.py (:37017) para Lobbies -------------
std::string ctl_request(const std::string& cmd, int timeout_ms = 350) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return "";
    DWORD tv = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(g_ctl_port);
    dst.sin_addr.s_addr = inet_addr(g_ctl_ip);
    sendto(s, cmd.data(), (int)cmd.size(), 0, (sockaddr*)&dst, sizeof(dst));
    char buf[1024];
    sockaddr_in from{};
    int fl = sizeof(from);
    int n = recvfrom(s, buf, sizeof(buf) - 1, 0, (sockaddr*)&from, &fl);
    closesocket(s);
    if (n <= 0) return "";
    buf[n] = '\0';
    return std::string(buf, n);
}

// ---- Estado local de Lobbies (SteamMatchMaking009) --------------------------
struct LobbyState {
    uint64_t owner = 0;
    std::vector<uint64_t> members;
};

#pragma pack(push, 1)
struct LobbyCreated_16 { // 0x201 (16B, ver 0x1423feaf0)
    int32_t  m_eResult;
    int32_t  _pad;
    uint64_t m_ulSteamIDLobby;
};
struct LobbyEnter_24 { // 0x1f8 (24B, ver 0x1423ff1a0)
    uint64_t m_ulSteamIDLobby;
    uint32_t m_rgfChatPermissions;
    uint8_t  m_bLocked;
    uint8_t  _pad1[3];
    uint32_t m_EChatRoomEnterResponse;
    uint32_t _pad2;
};
struct LobbyChatUpdate_32 { // 0x1fa (32B, ver 0x1423f8390)
    uint64_t m_ulSteamIDLobby;
    uint64_t m_ulSteamIDUserChanged;
    uint64_t m_ulSteamIDMakingChange;
    uint32_t m_rgfChatMemberStateChange;
    uint32_t _pad;
};
struct ValidateAuthTicket_20 { // 0x8f (20B, ver 0x1423f8380)
    uint64_t m_SteamID;
    int32_t  m_eAuthSessionResponse;
    uint64_t m_OwnerSteamID;
};
struct P2PSessionRequest_8 { // 0x4b2 (8B)
    uint64_t m_steamIDRemote;
};
#pragma pack(pop)

static_assert(sizeof(LobbyCreated_16) == 16, "LobbyCreated size");
static_assert(sizeof(LobbyEnter_24) == 24, "LobbyEnter size");
static_assert(sizeof(LobbyChatUpdate_32) == 32, "LobbyChatUpdate size");
static_assert(sizeof(ValidateAuthTicket_20) == 20, "ValidateAuthTicket size");
static_assert(sizeof(P2PSessionRequest_8) == 8, "P2PSessionRequest size");

std::mutex g_lb_mtx;
std::unordered_map<uint64_t, LobbyState> g_lobbies;
std::atomic<uint64_t> g_active_lobby{0};
std::atomic<bool> g_poll_started{false};

// Parsea "ok <owner> <sid>:<ip>:<port>,<sid2>:<ip2>:<port2>" y enlaza peers UDP
bool apply_lobby_snapshot(uint64_t lid, const std::string& resp, bool emit_diff) {
    if (resp.rfind("ok ", 0) != 0) return false;
    size_t sp = resp.find(' ', 3);
    if (sp == std::string::npos) return false;
    uint64_t owner = strtoull(resp.substr(3, sp - 3).c_str(), nullptr, 10);
    std::string list = resp.substr(sp + 1);

    std::vector<uint64_t> new_members;
    size_t pos = 0;
    while (pos <= list.size()) {
        size_t comma = list.find(',', pos);
        std::string item = (comma == std::string::npos) ? list.substr(pos) : list.substr(pos, comma - pos);
        if (!item.empty()) {
            size_t c1 = item.find(':');
            size_t c2 = (c1 != std::string::npos) ? item.find(':', c1 + 1) : std::string::npos;
            if (c1 != std::string::npos && c2 != std::string::npos) {
                uint64_t sid = strtoull(item.substr(0, c1).c_str(), nullptr, 10);
                std::string ip = item.substr(c1 + 1, c2 - c1 - 1);
                uint16_t port = (uint16_t)strtoul(item.substr(c2 + 1).c_str(), nullptr, 10);
                if (sid != 0) {
                    new_members.push_back(sid);
                    if (sid != g_net_sid && port > 0) {
                        transport::bind_peer(sid, inet_addr(ip.c_str()), port);
                    }
                }
            }
        }
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }

    std::vector<uint64_t> entered, left;
    {
        std::lock_guard<std::mutex> lk(g_lb_mtx);
        auto& st = g_lobbies[lid];
        if (emit_diff) {
            for (uint64_t m : new_members) {
                if (m != g_net_sid && std::find(st.members.begin(), st.members.end(), m) == st.members.end())
                    entered.push_back(m);
            }
            for (uint64_t m : st.members) {
                if (m != g_net_sid && std::find(new_members.begin(), new_members.end(), m) == new_members.end())
                    left.push_back(m);
            }
        }
        st.owner = owner ? owner : g_net_sid;
        st.members = new_members;
    }

    for (uint64_t m : entered) {
        log::info("lobby: member ENTERED 0x%llx in lobby 0x%llx", (unsigned long long)m, (unsigned long long)lid);
        LobbyChatUpdate_32 ev{lid, m, m, 0x01, 0};
        push_event(0x1fa, &ev, sizeof(ev));
    }
    for (uint64_t m : left) {
        log::info("lobby: member LEFT 0x%llx in lobby 0x%llx", (unsigned long long)m, (unsigned long long)lid);
        LobbyChatUpdate_32 ev{lid, m, m, 0x02, 0};
        push_event(0x1fa, &ev, sizeof(ev));
    }
    return true;
}

void lobby_poll_loop() {
    while (true) {
        Sleep(150);
        uint64_t lid = g_active_lobby.load();
        if (!lid) continue;
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "lpoll %llu %llu %u",
                 (unsigned long long)lid, (unsigned long long)g_net_sid, transport::bound_port());
        std::string r = ctl_request(cmd, 200);
        if (!r.empty()) apply_lobby_snapshot(lid, r, true);
    }
}

void ensure_poll_thread() {
    bool expected = false;
    if (g_poll_started.compare_exchange_strong(expected, true)) {
        std::thread(lobby_poll_loop).detach();
    }
}

// ---- ISteamNetworking006 (FakeNet multicanal) -------------------------------
struct FakeNet;
struct FakeNetVT { void* f[22]; };
struct FakeNet { const FakeNetVT* vt; };

bool fake_SendP2PPacket(FakeNet*, uint64_t peer, const void* d, uint32_t n, int, int channel) {
    transport::send_to(peer, channel, d, (int)n);
    return true;
}
bool fake_IsP2PPacketAvailable(FakeNet*, uint32_t* out, int channel) {
    int n = transport::recv_peek(channel);
    if (out) *out = (uint32_t)n;
    return n > 0;
}
bool fake_ReadP2PPacket(FakeNet*, void* buf, uint32_t cap, uint32_t* len, uint64_t* peer, int channel) {
    return transport::recv(channel, buf, cap, len, peer);
}
bool fake_AcceptP2PSession(FakeNet*, uint64_t peer) {
    log::info("p2p: AcceptP2PSessionWithUser(0x%llx)", (unsigned long long)peer);
    return true;
}
bool fake_CloseP2PSession(FakeNet*, uint64_t peer) {
    log::info("p2p: CloseP2PSessionWithUser(0x%llx)", (unsigned long long)peer);
    transport::close_peer(peer);
    return true;
}
bool fake_CloseP2PChannel(FakeNet*, uint64_t peer, int channel) {
    transport::close_channel(peer, channel);
    return true;
}
bool fake_GetP2PSessionState(FakeNet*, uint64_t, void* st) {
    if (st) {
        memset(st, 0, 16);
        ((uint8_t*)st)[0] = 1; // m_bConnectionActive = 1
    }
    return true;
}
bool fake_AllowRelay(FakeNet*, bool) { return true; }
uint32_t fake_sock0(FakeNet*, int, ...) { return 0; }
bool fake_bool0(FakeNet*, ...) { return false; }
uint32_t fake_maxpkt(FakeNet*, uint32_t) { return 1200; }
int fake_conn_type(FakeNet*, uint32_t) { return 1; }

FakeNetVT g_fake_vt{{
    (void*)fake_SendP2PPacket, (void*)fake_IsP2PPacketAvailable, (void*)fake_ReadP2PPacket,
    (void*)fake_AcceptP2PSession, (void*)fake_CloseP2PSession, (void*)fake_CloseP2PChannel,
    (void*)fake_GetP2PSessionState, (void*)fake_AllowRelay,
    (void*)fake_sock0, (void*)fake_sock0, (void*)fake_sock0,
    (void*)fake_bool0, (void*)fake_bool0, (void*)fake_bool0,
    (void*)fake_bool0, (void*)fake_bool0, (void*)fake_bool0,
    (void*)fake_bool0, (void*)fake_bool0, (void*)fake_bool0,
    (void*)fake_conn_type, (void*)fake_maxpkt
}};
FakeNet g_fake{&g_fake_vt};

// ---- SteamUser021 wrapper ---------------------------------------------------
void* g_su_orig_vt[40] = {};
void* g_su_vt[40] = {};
bool  g_su_wrapped = false;

uint64_t* fake_GetSteamID(void* self, uint64_t* out) {
    uintptr_t ret = (uintptr_t)__builtin_return_address(0);
    uintptr_t base = (uintptr_t)g_exe_base;
    // DLNR3D/DLNW3D (0x23f0000..0x2660000) recibe identidad de red unica;
    // SaveData (<0x23f0000) conserva el SteamID original de ER0000.sl2.
    if (base && ret >= base + 0x23f0000 && ret < base + 0x2660000) {
        *out = g_net_sid;
        log::info("steam: GetSteamID(net @ +0x%llx) -> 0x%llx",
                  (unsigned long long)(ret - base), (unsigned long long)g_net_sid);
        return out;
    }
    using Orig_t = uint64_t*(*)(void*, uint64_t*);
    return ((Orig_t)g_su_orig_vt[2])(self, out);
}

uint32_t fake_GetAuthSessionTicket(void*, void* pTicket, int cbMax, uint32_t* pcbTicket) {
    if (pcbTicket) *pcbTicket = 16;
    if (pTicket && cbMax >= 16) {
        memset(pTicket, 0, 16);
        memcpy(pTicket, "ERAUTH", 6);
        memcpy((uint8_t*)pTicket + 8, &g_net_sid, 8);
    }
    uint32_t h = ++g_auth_seq;
    log::info("steam: GetAuthSessionTicket -> h=%u", h);
    return h;
}

int fake_BeginAuthSession(void*, const void*, int, uint64_t steamID) {
    log::info("steam: BeginAuthSession(0x%llx) -> OK + fire 0x8f", (unsigned long long)steamID);
    ValidateAuthTicket_20 ev{steamID, 0, steamID};
    push_event(0x8f, &ev, sizeof(ev));
    return 0; // k_EBeginAuthSessionResultOK
}

void fake_EndAuthSession(void*, uint64_t steamID) {
    log::info("steam: EndAuthSession(0x%llx)", (unsigned long long)steamID);
}

void fake_CancelAuthTicket(void*, uint32_t h) {
    log::info("steam: CancelAuthTicket(%u)", h);
}

uint64_t fake_RequestEncryptedAppTicket(void*, void*, int cbData) {
    int dummy = 1;
    uint64_t h = alloc_api_call(154, &dummy, sizeof(dummy));
    log::info("steam: RequestEncryptedAppTicket(cb=%d) -> call=0x%llx", cbData, (unsigned long long)h);
    return h;
}

bool fake_GetEncryptedAppTicket(void*, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket) {
    uint8_t local_ticket[32] = {};
    memcpy(local_ticket, "ERLOCALMP_TICKET", 16);
    uint16_t uport = transport::bound_port();
    memcpy(local_ticket + 16, &g_net_acct, sizeof(g_net_acct));
    memcpy(local_ticket + 20, &uport, sizeof(uport));
    if (pcbTicket) *pcbTicket = sizeof(local_ticket);
    if (!pTicket || cbMaxTicket < (int)sizeof(local_ticket)) return false;
    memcpy(pTicket, local_ticket, sizeof(local_ticket));
    log::info("steam: GetEncryptedAppTicket -> acct=0x%x udp=%u", g_net_acct, uport);
    return true;
}

void wrap_vtable(void* iface, void** orig_store, void** custom_vt, size_t slots, bool& flag, const char* tag) {
    if (!iface || flag) return;
    void** vt = *(void***)iface;
    if (!vt || vt == custom_vt) return;
    memcpy(orig_store, vt, slots * sizeof(void*));
    memcpy(custom_vt, vt, slots * sizeof(void*));
    flag = true;
    log::info("steam: captured %s=%p (orig_vt=%p)", tag, iface, vt);
}

void commit_vtable(void* iface, void** custom_vt) {
    if (!iface) return;
    DWORD old = 0;
    VirtualProtect(iface, sizeof(void*), PAGE_READWRITE, &old);
    *(void***)iface = custom_vt;
    VirtualProtect(iface, sizeof(void*), old, &old);
}

void wrap_steam_user(void* su) {
    if (!su) return;
    if (!g_su_wrapped) {
        wrap_vtable(su, g_su_orig_vt, g_su_vt, 40, g_su_wrapped, "SteamUser021");
        g_su_vt[2]  = (void*)fake_GetSteamID;
        g_su_vt[13] = (void*)fake_GetAuthSessionTicket;
        g_su_vt[14] = (void*)fake_BeginAuthSession;
        g_su_vt[15] = (void*)fake_EndAuthSession;
        g_su_vt[16] = (void*)fake_CancelAuthTicket;
        g_su_vt[20] = (void*)fake_RequestEncryptedAppTicket;
        g_su_vt[21] = (void*)fake_GetEncryptedAppTicket;
    }
    commit_vtable(su, g_su_vt);
}

// ---- SteamFriends017 wrapper ------------------------------------------------
void* g_sf_orig_vt[64] = {};
void* g_sf_vt[64] = {};
bool  g_sf_wrapped = false;

const char* fake_GetFriendPersonaName(void* self, uint64_t sid) {
    using Orig_t = const char*(*)(void*, uint64_t);
    const char* r = g_sf_orig_vt[7] ? ((Orig_t)g_sf_orig_vt[7])(self, sid) : nullptr;
    if (!r || r[0] == '\0') return "Tarnished";
    return r;
}

void wrap_steam_friends(void* sf) {
    if (!sf) return;
    if (!g_sf_wrapped) {
        wrap_vtable(sf, g_sf_orig_vt, g_sf_vt, 64, g_sf_wrapped, "SteamFriends017");
        g_sf_vt[7] = (void*)fake_GetFriendPersonaName; // +0x38
    }
    commit_vtable(sf, g_sf_vt);
}

// ---- SteamUtils010 wrapper --------------------------------------------------
void* g_ut_orig_vt[40] = {};
void* g_ut_vt[40] = {};
bool  g_ut_wrapped = false;

bool fake_IsAPICallCompleted(void* self, uint64_t hCall, bool* pbFailed) {
    if ((hCall & SYNTH_CALL_MASK) == SYNTH_CALL_PREFIX) {
        if (pbFailed) *pbFailed = false;
        std::lock_guard<std::mutex> lk(g_cb_mtx);
        return g_api_results.find(hCall) != g_api_results.end();
    }
    using Orig_t = bool(*)(void*, uint64_t, bool*);
    return ((Orig_t)g_ut_orig_vt[11])(self, hCall, pbFailed);
}

int fake_GetAPICallFailureReason(void* self, uint64_t hCall) {
    if ((hCall & SYNTH_CALL_MASK) == SYNTH_CALL_PREFIX) return -1;
    using Orig_t = int(*)(void*, uint64_t);
    return ((Orig_t)g_ut_orig_vt[12])(self, hCall);
}

bool fake_GetAPICallResult(void* self, uint64_t hCall, void* pCallback, int cubCallback,
                           int iExpected, bool* pbFailed) {
    if ((hCall & SYNTH_CALL_MASK) == SYNTH_CALL_PREFIX) {
        if (pbFailed) *pbFailed = false;
        std::lock_guard<std::mutex> lk(g_cb_mtx);
        auto it = g_api_results.find(hCall);
        if (it == g_api_results.end()) return false;
        int cp = (int)it->second.data.size();
        if (cp > cubCallback) cp = cubCallback;
        if (pCallback && cp > 0) memcpy(pCallback, it->second.data.data(), cp);
        log::info("steam: GetAPICallResult(0x%llx, exp=0x%x, sz=%d) -> OK",
                  (unsigned long long)hCall, iExpected, cp);
        g_api_results.erase(it);
        return true;
    }
    using Orig_t = bool(*)(void*, uint64_t, void*, int, int, bool*);
    return ((Orig_t)g_ut_orig_vt[13])(self, hCall, pCallback, cubCallback, iExpected, pbFailed);
}

void wrap_steam_utils(void* ut) {
    if (!ut) return;
    if (!g_ut_wrapped) {
        wrap_vtable(ut, g_ut_orig_vt, g_ut_vt, 40, g_ut_wrapped, "SteamUtils010");
        g_ut_vt[11] = (void*)fake_IsAPICallCompleted;     // +0x58
        g_ut_vt[12] = (void*)fake_GetAPICallFailureReason; // +0x60
        g_ut_vt[13] = (void*)fake_GetAPICallResult;        // +0x68
    }
    commit_vtable(ut, g_ut_vt);
}

// ---- SteamMatchMaking009 wrapper --------------------------------------------
void* g_mm_orig_vt[48] = {};
void* g_mm_vt[48] = {};
bool  g_mm_wrapped = false;

uint64_t fake_CreateLobby(void*, int eType, int cMax) {
    ensure_poll_thread();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "lcreate %llu %u",
             (unsigned long long)g_net_sid, transport::bound_port());
    std::string r = ctl_request(cmd);
    uint64_t lid = 0;
    if (r.rfind("ok ", 0) == 0) {
        lid = strtoull(r.c_str() + 3, nullptr, 10);
    }
    if (!lid) {
        lid = 0x0184000000000000ULL | (g_net_acct ? g_net_acct : 1);
    }
    {
        std::lock_guard<std::mutex> lk(g_lb_mtx);
        g_lobbies[lid] = {g_net_sid, {g_net_sid}};
    }
    g_active_lobby.store(lid);
    LobbyCreated_16 res{1, 0, lid};
    uint64_t h = alloc_api_call(0x201, &res, sizeof(res));
    log::info("lobby: CreateLobby(type=%d, max=%d) -> lid=0x%llx call=0x%llx",
              eType, cMax, (unsigned long long)lid, (unsigned long long)h);
    return h;
}

uint64_t fake_JoinLobby(void*, uint64_t lid) {
    ensure_poll_thread();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ljoin %llu %llu %u",
             (unsigned long long)lid, (unsigned long long)g_net_sid, transport::bound_port());
    std::string r = ctl_request(cmd);
    if (!apply_lobby_snapshot(lid, r, false)) {
        std::lock_guard<std::mutex> lk(g_lb_mtx);
        auto& st = g_lobbies[lid];
        if (!st.owner) st.owner = g_net_sid;
        if (std::find(st.members.begin(), st.members.end(), g_net_sid) == st.members.end())
            st.members.push_back(g_net_sid);
    }
    g_active_lobby.store(lid);
    LobbyEnter_24 res{lid, 0, 0, {0, 0, 0}, 1, 0};
    uint64_t h = alloc_api_call(0x1f8, &res, sizeof(res));
    log::info("lobby: JoinLobby(0x%llx) -> call=0x%llx resp='%s'",
              (unsigned long long)lid, (unsigned long long)h, r.c_str());
    return h;
}

void fake_LeaveLobby(void*, uint64_t lid) {
    log::info("lobby: LeaveLobby(0x%llx)", (unsigned long long)lid);
    if (g_active_lobby.load() == lid) g_active_lobby.store(0);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "lleave %llu %llu",
             (unsigned long long)lid, (unsigned long long)g_net_sid);
    ctl_request(cmd, 150);
    std::lock_guard<std::mutex> lk(g_lb_mtx);
    g_lobbies.erase(lid);
}

int fake_GetNumLobbyMembers(void*, uint64_t lid) {
    std::lock_guard<std::mutex> lk(g_lb_mtx);
    auto it = g_lobbies.find(lid);
    if (it == g_lobbies.end()) return 1;
    return (int)it->second.members.size();
}

uint64_t* fake_GetLobbyMemberByIndex(void*, uint64_t* out, uint64_t lid, int idx) {
    std::lock_guard<std::mutex> lk(g_lb_mtx);
    auto it = g_lobbies.find(lid);
    if (it != g_lobbies.end() && idx >= 0 && idx < (int)it->second.members.size()) {
        *out = it->second.members[idx];
    } else {
        *out = (idx == 0) ? g_net_sid : 0;
    }
    return out;
}

uint64_t* fake_GetLobbyOwner(void*, uint64_t* out, uint64_t lid) {
    std::lock_guard<std::mutex> lk(g_lb_mtx);
    auto it = g_lobbies.find(lid);
    *out = (it != g_lobbies.end() && it->second.owner) ? it->second.owner : g_net_sid;
    return out;
}

bool fake_SetLobbyOwner(void*, uint64_t lid, uint64_t new_owner) {
    std::lock_guard<std::mutex> lk(g_lb_mtx);
    g_lobbies[lid].owner = new_owner;
    return true;
}

void wrap_steam_matchmaking(void* mm) {
    if (!mm) return;
    if (!g_mm_wrapped) {
        wrap_vtable(mm, g_mm_orig_vt, g_mm_vt, 48, g_mm_wrapped, "SteamMatchMaking009");
        g_mm_vt[13] = (void*)fake_CreateLobby;           // +0x68
        g_mm_vt[14] = (void*)fake_JoinLobby;             // +0x70
        g_mm_vt[15] = (void*)fake_LeaveLobby;            // +0x78
        g_mm_vt[17] = (void*)fake_GetNumLobbyMembers;    // +0x88
        g_mm_vt[18] = (void*)fake_GetLobbyMemberByIndex; // +0x90
        g_mm_vt[35] = (void*)fake_GetLobbyOwner;         // +0x118
        g_mm_vt[36] = (void*)fake_SetLobbyOwner;         // +0x120
    }
    commit_vtable(mm, g_mm_vt);
}

// ---- IAT hooks de steam_api64.dll -------------------------------------------
using CreateInterface_t = void*(*)(const char*);
using FindOrCreate_t    = void*(*)(int, const char*);
using RegCb_t           = void(*)(void*, int);
using UnregCb_t         = void(*)(void*);
using RegCallRes_t      = void(*)(void*, uint64_t);
using UnregCallRes_t    = void(*)(void*, uint64_t);
using RunCallbacks_t    = void(*)();
using SteamInit_t       = bool(*)();
using RestartApp_t      = bool(*)(uint32_t);
using ContextInit_t     = void*(*)(void*);
using GetHSteamUser_t   = int(*)();

CreateInterface_t g_orig_ci      = nullptr;
FindOrCreate_t    g_orig_foc     = nullptr;
RegCb_t           g_orig_regcb   = nullptr;
UnregCb_t         g_orig_unregcb = nullptr;
RegCallRes_t      g_orig_regcr   = nullptr;
UnregCallRes_t    g_orig_unregcr = nullptr;
RunCallbacks_t    g_orig_runcb   = nullptr;
SteamInit_t       g_orig_init    = nullptr;
RestartApp_t      g_orig_raan    = nullptr;
ContextInit_t     g_orig_ctx     = nullptr;
GetHSteamUser_t   g_orig_ghu     = nullptr;

void* route_interface(const char* ver, void* r) {
    if (!ver) return r;
    if (g_steam_mode) return r; // mode=steam: passthrough total a OnlineFix
    if (strstr(ver, "SteamNetworking00")) return &g_fake;
    if (strstr(ver, "SteamUser0"))        wrap_steam_user(r);
    else if (strstr(ver, "SteamFriends0")) wrap_steam_friends(r);
    else if (strstr(ver, "SteamUtils0"))   wrap_steam_utils(r);
    else if (strstr(ver, "SteamMatchMaking0")) wrap_steam_matchmaking(r);
    return r;
}

void* hook_CreateInterface(const char* ver) {
    // directo: la impl real sin cliente Steam puede crashear; usamos fakes propios
    void* r = (g_steam_mode && g_orig_ci) ? g_orig_ci(ver) : nullptr;
    log::info("steam: CreateInterface(%s) -> %p", ver ? ver : "?", r);
    return route_interface(ver, r);
}

void* hook_FindOrCreate(int hUser, const char* ver) {
    void* r = (g_steam_mode && g_orig_foc) ? g_orig_foc(hUser, ver) : nullptr;
    log::info("steam: FindOrCreate(%d,%s) -> %p", hUser, ver ? ver : "?", r);
    return route_interface(ver, r);
}

// Bootstrap: sin cliente Steam el juego llama SteamAPI_Init /
// SteamAPI_RestartAppIfNecessary y se cierra solo. En directo se finge OK;
// en steam se delega a la impl real (OnlineFix/Steam presente).
bool hook_SteamInit() {
    if (g_steam_mode && g_orig_init) return g_orig_init();
    log::info("steam: Init -> true (fake)");
    return true;
}

bool hook_RestartApp(uint32_t appid) {
    if (g_steam_mode && g_orig_raan) return g_orig_raan(appid);
    log::info("steam: RestartAppIfNecessary -> false");
    return false;
}

// El juego trata el retorno de ContextInit como ctx* -> obj -> vtable y
// llama vfuncs ([+0x30] al menos) esperando true. En directo devolvemos una
// estructura falsa con todos los slots -> true; en steam delegamos al real.
bool ctx_bootstrap_ok() { return true; }
void* g_ctx_vt[64]    = {};
void* g_ctx_obj       = nullptr;
void* g_ctx_inner[1]  = {};

void* hook_ContextInit(void* p) {
    if (g_steam_mode && g_orig_ctx) return g_orig_ctx(p); // mismo tipo
    if (!g_ctx_obj) {
        for (auto& s : g_ctx_vt) s = (void*)ctx_bootstrap_ok;
        g_ctx_obj      = g_ctx_vt;
        g_ctx_inner[0] = &g_ctx_obj;
        log::info("steam: ContextInit -> fake ctx");
    }
    return g_ctx_inner;
}

int hook_GetHSteamUser() {
    if (g_steam_mode && g_orig_ghu) return g_orig_ghu();
    return 1;
}

void hook_RegisterCallback(void* cb, int iCallback) {
    if (cb) {
        std::lock_guard<std::mutex> lk(g_cb_mtx);
        bool exists = false;
        for (const auto& e : g_reg_cbs) {
            if (e.obj == cb && e.id == iCallback) { exists = true; break; }
        }
        if (!exists) g_reg_cbs.push_back({cb, iCallback});
    }
    if (g_steam_mode && g_orig_regcb) g_orig_regcb(cb, iCallback);
}

void hook_UnregisterCallback(void* cb) {
    if (cb) {
        std::lock_guard<std::mutex> lk(g_cb_mtx);
        for (auto it = g_reg_cbs.begin(); it != g_reg_cbs.end();) {
            if (it->obj == cb) it = g_reg_cbs.erase(it);
            else ++it;
        }
    }
    if (g_steam_mode && g_orig_unregcb) g_orig_unregcb(cb);
}

void hook_RegisterCallResult(void* cb, uint64_t call) {
    if ((call & SYNTH_CALL_MASK) == SYNTH_CALL_PREFIX) {
        log::info("steam: RegisterCallResult(cb=%p, synth=0x%llx)", cb, (unsigned long long)call);
        std::lock_guard<std::mutex> lk(g_cb_mtx);
        g_pending_crs.push_back({cb, call});
        return;
    }
    if (g_steam_mode && g_orig_regcr) g_orig_regcr(cb, call);
}

void hook_UnregisterCallResult(void* cb, uint64_t call) {
    if ((call & SYNTH_CALL_MASK) == SYNTH_CALL_PREFIX) {
        std::lock_guard<std::mutex> lk(g_cb_mtx);
        for (auto it = g_pending_crs.begin(); it != g_pending_crs.end();) {
            if (it->cb_obj == cb && it->api_call == call) it = g_pending_crs.erase(it);
            else ++it;
        }
        return;
    }
    if (g_steam_mode && g_orig_unregcr) g_orig_unregcr(cb, call);
}

void hook_RunCallbacks() {
    if (g_steam_mode && g_orig_runcb) g_orig_runcb();

    uint64_t np = 0;
    while (transport::pop_new_peer(&np)) {
        P2PSessionRequest_8 req{np};
        push_event(0x4b2, &req, sizeof(req));
    }

    std::vector<SynthEvent> events;
    std::vector<RegCb> cbs_snapshot;
    std::vector<PendingCallResult> ready_crs;
    {
        std::lock_guard<std::mutex> lk(g_cb_mtx);
        if (!g_pending_events.empty()) {
            events.swap(g_pending_events);
            cbs_snapshot = g_reg_cbs;
        }
        if (!g_pending_crs.empty()) ready_crs.swap(g_pending_crs);
    }

    // CCallbackBase MSVC x64 (verificado en 0x1431f9b10):
    // vt[1] = void Run(CCallbackBase* this, void* pvParam)
    using RunCb_t = void(*)(void*, void*);
    for (auto& ev : events) {
        for (const auto& reg : cbs_snapshot) {
            if (reg.id == ev.cb_id && reg.obj) {
                void** vt = *(void***)reg.obj;
                log::info("steam: firing callback 0x%x -> cb=%p", ev.cb_id, reg.obj);
                ((RunCb_t)vt[1])(reg.obj, ev.data.data());
            }
        }
    }

    // vt[0] = void Run(CCallbackBase* this, void* pvParam, bool bIOFailure, uint64_t hSteamAPICall)
    using RunCR_t = void(*)(void*, void*, bool, uint64_t);
    for (const auto& item : ready_crs) {
        if (!item.cb_obj) continue;
        std::vector<uint8_t> pay;
        {
            std::lock_guard<std::mutex> lk(g_cb_mtx);
            auto it = g_api_results.find(item.api_call);
            if (it != g_api_results.end()) {
                pay = it->second.data;
                g_api_results.erase(it);
            }
        }
        if (pay.empty()) {
            int32_t ok = 1;
            pay.resize(4);
            memcpy(pay.data(), &ok, 4);
        }
        void** vt = *(void***)item.cb_obj;
        log::info("steam: firing CallResult 0x%llx -> cb=%p", (unsigned long long)item.api_call, item.cb_obj);
        ((RunCR_t)vt[0])(item.cb_obj, pay.data(), false, item.api_call);
    }
}

struct SEnt { uint32_t rva; void* fn; void** orig; const char* exp; };
// IAT steam_api64.dll @ base 0x4C1509C (llvm-readobj --coff-imports, build f9118fea)
SEnt STEAM_IAT[] = {
    {0x4c1509c, (void*)hook_FindOrCreate,         (void**)&g_orig_foc,     "SteamInternal_FindOrCreateUserInterface"},
    {0x4c150a4, (void*)hook_ContextInit,          (void**)&g_orig_ctx,     "SteamInternal_ContextInit"},
    {0x4c150ac, (void*)hook_GetHSteamUser,        (void**)&g_orig_ghu,     "SteamAPI_GetHSteamUser"},
    {0x4c150b4, (void*)hook_RegisterCallback,     (void**)&g_orig_regcb,   "SteamAPI_RegisterCallback"},
    {0x4c150bc, (void*)hook_SteamInit,            (void**)&g_orig_init,    "SteamAPI_Init"},
    {0x4c150cc, (void*)hook_RestartApp,           (void**)&g_orig_raan,    "SteamAPI_RestartAppIfNecessary"},
    {0x4c150ec, (void*)hook_CreateInterface,      (void**)&g_orig_ci,      "SteamInternal_CreateInterface"},
    {0x4c150fc, (void*)hook_UnregisterCallback,   (void**)&g_orig_unregcb, "SteamAPI_UnregisterCallback"},
    {0x4c150dc, (void*)hook_RegisterCallResult,   (void**)&g_orig_regcr,   "SteamAPI_RegisterCallResult"},
    {0x4c150e4, (void*)hook_UnregisterCallResult, (void**)&g_orig_unregcr, "SteamAPI_UnregisterCallResult"},
    {0x4c150f4, (void*)hook_RunCallbacks,         (void**)&g_orig_runcb,   "SteamAPI_RunCallbacks"},
};

} // namespace

bool hooks::install() {
    g_exe_base = (uint8_t*)GetModuleHandleA(nullptr);
    uint16_t uport = transport::bound_port() ? transport::bound_port() : 27016;

    char dir[MAX_PATH];
    GetModuleFileNameA(nullptr, dir, MAX_PATH);
    char* s = strrchr(dir, '\\');
    if (s) s[1] = '\0';
    char inip[MAX_PATH];
    snprintf(inip, MAX_PATH, "%ser_local_mp.ini", dir);
    GetPrivateProfileStringA("net", "matchbox_ip", "127.0.0.1", g_ctl_ip, sizeof(g_ctl_ip), inip);
    GetPrivateProfileStringA("fn", "host", g_ctl_ip, g_ctl_ip, sizeof(g_ctl_ip), inip);
    char sess[32];
    GetPrivateProfileStringA("net", "session", "direct", sess, sizeof(sess), inip);
    g_steam_mode = (strcmp(sess, "steam") == 0);

    g_net_acct = ((uint32_t)(GetCurrentProcessId() & 0xFFFFU) << 16) | (uint32_t)uport;
    g_net_sid  = 0x0110000100000000ULL | (uint64_t)g_net_acct;
    transport::set_local_steam_id(g_net_sid);

    log::info("hooks: session=%s net_sid=0x%llx (acct=0x%x udp=%u ctl=%s:%u)",
              sess, (unsigned long long)g_net_sid, g_net_acct, uport, g_ctl_ip, g_ctl_port);

    whs::install();
    ws2p::install();
    eos::install();

    HMODULE api = GetModuleHandleA("steam_api64.dll");
    if (!api) { log::err("steam_api64 not loaded"); return false; }

    int patched = 0;
    for (auto& e : STEAM_IAT) {
        *e.orig = (void*)GetProcAddress(api, e.exp);
        if (!*e.orig) { log::err("resolve %s failed", e.exp); continue; }
        auto* slot = (void**)(g_exe_base + e.rva);
        DWORD old;
        VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old);
        *slot = e.fn;
        VirtualProtect(slot, sizeof(void*), old, &old);
        ++patched;
    }

    int hu = 1;
    if (g_steam_mode) {
        // solo en steam se consulta al cliente real; sin el la impl puede crashear
        auto get_huser = (GetHSteamUser_t)GetProcAddress(api, "SteamAPI_GetHSteamUser");
        if (get_huser) hu = get_huser();
    }
    if (g_steam_mode) {
        // mode=steam: no wrapping — identidad real de la emu OnlineFix.
        // Leer el SteamID64 real via vtable[2] (ISteamUser::GetSteamID) para
        // transporte/EOS/logs; el juego ve el mismo ID en red y save.
        if (g_orig_foc) {
            void* su = g_orig_foc(hu, "SteamUser021");
            if (su) {
                using GetSteamID_t = uint64_t*(*)(void*, uint64_t*);
                uint64_t real_id = 0;
                void** vt = *(void***)su;
                ((GetSteamID_t)vt[2])(su, &real_id);
                if (real_id) {
                    g_net_sid = real_id;
                    transport::set_local_steam_id(g_net_sid);
                    log::info("steam: emu SteamID64 -> net_sid=0x%llx", (unsigned long long)g_net_sid);
                }
            }
        }
    } else if (g_orig_foc) {
        wrap_steam_user(g_orig_foc(hu, "SteamUser021"));
        wrap_steam_friends(g_orig_foc(hu, "SteamFriends017"));
        wrap_steam_utils(g_orig_foc(hu, "SteamUtils010"));
        wrap_steam_matchmaking(g_orig_foc(hu, "SteamMatchMaking009"));
    }

    // NOTA build f9118fea: las interfaces se cachean en campos de objetos
    // via fns resolver (0x23faff0/0x2644b40/0xe74de0/0xe74e10: FindOrCreate +
    // store en [rcx]). Los objetos singleton quedan envueltos por las
    // llamadas proactivas de arriba — los resolvers posteriores heredan la
    // vtable ya envuelta. Los antiguos slots globales (0x3b48a10 etc.) no
    // existen en esta build y no deben tocarse.

    log::info("steam iat: %d/11 slots patched (su=%d sf=%d ut=%d mm=%d)",
              patched, g_su_wrapped ? 1 : 0, g_sf_wrapped ? 1 : 0,
              g_ut_wrapped ? 1 : 0, g_mm_wrapped ? 1 : 0);
    return patched == 11;
}

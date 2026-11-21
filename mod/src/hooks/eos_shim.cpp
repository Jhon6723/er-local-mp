// Shim local offline de EOS (32 slots delay-load en 0x143d5ac58..0x143d5ad50).
// Resuelve EOS_Connect_Login en local sin trafico externo hacia Epic/EAC.
// FRONTERA BINARIO: eldenring.exe sha256 5d0b85d2...
#include "eos_shim.h"
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>
#include <windows.h>
#include "../log.h"
#include "../matchbox/client.h"

namespace {

using EOS_Connect_OnLoginCallback = void(__stdcall*)(const void* data);
using EOS_AC_OnPeerAuthCallback   = void(__stdcall*)(const void* data);

struct EOS_Connect_LoginCallbackInfo {
    int32_t ResultCode;       // +0x00: 0 = EOS_Success
    int32_t _pad;             // +0x04
    void* ClientData;         // +0x08: eosMgr
    void* LocalUserId;        // +0x10: EOS_ProductUserId
    void* ContinuanceToken;   // +0x18
};

struct EOS_AC_PeerAuthCallbackInfo {
    void*   ClientData;       // +0x00: eosMgr (ver 0x140de1e93)
    void*   PeerHandle;       // +0x08: clave en [eosMgr+0x88] (ver 0x140de1e96)
    int32_t AuthStatus;       // +0x10: 2 = RemoteAuthComplete -> [peer+0x54]=-1.0f (0x140de2051)
    int32_t _pad;
};

struct PendingLogin {
    void* client_data;
    EOS_Connect_OnLoginCallback cb;
};

std::mutex g_mtx;
std::vector<PendingLogin> g_pending;
std::vector<void*> g_pending_peers;
void* g_peer_auth_cd = nullptr;
EOS_AC_OnPeerAuthCallback g_peer_auth_cb = nullptr;
std::atomic<uint64_t> g_next_notify{100};

void* local_puid() {
    uint32_t pid = mb::peer_id();
    if (!pid) pid = 1;
    return (void*)(uintptr_t)(0xE0510000ULL | (pid & 0xFFFFU));
}

// [0] EOS_ByteArray_ToString
int32_t __stdcall f_ByteArray_ToString(const uint8_t* bytes, uint32_t len, char* out, int32_t* inout_len) {
    if (!inout_len) return 3; // EOS_InvalidParameters
    int32_t need = (int32_t)(len * 2 + 1);
    if (!out || *inout_len < need) {
        *inout_len = need;
        return 20; // EOS_LimitExceeded
    }
    for (uint32_t i = 0; i < len; ++i) {
        snprintf(out + i * 2, 3, "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
    *inout_len = need;
    log::info("eos: ByteArray_ToString len=%u -> %d chars", len, need - 1);
    return 0;
}

// [1] EOS_ProductUserId_IsValid
int32_t __stdcall f_ProductUserId_IsValid(void* id) {
    return id != nullptr ? 1 : 0;
}

// [2] EOS_ProductUserId_ToString
int32_t __stdcall f_ProductUserId_ToString(void* id, char* out, int32_t* inout_len) {
    if (!id || !inout_len) return 3;
    if (!out || *inout_len < 33) {
        *inout_len = 33;
        return 20;
    }
    uint32_t low = (uint32_t)((uintptr_t)id & 0xFFFFU);
    if (!low) low = mb::peer_id() ? mb::peer_id() : 1;
    snprintf(out, 33, "000200000000000000000000%08x", low);
    *inout_len = 33;
    log::info("eos: ProductUserId_ToString(%p) -> %s", id, out);
    return 0;
}

// [3] EOS_ProductUserId_FromString
void* __stdcall f_ProductUserId_FromString(const char* s) {
    if (!s || !s[0]) return nullptr;
    size_t n = strlen(s);
    uint32_t low = 1;
    if (n >= 8) {
        unsigned v = 0;
        if (sscanf(s + n - 8, "%x", &v) == 1 && v != 0) low = v;
    }
    return (void*)(uintptr_t)(0xE0510000ULL | (low & 0xFFFFU));
}

// [4] EOS_Initialize
int32_t __stdcall f_Initialize(const void*) {
    log::info("eos: Initialize -> 0");
    return 0;
}

// [5] EOS_Shutdown
int32_t __stdcall f_Shutdown() {
    log::info("eos: Shutdown -> 0");
    return 0;
}

// [6] EOS_Platform_Create
void* __stdcall f_Platform_Create(const void*) {
    log::info("eos: Platform_Create -> fake");
    return (void*)0xE0500001ULL;
}

// [7] EOS_Platform_Release
void __stdcall f_Platform_Release(void*) {}

// [8] EOS_Connect_Login
void __stdcall f_Connect_Login(void* h, const void*, void* client_data, EOS_Connect_OnLoginCallback cb) {
    log::info("eos: Connect_Login h=%p clientData=%p cb=%p", h, client_data, cb);
    if (client_data) {
        // Garantizar que eosMgr->hAntiCheatClient (+0x10) no sea nulo (compuerta 0x140de2670)
        auto** ac_slot = (void**)((uint8_t*)client_data + 0x10);
        if (*ac_slot == nullptr) {
            *ac_slot = (void*)0xE050AC01ULL;
            log::info("eos: populated eosMgr+0x10 dummy handle");
        }
    }
    if (cb) {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_pending.push_back({client_data, cb});
    }
}

// [9] EOS_Connect_CreateUser
void __stdcall f_Connect_CreateUser(void* h, const void*, void* client_data, EOS_Connect_OnLoginCallback cb) {
    log::info("eos: Connect_CreateUser h=%p clientData=%p cb=%p", h, client_data, cb);
    if (cb) {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_pending.push_back({client_data, cb});
    }
}

// [10] EOS_Connect_GetLoginStatus (2 = EOS_LS_LoggedIn)
int32_t __stdcall f_Connect_GetLoginStatus(void*, void*) {
    return 2;
}

// [11..14] Connect Notify
uint64_t __stdcall f_AddNotify(void*, const void*, void*, void*) {
    return ++g_next_notify;
}
void __stdcall f_RemoveNotify(void*, uint64_t) {}

// [24] EOS_AntiCheatClient_AddNotifyPeerAuthStatusChanged (0x3d5ad18)
uint64_t __stdcall f_AddNotifyPeerAuth(void*, const void*, void* client_data, void* cb) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_peer_auth_cd = client_data;
    g_peer_auth_cb = (EOS_AC_OnPeerAuthCallback)cb;
    uint64_t id = ++g_next_notify;
    log::info("eos: AddNotifyPeerAuthStatusChanged cd=%p cb=%p -> %llu",
              client_data, cb, (unsigned long long)id);
    return id;
}

// [15] EOS_Platform_Tick
void __stdcall f_Platform_Tick(void*) {
    std::vector<PendingLogin> todo;
    std::vector<void*> peers;
    void* auth_cd = nullptr;
    EOS_AC_OnPeerAuthCallback auth_cb = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (!g_pending.empty()) todo.swap(g_pending);
        if (!g_pending_peers.empty() && g_peer_auth_cb) {
            peers.swap(g_pending_peers);
            auth_cd = g_peer_auth_cd;
            auth_cb = g_peer_auth_cb;
        }
    }
    for (const auto& p : todo) {
        EOS_Connect_LoginCallbackInfo info{};
        info.ResultCode = 0; // EOS_Success
        info.ClientData = p.client_data;
        info.LocalUserId = local_puid();
        info.ContinuanceToken = nullptr;
        log::info("eos: firing LoginCallback -> Result=0 puid=%p", info.LocalUserId);
        p.cb(&info);
    }
    for (void* ph : peers) {
        EOS_AC_PeerAuthCallbackInfo ainfo{};
        ainfo.ClientData = auth_cd;
        ainfo.PeerHandle = ph;
        ainfo.AuthStatus = 2; // EOS_ACCC_RemoteAuthComplete -> desactiva watchdog 120s
        log::info("eos: firing PeerAuthStatusChanged(peer=%p, status=2)", ph);
        auth_cb(&ainfo);
    }
}

// [16..18] Platform Get*Interface
void* __stdcall f_GetConnectInterface(void*) {
    log::info("eos: GetConnectInterface -> fake");
    return (void*)0xE050C001ULL;
}
void* __stdcall f_GetAntiCheatClientInterface(void*) {
    log::info("eos: GetAntiCheatClientInterface -> fake");
    return (void*)0xE050AC01ULL;
}
void* __stdcall f_GetReportsInterface(void*) {
    return (void*)0xE050B001ULL;
}

// [19..20] Logging
int32_t __stdcall f_Logging_SetCallback(void*) { return 0; }
int32_t __stdcall f_Logging_SetLogLevel(int32_t, int32_t) { return 0; }

// [26..31] AntiCheatClient local no-ops
int32_t __stdcall f_AC_BeginSession(void*, const void*) {
    log::info("eos: AC_BeginSession -> 0");
    return 0;
}
int32_t __stdcall f_AC_EndSession(void*, const void*) {
    log::info("eos: AC_EndSession -> 0");
    return 0;
}
int32_t __stdcall f_AC_PollStatus(void*, const void*, int32_t* out_type, char* out_msg) {
    // 18 (0x12) = EOS_NotFound (cola vacia, sin infracciones; ver 0x140ddfd48)
    if (out_type) *out_type = 0;
    if (out_msg) out_msg[0] = '\0';
    return 18;
}
int32_t __stdcall f_AC_RegisterPeer(void*, const void* opts) {
    void* peer_handle = opts ? *(void* const*)((const uint8_t*)opts + 8) : nullptr;
    log::info("eos: AC_RegisterPeer(peer=%p) -> 0", peer_handle);
    if (peer_handle) {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_pending_peers.push_back(peer_handle);
    }
    return 0;
}
int32_t __stdcall f_AC_UnregisterPeer(void*, const void*) { return 0; }
int32_t __stdcall f_AC_ReceiveMessageFromPeer(void*, const void*) { return 0; }

static void* const EOS_SLOTS[32] = {
    (void*)f_ByteArray_ToString,           // [0]  0x3d5ac58
    (void*)f_ProductUserId_IsValid,        // [1]  0x3d5ac60
    (void*)f_ProductUserId_ToString,       // [2]  0x3d5ac68
    (void*)f_ProductUserId_FromString,     // [3]  0x3d5ac70
    (void*)f_Initialize,                   // [4]  0x3d5ac78
    (void*)f_Shutdown,                     // [5]  0x3d5ac80
    (void*)f_Platform_Create,              // [6]  0x3d5ac88
    (void*)f_Platform_Release,             // [7]  0x3d5ac90
    (void*)f_Connect_Login,                // [8]  0x3d5ac98
    (void*)f_Connect_CreateUser,           // [9]  0x3d5aca0
    (void*)f_Connect_GetLoginStatus,       // [10] 0x3d5aca8
    (void*)f_AddNotify,                    // [11] 0x3d5acb0
    (void*)f_RemoveNotify,                 // [12] 0x3d5acb8
    (void*)f_AddNotify,                    // [13] 0x3d5acc0
    (void*)f_RemoveNotify,                 // [14] 0x3d5acc8
    (void*)f_Platform_Tick,                // [15] 0x3d5acd0
    (void*)f_GetConnectInterface,          // [16] 0x3d5acd8
    (void*)f_GetAntiCheatClientInterface,  // [17] 0x3d5ace0
    (void*)f_GetReportsInterface,          // [18] 0x3d5ace8
    (void*)f_Logging_SetCallback,          // [19] 0x3d5acf0
    (void*)f_Logging_SetLogLevel,          // [20] 0x3d5acf8
    (void*)f_AddNotify,                    // [21] 0x3d5ad00
    (void*)f_AddNotify,                    // [22] 0x3d5ad08
    (void*)f_RemoveNotify,                 // [23] 0x3d5ad10
    (void*)f_AddNotifyPeerAuth,            // [24] 0x3d5ad18
    (void*)f_RemoveNotify,                 // [25] 0x3d5ad20
    (void*)f_AC_BeginSession,              // [26] 0x3d5ad28
    (void*)f_AC_EndSession,                // [27] 0x3d5ad30
    (void*)f_AC_PollStatus,                // [28] 0x3d5ad38
    (void*)f_AC_RegisterPeer,              // [29] 0x3d5ad40
    (void*)f_AC_UnregisterPeer,            // [30] 0x3d5ad48
    (void*)f_AC_ReceiveMessageFromPeer,    // [31] 0x3d5ad50
};

} // namespace

static void rehabilitate_eos_mgr(uint8_t* mgr) {
    void* orig_plat = *(void**)(mgr + 0x00);
    void* orig_ac   = *(void**)(mgr + 0x10);
    void* orig_conn = *(void**)(mgr + 0x18);
    uint8_t b78     = *(uint8_t*)(mgr + 0x78);
    int32_t i7c     = *(int32_t*)(mgr + 0x7c);
    int32_t i9c     = *(int32_t*)(mgr + 0x9c);
    uint8_t ba0     = *(uint8_t*)(mgr + 0xa0);
    log::info("eos: g_eosMgr=%p before: plat=%p ac=%p conn=%p f78=%u f7c=%d err9c=%d fa0=%u",
              mgr, orig_plat, orig_ac, orig_conn, b78, i7c, i9c, ba0);
    *(void**)(mgr + 0x00)   = (void*)0xE0500001ULL;
    *(void**)(mgr + 0x10)   = (void*)0xE050AC01ULL;
    *(void**)(mgr + 0x18)   = (void*)0xE050C001ULL;
    *(uint8_t*)(mgr + 0x70) = 0;
    *(int32_t*)(mgr + 0x74) = 0;
    *(uint8_t*)(mgr + 0x78) = 0;
    *(int32_t*)(mgr + 0x7c) = 0;
    *(int32_t*)(mgr + 0x9c) = 0;
    *(uint8_t*)(mgr + 0xa0) = 0;
    {
        auto* base = (uint8_t*)GetModuleHandleA(nullptr);
        std::lock_guard<std::mutex> lk(g_mtx);
        if (!g_peer_auth_cb) {
            g_peer_auth_cd = mgr;
            g_peer_auth_cb = (EOS_AC_OnPeerAuthCallback)(base + 0xde1e60);
            if (*(uint64_t*)(mgr + 0x68) == 0) *(uint64_t*)(mgr + 0x68) = ++g_next_notify;
        }
    }
    log::info("eos: g_eosMgr rehabilitated for local offline session");
}

static DWORD WINAPI eos_mgr_watcher(LPVOID arg) {
    auto* slot = (uint8_t**)arg;
    for (int i = 0; i < 300; ++i) {
        uint8_t* mgr = *slot;
        if (mgr) {
            rehabilitate_eos_mgr(mgr);
            return 0;
        }
        Sleep(100);
    }
    log::err("eos: g_eosMgr remained null after 30s");
    return 0;
}

bool eos::install() {
    auto* base = (uint8_t*)GetModuleHandleA(nullptr);
    auto** iat = (void**)(base + 0x3d5ac58);
    DWORD old = 0;
    if (!VirtualProtect(iat, sizeof(void*) * 32, PAGE_READWRITE, &old)) {
        log::err("eos: VirtualProtect failed err=%lu", GetLastError());
        return false;
    }
    for (int i = 0; i < 32; ++i) {
        iat[i] = EOS_SLOTS[i];
    }
    VirtualProtect(iat, sizeof(void*) * 32, old, &old);
    log::info("eos: 32/32 delay-IAT slots patched");

    // g_eosMgr @ 0x143d855c8 (rva 0x3d855c8): creado antes del delay de 5s del loader
    auto* mgr_slot = (uint8_t**)(base + 0x3d855c8);
    if (*mgr_slot) {
        rehabilitate_eos_mgr(*mgr_slot);
    } else {
        HANDLE th = CreateThread(nullptr, 0, eos_mgr_watcher, mgr_slot, 0, nullptr);
        if (th) CloseHandle(th);
    }
    return true;
}

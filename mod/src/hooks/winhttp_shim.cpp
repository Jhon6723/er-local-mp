// Shim WinHTTP modo passthrough (arquitectura waygate):
// - WinHttpConnect a *.fromsoftware-game.net -> redirige a 127.0.0.1:[fn]port
// - WinHttpOpenRequest del upgrade WS -> quita WINHTTP_FLAG_SECURE (ws:// plano)
// - Todo lo demas pasa a winhttp.dll real: el upgrade WS lo hace el stack real
//   contra nuestro servidor Python local (fnserver.py).
// - Hook en la derivacion de claves kx de sodium (0x141e69570, pattern waygate):
//   reemplaza el par preshared del juego por nuestro par conocido, asi ambos
//   extremos comparten claves sin extraer las originales del binario.
#include "winhttp_shim.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <wchar.h>
#include <windows.h>
#include <winhttp.h>
#include "../detour.h"
#include "../log.h"

namespace {

HMODULE g_wh = nullptr;
HINTERNET(WINAPI* r_Open)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
HINTERNET(WINAPI* r_Connect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
HINTERNET(WINAPI* r_OpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
WINHTTP_STATUS_CALLBACK(WINAPI* r_SetStatusCallback)(HINTERNET, WINHTTP_STATUS_CALLBACK, DWORD, DWORD_PTR);
BOOL(WINAPI* r_SetOption)(HINTERNET, DWORD, LPVOID, DWORD);
BOOL(WINAPI* r_QueryOption)(HINTERNET, DWORD, LPVOID, LPDWORD);
BOOL(WINAPI* r_CrackUrl)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);
BOOL(WINAPI* r_SendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
BOOL(WINAPI* r_ReceiveResponse)(HINTERNET, LPVOID);
HINTERNET(WINAPI* r_CompleteUpgrade)(HINTERNET, DWORD_PTR);
DWORD(WINAPI* r_WsSend)(HINTERNET, WINHTTP_WEB_SOCKET_BUFFER_TYPE, PVOID, DWORD);
DWORD(WINAPI* r_WsReceive)(HINTERNET, PVOID, DWORD, DWORD*, WINHTTP_WEB_SOCKET_BUFFER_TYPE*);
DWORD(WINAPI* r_WsClose)(HINTERNET, USHORT, PVOID, DWORD);
BOOL(WINAPI* r_CloseHandle)(HINTERNET);
HANDLE(WINAPI* r_CreateMutexW)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);

uint16_t g_fn_port = 10901;
wchar_t  g_fn_host[64] = L"127.0.0.1";

// Bypass mutex de instancia unica ("Global\SekiroMutex"): se renombra por PID
// para que dos instancias locales coexistan.
HANDLE WINAPI f_CreateMutexW(LPSECURITY_ATTRIBUTES attr, BOOL owner, LPCWSTR name) {
    if (name && wcsstr(name, L"SekiroMutex")) {
        wchar_t buf[128];
        _snwprintf(buf, 128, L"%s_%lu", name, GetCurrentProcessId());
        buf[127] = 0;
        log::info("whs: mutex rename %ls -> %ls", name, buf);
        name = buf;
    }
    return r_CreateMutexW(attr, owner, name);
}

bool is_fn_host(LPCWSTR s) {
    return s && wcsstr(s, L"fromsoftware-game.net") != nullptr;
}

HINTERNET WINAPI f_Open(LPCWSTR a, DWORD b, LPCWSTR c, LPCWSTR d, DWORD e) {
    auto* h = r_Open(a, b, c, d, e);
    log::info("whs: Open acc=%lu flags=0x%lx -> %p", b, e, h);
    return h;
}

HINTERNET WINAPI f_Connect(HINTERNET s, LPCWSTR server, INTERNET_PORT port, DWORD r) {
    if (is_fn_host(server)) {
        log::info("whs: Connect %ls:%u -> REDIRECT %ls:%u", server, port, g_fn_host, g_fn_port);
        return r_Connect(s, g_fn_host, g_fn_port, r);
    }
    log::info("whs: Connect %ls:%u (passthrough)", server ? server : L"?", port);
    return r_Connect(s, server, port, r);
}

HINTERNET WINAPI f_OpenRequest(HINTERNET c, LPCWSTR verb, LPCWSTR obj, LPCWSTR ver,
                               LPCWSTR ref, LPCWSTR* acc, DWORD flags) {
    // Upgrade WS del juego: GET con objeto vacio + SECURE. Quitamos SECURE para
    // que el stack hable ws:// plano con nuestro servidor local.
    if (verb && wcscmp(verb, L"GET") == 0 && obj && obj[0] == 0 &&
        !ver && !ref && !acc && (flags & WINHTTP_FLAG_SECURE)) {
        log::info("whs: OpenRequest GET \"\" SECURE -> strip SECURE (ws://)");
        flags &= ~((DWORD)WINHTTP_FLAG_SECURE);
    } else {
        log::info("whs: OpenRequest %ls %ls flags=0x%lx", verb ? verb : L"?",
                  obj ? obj : L"?", flags);
    }
    return r_OpenRequest(c, verb, obj, ver, ref, acc, flags);
}

WINHTTP_STATUS_CALLBACK WINAPI f_SetStatusCallback(HINTERNET h, WINHTTP_STATUS_CALLBACK cb,
                                                   DWORD fl, DWORD_PTR x) {
    log::info("whs: SetStatusCallback h=%p cb=%p flags=0x%lx", h, cb, fl);
    return r_SetStatusCallback(h, cb, fl, x);
}

BOOL WINAPI f_SetOption(HINTERNET h, DWORD o, LPVOID b, DWORD l) {
    log::info("whs: SetOption h=%p opt=%lu len=%lu", h, o, l);
    return r_SetOption(h, o, b, l);
}

BOOL WINAPI f_QueryOption(HINTERNET h, DWORD o, LPVOID b, LPDWORD l) {
    return r_QueryOption(h, o, b, l);
}

BOOL WINAPI f_CrackUrl(LPCWSTR u, DWORD l, DWORD f, LPURL_COMPONENTS uc) {
    return r_CrackUrl(u, l, f, uc);
}

BOOL WINAPI f_SendRequest(HINTERNET h, LPCWSTR hdrs, DWORD hl, LPVOID o, DWORD ol,
                          DWORD t, DWORD_PTR c) {
    log::info("whs: SendRequest h=%p hlen=%lu total=%lu", h, hl, t);
    return r_SendRequest(h, hdrs, hl, o, ol, t, c);
}

BOOL WINAPI f_ReceiveResponse(HINTERNET h, LPVOID r) {
    auto ok = r_ReceiveResponse(h, r);
    log::info("whs: ReceiveResponse h=%p -> %d", h, ok);
    return ok;
}

HINTERNET WINAPI f_CompleteUpgrade(HINTERNET h, DWORD_PTR c) {
    auto* ws = r_CompleteUpgrade(h, c);
    log::info("whs: CompleteUpgrade req=%p -> ws=%p", h, ws);
    return ws;
}

void dump_out(const uint8_t* p, DWORD n) {
    char hex[512];
    char asc[160];
    for (DWORD off = 0; off < n && off < 128; off += 32) {
        int hk = 0, ak = 0;
        DWORD chunk = n - off; if (chunk > 32) chunk = 32;
        for (DWORD i = 0; i < chunk; ++i) {
            hk += snprintf(hex + hk, sizeof(hex) - hk, "%02x ", p[off + i]);
            asc[ak++] = (p[off + i] >= 32 && p[off + i] < 127) ? (char)p[off + i] : '.';
        }
        asc[ak] = 0;
        log::info("whs:   +%04x: %-96s |%s|", off, hex, asc);
    }
}

DWORD WINAPI f_WsSend(HINTERNET h, WINHTTP_WEB_SOCKET_BUFFER_TYPE t, PVOID b, DWORD l) {
    log::info("whs: WsSend h=%p type=%d len=%lu", h, (int)t, l);
    if (b && l) dump_out((const uint8_t*)b, l);
    return r_WsSend(h, t, b, l);
}

DWORD WINAPI f_WsReceive(HINTERNET h, PVOID b, DWORD l, DWORD* rd,
                         WINHTTP_WEB_SOCKET_BUFFER_TYPE* t) {
    auto err = r_WsReceive(h, b, l, rd, t);
    if (err == ERROR_SUCCESS && rd && *rd) {
        log::info("whs: WsRecv h=%p got=%lu type=%d", h, *rd, t ? (int)*t : -1);
        dump_out((const uint8_t*)b, *rd);
    }
    return err;
}

DWORD WINAPI f_WsClose(HINTERNET h, USHORT st, PVOID b, DWORD l) {
    log::info("whs: WsClose h=%p status=%u", h, st);
    return r_WsClose(h, st, b, l);
}

BOOL WINAPI f_CloseHandle(HINTERNET h) {
    return r_CloseHandle(h);
}

// --- Hook kx: intercambio de claves preshared --------------------------------
// Firma waygate: fn(usize out, u8* pk_out, u8* sk_out). Escribimos nuestro
// server_public en pk_out y client_secret en sk_out antes de llamar al original.

static const uint8_t KX_SERVER_PK[32] = {
    0x26,0x1c,0xd9,0xcd,0x2e,0x93,0x5f,0x9c,0x24,0x55,0x87,0x6a,0x80,0xf0,0x2a,0x4d,
    0x67,0x86,0xb8,0xab,0x87,0x7f,0x07,0x22,0x77,0x37,0xca,0x0b,0x57,0x7b,0xf1,0x61};
static const uint8_t KX_CLIENT_SK[32] = {
    0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,
    0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43,0x43};

using kx_fn_t = size_t (*)(uintptr_t, uint8_t*, uint8_t*);
kx_fn_t g_kx_orig = nullptr;

size_t hk_kx_derive(uintptr_t out, uint8_t* pk, uint8_t* sk) {
    log::info("whs: kx called pk=%p sk=%p out=%p", pk, sk, (void*)out);
    if (pk) memcpy(pk, KX_SERVER_PK, 32);
    if (sk) memcpy(sk, KX_CLIENT_SK, 32);
    return g_kx_orig(out, pk, sk);
}

// Detour x64 con salto absoluto (mov rax,imm64; jmp rax) + fixup RIP-relative.
// detour_install usa E9 rel32 que no alcanza nuestro DLL (>2GB del game code).
// Stolen bytes de 0x141e69570 (21 bytes, 5 instrucciones completas):
//   +0  40 53             push rbx            (2)
//   +2  48 83 EC 50       sub rsp,0x50        (4)
//   +6  48 8B 05 <d32>    mov rax,[rip+d]     (7) <- rip-relative, disp en +9
//   +13 48 33 C4          xor rax,rsp         (3)
//   +16 48 89 44 24 40    mov [rsp+0x40],rax  (5)

uint8_t* alloc_exec_near(uintptr_t target) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t base = target & ~0xFFFFull;
    for (int i = 0; i < 0x8000; ++i) {
        for (int dir = -1; dir <= 1; dir += 2) {
            uintptr_t addr = base + (uintptr_t)(dir * i) * si.dwAllocationGranularity;
            void* p = VirtualAlloc((void*)addr, 0x1000,
                                   MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return (uint8_t*)p;
        }
    }
    return nullptr;
}

bool install_kx_hook(uint8_t* base) {
    uint8_t* target = base + 0x1e69570;
    const int STOLEN = 21;
    uint8_t* tramp = alloc_exec_near((uintptr_t)target);
    if (!tramp) { log::err("whs: kx no near mem"); return false; }

    memcpy(tramp, target, STOLEN);
    // Fixup del mov rax,[rip+disp] en +9: su fin original = target+13
    int32_t disp0 = *(int32_t*)(target + 9);
    uintptr_t orig_read = (uintptr_t)target + 13 + disp0;
    int32_t disp1 = (int32_t)(orig_read - ((uintptr_t)tramp + 13));
    memcpy(tramp + 9, &disp1, 4);
    // Salto de regreso: mov rax,imm64; jmp rax  -> target+STOLEN
    tramp[STOLEN] = 0x48; tramp[STOLEN + 1] = 0xB8;
    *(uint64_t*)(tramp + STOLEN + 2) = (uintptr_t)(target + STOLEN);
    tramp[STOLEN + 10] = 0xFF; tramp[STOLEN + 11] = 0xE0;

    // Parche en target: mov rax,imm64; jmp rax (12B) + NOPs
    DWORD old;
    VirtualProtect(target, STOLEN, PAGE_EXECUTE_READWRITE, &old);
    memset(target, 0x90, STOLEN);
    target[0] = 0x48; target[1] = 0xB8;
    *(uint64_t*)(target + 2) = (uintptr_t)hk_kx_derive;
    target[10] = 0xFF; target[11] = 0xE0;
    VirtualProtect(target, STOLEN, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, STOLEN);

    g_kx_orig = (kx_fn_t)tramp;
    log::info("whs: kx-derive hook(abs) @ %p tramp=%p", target, tramp);
    return true;
}

struct RealEnt { uint32_t rva; void* fn; const char* name; };
static const RealEnt REAL_IAT[] = {
    {0x4c0cc6c, (void*)f_SetStatusCallback, "WinHttpSetStatusCallback"},
    {0x4c0cc74, (void*)f_Open,              "WinHttpOpen"},
    {0x4c0cc7c, (void*)f_CloseHandle,       "WinHttpCloseHandle"},
    {0x4c0cc84, (void*)f_Connect,           "WinHttpConnect"},
    {0x4c0cc8c, (void*)f_QueryOption,       "WinHttpQueryOption"},
    {0x4c0cc94, (void*)f_SetOption,         "WinHttpSetOption"},
    {0x4c0cc9c, (void*)f_OpenRequest,       "WinHttpOpenRequest"},
    {0x4c0cca4, (void*)f_CrackUrl,          "WinHttpCrackUrl"},
    {0x4c0ccac, (void*)f_WsClose,           "WinHttpWebSocketClose"},
    {0x4c0ccb4, (void*)f_WsReceive,         "WinHttpWebSocketReceive"},
    {0x4c0ccbc, (void*)f_WsSend,            "WinHttpWebSocketSend"},
    {0x4c0ccc4, (void*)f_SendRequest,       "WinHttpSendRequest"},
    {0x4c0cccc, (void*)f_CompleteUpgrade,   "WinHttpWebSocketCompleteUpgrade"},
    {0x4c0ccd4, (void*)f_ReceiveResponse,   "WinHttpReceiveResponse"},
    {0x4c0c5ec, (void*)f_CreateMutexW,      "CreateMutexW"},
};

} // namespace

bool whs::install() {
    g_wh = LoadLibraryA("winhttp.dll");
    if (!g_wh) { log::err("whs: no winhttp.dll"); return false; }
    r_Open = (decltype(r_Open))GetProcAddress(g_wh, "WinHttpOpen");
    r_Connect = (decltype(r_Connect))GetProcAddress(g_wh, "WinHttpConnect");
    r_OpenRequest = (decltype(r_OpenRequest))GetProcAddress(g_wh, "WinHttpOpenRequest");
    r_SetStatusCallback = (decltype(r_SetStatusCallback))GetProcAddress(g_wh, "WinHttpSetStatusCallback");
    r_SetOption = (decltype(r_SetOption))GetProcAddress(g_wh, "WinHttpSetOption");
    r_QueryOption = (decltype(r_QueryOption))GetProcAddress(g_wh, "WinHttpQueryOption");
    r_CrackUrl = (decltype(r_CrackUrl))GetProcAddress(g_wh, "WinHttpCrackUrl");
    r_SendRequest = (decltype(r_SendRequest))GetProcAddress(g_wh, "WinHttpSendRequest");
    r_ReceiveResponse = (decltype(r_ReceiveResponse))GetProcAddress(g_wh, "WinHttpReceiveResponse");
    r_CompleteUpgrade = (decltype(r_CompleteUpgrade))GetProcAddress(g_wh, "WinHttpWebSocketCompleteUpgrade");
    r_WsSend = (decltype(r_WsSend))GetProcAddress(g_wh, "WinHttpWebSocketSend");
    r_WsReceive = (decltype(r_WsReceive))GetProcAddress(g_wh, "WinHttpWebSocketReceive");
    r_WsClose = (decltype(r_WsClose))GetProcAddress(g_wh, "WinHttpWebSocketClose");
    r_CloseHandle = (decltype(r_CloseHandle))GetProcAddress(g_wh, "WinHttpCloseHandle");
    r_CreateMutexW = (decltype(r_CreateMutexW))GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateMutexW");

    // [fn] port del ini
    char dir[MAX_PATH];
    GetModuleFileNameA(nullptr, dir, MAX_PATH);
    char* s = strrchr(dir, '\\');
    if (s) s[1] = 0;
    char inip[MAX_PATH];
    snprintf(inip, MAX_PATH, "%ser_local_mp.ini", dir);
    g_fn_port = (uint16_t)GetPrivateProfileIntA("fn", "port", 10901, inip);
    char host_a[64] = {};
    GetPrivateProfileStringA("net", "matchbox_ip", "127.0.0.1", host_a, sizeof(host_a), inip);
    GetPrivateProfileStringA("fn", "host", host_a, host_a, sizeof(host_a), inip);
    MultiByteToWideChar(CP_ACP, 0, host_a, -1, g_fn_host, 64);

    auto* base = (uint8_t*)GetModuleHandleA(nullptr);
    int patched = 0;
    for (const auto& e : REAL_IAT) {
        auto* slot = (void**)(base + e.rva);
        DWORD old;
        VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old);
        *slot = e.fn;
        VirtualProtect(slot, sizeof(void*), old, &old);
        ++patched;
    }
    log::info("whs: %d/14 real-IAT slots patched (passthrough, fn_port=%u)", patched, g_fn_port);

    // Hook kx-derive (pattern waygate) con salto absoluto + fixup rip
    install_kx_hook(base);

    return patched == 14 && g_kx_orig != nullptr;
}

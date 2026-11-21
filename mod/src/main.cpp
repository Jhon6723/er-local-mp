#include <windows.h>
#include <cstring>
#include <cstdio>
#include "log.h"
#include "config.h"
#include "detour.h"
#include "hooks/hooks.h"
#include "transport/transport.h"
#include "matchbox/client.h"

// Volcado minimo en crash: RIP relativo al modulo + registros + pila para
// rastrear la cadena de llamadas cuando el juego muere sin logs.
static LONG WINAPI crash_dump(EXCEPTION_POINTERS* ep) {
    auto* er = ep->ExceptionRecord;
    // Ignorar excepciones benignas (SetThreadName 0x406d1388, C++ throw 0xe06d7363, etc.)
    if (er->ExceptionCode < 0xC0000000UL || er->ExceptionCode == 0xE06D7363UL)
        return EXCEPTION_CONTINUE_SEARCH;
    auto* c = ep->ContextRecord;
    uintptr_t rip = (uintptr_t)c->Rip;
    uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);
    uintptr_t dllb = 0;
    { HMODULE m; if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                        (LPCSTR)rip, &m)) dllb = (uintptr_t)m; }
    log::err("CRASH code=0x%lx rip=%p (exe+0x%llx, mod+0x%llx) addr=%p",
             er->ExceptionCode, (void*)rip,
             (unsigned long long)(rip - base),
             (unsigned long long)(dllb ? rip - dllb : 0),
             er->ExceptionAddress);
    log::err("  rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p r8=%p r9=%p",
             (void*)c->Rax, (void*)c->Rbx, (void*)c->Rcx, (void*)c->Rdx,
             (void*)c->Rsi, (void*)c->Rdi, (void*)c->R8, (void*)c->R9);
    auto* sp = (uintptr_t*)c->Rsp;
    for (int i = 0; i < 24; ++i) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(&sp[i], &mbi, sizeof(mbi)) ||
            !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                             PAGE_EXECUTE_READWRITE))) break;
        uintptr_t v = sp[i];
        // marcar posibles return addresses dentro del exe
        const char* tag = (v > base && v < base + 0x6000000) ? " <ret?" : "";
        log::err("  [rsp+%02x] = %p%s", i * 8, (void*)v, tag);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI main_thread(LPVOID) {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    char dir[MAX_PATH];
    strncpy(dir, path, MAX_PATH - 1);
    dir[MAX_PATH - 1] = '\0';
    char* slash = strrchr(dir, '\\');
    const char* exe = slash ? (slash + 1) : path;
    bool is_p2 = (strstr(exe, "_p2") != nullptr || strstr(exe, "_P2") != nullptr);
    if (slash) slash[1] = '\0';

    char logp[MAX_PATH], inip[MAX_PATH];
    snprintf(logp, MAX_PATH, "%ser_local_mp%s.log", dir, is_p2 ? "_p2" : "");
    snprintf(inip, MAX_PATH, "%ser_local_mp.ini", dir);
    log::init(logp);

    Config cfg = load_config(inip);
    log::info("exe=%s player=%s matchbox=%s:%u listen=%u mode=%d",
              exe, cfg.player_name, cfg.matchbox_ip, cfg.matchbox_port, cfg.listen_port, cfg.mode);

    AddVectoredExceptionHandler(1, crash_dump);

    transport::init(cfg.listen_port);
    hooks::install();

    if (mb::init(cfg) && cfg.selftest) {
        if (cfg.selftest == 1) {
            uint32_t sid;
            log::info("selftest sign_up -> %s", mb::sign_up(0x2600, 0xABCD, &sid) ? "ok" : "fail");
            if (sid) log::info("selftest sign_id=%u", sid);
        } else if (cfg.selftest == 2 && cfg.join_id) {
            uint32_t sess, hip; uint16_t hport; uint8_t mode;
            if (mb::join(cfg.join_id, &sess, &hip, &hport, &mode))
                log::info("selftest join session=%u host=%08x:%u mode=%u", sess, hip, hport, mode);
            else log::err("selftest join failed");
        }
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(nullptr, 0, main_thread, nullptr, 0, nullptr);
    }
    return TRUE;
}

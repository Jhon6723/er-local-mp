#include <windows.h>
#include <cstring>
#include <cstdio>
#include "log.h"
#include "config.h"
#include "detour.h"
#include "hooks/hooks.h"
#include "transport/transport.h"
#include "matchbox/client.h"

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

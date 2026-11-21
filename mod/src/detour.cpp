#include "detour.h"
#include <cstring>
#include <initializer_list>
#include <windows.h>
#include "log.h"

static uint8_t* alloc_near(void* target) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    // simple approach: use VirtualAlloc anywhere; rel32 needs within 2GB
    // try allocating near target first
    uintptr_t base = (uintptr_t)target & ~0xFFFFull;
    for (int i = 0; i < 0x10000; i++) {
        uintptr_t lo = base - (uintptr_t)i * si.dwAllocationGranularity;
        uintptr_t hi = base + (uintptr_t)i * si.dwAllocationGranularity;
        for (uintptr_t addr : {lo, hi}) {
            void* p = VirtualAlloc((void*)addr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return (uint8_t*)p;
        }
    }
    return nullptr;
}

void* detour_install(void* target, void* hook, int stolen_bytes) {
    uint8_t* tramp = alloc_near(target);
    if (!tramp) { log::err("detour: no mem near %p", target); return nullptr; }
    // trampoline: stolen bytes + jmp back to target+stolen
    memcpy(tramp, target, stolen_bytes);
    tramp[stolen_bytes] = 0xE9;
    int32_t back = (int32_t)((uintptr_t)target + stolen_bytes - ((uintptr_t)tramp + stolen_bytes + 5));
    memcpy(tramp + stolen_bytes + 1, &back, 4);
    DWORD old;
    VirtualProtect(target, stolen_bytes, PAGE_EXECUTE_READWRITE, &old);
    memset(target, 0x90, stolen_bytes);
    ((uint8_t*)target)[0] = 0xE9;
    int32_t fwd = (int32_t)((uintptr_t)hook - ((uintptr_t)target + 5));
    memcpy((uint8_t*)target + 1, &fwd, 4);
    VirtualProtect(target, stolen_bytes, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, stolen_bytes);
    log::info("detour installed %p -> %p tramp=%p", target, hook, tramp);
    return tramp;
}

#pragma once
#include <cstdint>
// Minimal x64 detour: patches target with rel32 jmp to hook, builds trampoline.
void* detour_install(void* target, void* hook, int stolen_bytes);

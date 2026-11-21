#include "log.h"
#include <cstdarg>
#include <windows.h>
static FILE* g_fp;
static CRITICAL_SECTION g_cs;
void log::init(const char* path) {
    InitializeCriticalSection(&g_cs);
    g_fp = fopen(path, "w");
    info("er_local_mp log init");
}
void log::info(const char* fmt, ...) {
    if (!g_fp) return;
    EnterCriticalSection(&g_cs);
    va_list ap; va_start(ap, fmt);
    vfprintf(g_fp, fmt, ap); fputc('\n', g_fp); fflush(g_fp);
    va_end(ap);
    LeaveCriticalSection(&g_cs);
}
void log::err(const char* fmt, ...) {
    if (!g_fp) return;
    EnterCriticalSection(&g_cs);
    fputs("[ERR] ", g_fp);
    va_list ap; va_start(ap, fmt);
    vfprintf(g_fp, fmt, ap); fputc('\n', g_fp); fflush(g_fp);
    va_end(ap);
    LeaveCriticalSection(&g_cs);
}

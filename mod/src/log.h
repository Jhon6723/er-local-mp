#pragma once
#include <cstdio>
namespace log {
void init(const char* path);
void info(const char* fmt, ...);
void err(const char* fmt, ...);
}

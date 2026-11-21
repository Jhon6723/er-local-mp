#include "config.h"
#include <cstring>
#include <windows.h>
Config load_config(const char* path) {
    Config c;
    char buf[512];
    GetPrivateProfileStringA("player", "name", c.player_name, buf, sizeof buf, path);
    strncpy(c.player_name, buf, sizeof c.player_name - 1);
    GetPrivateProfileStringA("net", "matchbox_ip", c.matchbox_ip, buf, sizeof buf, path);
    strncpy(c.matchbox_ip, buf, sizeof c.matchbox_ip - 1);
    c.matchbox_port = (uint16_t)GetPrivateProfileIntA("net", "matchbox_port", c.matchbox_port, path);
    c.listen_port   = (uint16_t)GetPrivateProfileIntA("net", "listen_port", c.listen_port, path);
    c.mode          = GetPrivateProfileIntA("net", "mode", c.mode, path);
    c.selftest      = GetPrivateProfileIntA("test", "selftest", 0, path);
    c.join_id       = (uint32_t)GetPrivateProfileIntA("test", "join_id", 0, path);
    return c;
}

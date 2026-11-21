#pragma once
#include <cstdint>
struct Config {
    char player_name[64] = "Phantom";
    char matchbox_ip[64] = "127.0.0.1";
    uint16_t matchbox_port = 37015;
    uint16_t listen_port = 27016;
    int mode = 0; // 0=direct 1=relay
    int selftest = 0; // 0=off 1=sign_up 2=sign_up+join(sign_id en join_id)
    uint32_t join_id = 0;
};
Config load_config(const char* path);

#pragma once
#include <cstdint>
#include "../config.h"
namespace mb {
bool init(const Config& cfg);
void shutdown();
// blocking request/response against matchbox; returns payload len or -1
int request(uint8_t type, const void* payload, int plen, uint8_t want_type,
            void* out, int out_cap);
bool sign_up(uint32_t area_id, uint32_t char_hash, uint32_t* sign_id);
bool join(uint32_t sign_id, uint32_t* session_id, uint32_t* host_ip, uint16_t* host_port, uint8_t* mode);
uint32_t peer_id();
const char* server_ip();
}

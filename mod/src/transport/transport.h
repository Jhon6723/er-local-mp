#pragma once
#include <cstdint>

namespace transport {
bool init(uint16_t listen_port);
void shutdown();
uint16_t bound_port();
void set_local_steam_id(uint64_t sid);

void send_to(uint64_t peer_key, int channel, const void* data, int len);
void bind_peer(uint64_t peer_key, uint32_t ip_nbo, uint16_t port_host);
int  recv_peek(int channel);
bool recv(int channel, void* buf, uint32_t cap, uint32_t* out_len, uint64_t* out_key);
void close_channel(uint64_t peer_key, int channel);
void close_peer(uint64_t peer_key);
bool pop_new_peer(uint64_t* out_peer);
}

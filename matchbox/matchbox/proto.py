"""Wire protocol per docs/02-protocolo-matchbox.md (v0.1)."""
import socket
import struct

MAGIC = b"MR"
VERSION = 0x01
HEADER = struct.Struct("<2sBBH")  # magic, version, type, seq

T_REGISTER = 0x01
T_REGISTER_ACK = 0x02
T_SIGN_UP = 0x03
T_SIGN_UP_ACK = 0x0B
T_SIGN_LIST = 0x04
T_SIGN_LIST_ACK = 0x05
T_SIGN_DOWN = 0x06
T_JOIN = 0x07
T_JOIN_ACK = 0x08
T_PUNCH = 0x09
T_KEEPALIVE = 0x0A
T_GENERIC_ACK = 0x0C
T_NOTIFY_JOIN = 0x0D
T_RELAY = 0x10
T_ERROR = 0x7F

ERR_UNKNOWN_PEER = 1
ERR_NO_SIGN = 2
ERR_FULL = 3

MODE_DIRECT = 0
MODE_RELAY = 1

MAX_NAME = 32


def ip2i(ip: str) -> int:
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def i2ip(v: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", v))


def pack(mtype: int, seq: int, payload: bytes = b"") -> bytes:
    return HEADER.pack(MAGIC, VERSION, mtype, seq) + payload


def unpack(dgram: bytes) -> tuple[int, int, bytes]:
    if len(dgram) < HEADER.size:
        raise ValueError("short datagram")
    magic, ver, mtype, seq = HEADER.unpack_from(dgram)
    if magic != MAGIC or ver != VERSION:
        raise ValueError("bad magic/version")
    return mtype, seq, dgram[HEADER.size:]


def dec_register(p: bytes) -> dict:
    nlen = p[0]
    name = p[1 : 1 + nlen].decode("utf-8", "replace")[:MAX_NAME]
    ip, port, game_hash = struct.unpack_from("<IHI", p, 1 + nlen)
    return {"name": name, "ip": ip, "port": port, "game_hash": game_hash}


def enc_register_ack(peer_id: int) -> bytes:
    return struct.pack("<I", peer_id)


def dec_sign_up(p: bytes) -> dict:
    peer_id, area_id, char_hash = struct.unpack_from("<III", p)
    return {"peer_id": peer_id, "area_id": area_id, "char_hash": char_hash}


def enc_sign_up_ack(sign_id: int) -> bytes:
    return struct.pack("<I", sign_id)


def dec_sign_list(p: bytes) -> dict:
    peer_id, area_id = struct.unpack_from("<II", p)
    return {"peer_id": peer_id, "area_id": area_id}


def enc_sign_list_ack(signs: list[dict]) -> bytes:
    out = struct.pack("<H", len(signs))
    for s in signs:
        out += struct.pack("<IIII", s["sign_id"], s["peer_id"], s["char_hash"], s["area_id"])
    return out


def dec_sign_down(p: bytes) -> dict:
    peer_id, sign_id = struct.unpack_from("<II", p)
    return {"peer_id": peer_id, "sign_id": sign_id}


def dec_join(p: bytes) -> dict:
    peer_id, sign_id, want_mode = struct.unpack_from("<IIB", p)
    return {"peer_id": peer_id, "sign_id": sign_id, "want_mode": want_mode}


def enc_join_ack(host_peer_id: int, host_ip: int, host_port: int, mode: int, session_id: int) -> bytes:
    return struct.pack("<IIHBI", host_peer_id, host_ip, host_port, mode, session_id)


def enc_notify_join(session_id: int, joiner_peer_id: int, joiner_ip: int, joiner_port: int, mode: int) -> bytes:
    return struct.pack("<IIIHB", session_id, joiner_peer_id, joiner_ip, joiner_port, mode)


def dec_keepalive(p: bytes) -> int:
    return struct.unpack_from("<I", p)[0]


def dec_relay(p: bytes) -> tuple[int, bytes]:
    session_id = struct.unpack_from("<I", p)[0]
    return session_id, p[4:]


def enc_relay(session_id: int, data: bytes) -> bytes:
    return struct.pack("<I", session_id) + data


def enc_error(req_type: int, code: int) -> bytes:
    return struct.pack("<BB", req_type, code)


def enc_generic_ack() -> bytes:
    return b""

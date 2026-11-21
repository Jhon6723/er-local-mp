"""Control-message dispatch: REGISTER/SIGN_UP/SIGN_LIST/SIGN_DOWN/JOIN/KEEPALIVE."""
from . import proto
from .state import State


def err(seq: int, req_type: int, code: int) -> tuple[int, int, bytes]:
    return proto.T_ERROR, seq, proto.enc_error(req_type, code)


def dispatch(state: State, mtype: int, seq: int, payload: bytes, addr,
             force_relay: bool = False) -> list[tuple[tuple, int, int, bytes]]:
    """Returns list of (dest_addr, type, seq, payload) to send."""
    out = []

    if mtype == proto.T_REGISTER:
        d = proto.dec_register(payload)
        # observed source endpoint is authoritative for routing
        peer = state.new_peer(d["name"], addr, d["game_hash"])
        out.append((addr, proto.T_REGISTER_ACK, seq, proto.enc_register_ack(peer.peer_id)))

    elif mtype == proto.T_SIGN_UP:
        d = proto.dec_sign_up(payload)
        if not state.touch(d["peer_id"]):
            out.append((addr, *err(seq, mtype, proto.ERR_UNKNOWN_PEER)))
        else:
            s = state.add_sign(d["peer_id"], d["area_id"], d["char_hash"])
            out.append((addr, proto.T_SIGN_UP_ACK, seq, proto.enc_sign_up_ack(s.sign_id)))

    elif mtype == proto.T_SIGN_LIST:
        d = proto.dec_sign_list(payload)
        if not state.touch(d["peer_id"]):
            out.append((addr, *err(seq, mtype, proto.ERR_UNKNOWN_PEER)))
        else:
            signs = [
                {"sign_id": s.sign_id, "peer_id": s.peer_id,
                 "char_hash": s.char_hash, "area_id": s.area_id}
                for s in state.signs.values()
                if s.peer_id != d["peer_id"]
                and (d["area_id"] == 0 or s.area_id == d["area_id"])
            ]
            out.append((addr, proto.T_SIGN_LIST_ACK, seq, proto.enc_sign_list_ack(signs)))

    elif mtype == proto.T_SIGN_DOWN:
        d = proto.dec_sign_down(payload)
        s = state.signs.get(d["sign_id"])
        if s and s.peer_id == d["peer_id"]:
            del state.signs[d["sign_id"]]
        out.append((addr, proto.T_GENERIC_ACK, seq, proto.enc_generic_ack()))

    elif mtype == proto.T_JOIN:
        d = proto.dec_join(payload)
        joiner = state.peers.get(d["peer_id"])
        sign = state.signs.get(d["sign_id"])
        host = state.peers.get(sign.peer_id) if sign else None
        if not joiner:
            out.append((addr, *err(seq, mtype, proto.ERR_UNKNOWN_PEER)))
        elif not host:
            out.append((addr, *err(seq, mtype, proto.ERR_NO_SIGN)))
        else:
            del state.signs[d["sign_id"]]  # JOIN consumes the sign
            mode = proto.MODE_RELAY if force_relay else d["want_mode"]
            session = state.add_session(host, joiner)
            joiner_ip, joiner_port = joiner.addr
            host_ip, host_port = host.addr
            out.append((addr, proto.T_JOIN_ACK, seq,
                        proto.enc_join_ack(host.peer_id, proto.ip2i(host_ip),
                                           host_port, mode, session.session_id)))
            out.append((host.addr, proto.T_NOTIFY_JOIN, 0,
                        proto.enc_notify_join(session.session_id, joiner.peer_id,
                                              proto.ip2i(joiner_ip), joiner_port, mode)))

    elif mtype == proto.T_KEEPALIVE:
        state.touch(proto.dec_keepalive(payload))  # silent per spec

    elif mtype == proto.T_PUNCH:
        pass  # v2: hole-punch coordination

    else:
        out.append((addr, *err(seq, mtype, 0xFF)))

    return out

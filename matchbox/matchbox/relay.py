"""RELAY message forwarding between session peers."""
from . import proto
from .state import State


def handle_relay(state: State, payload: bytes, addr) -> list[tuple[tuple, int, int, bytes]]:
    session_id, data = proto.dec_relay(payload)
    s = state.sessions.get(session_id)
    if not s:
        return []
    if addr == s.a_addr:
        dest = s.b_addr
    elif addr == s.b_addr:
        dest = s.a_addr
    else:
        return []  # sender is not a member of this session
    state.touch(s.a_peer if addr == s.a_addr else s.b_peer)
    return [(dest, proto.T_RELAY, 0, proto.enc_relay(session_id, data))]

"""In-memory state: peers, signs, relay sessions."""
import time
from dataclasses import dataclass, field


@dataclass
class Peer:
    peer_id: int
    name: str
    addr: tuple[str, int]      # observed UDP endpoint (authoritative)
    game_hash: int
    last_seen: float


@dataclass
class Sign:
    sign_id: int
    peer_id: int
    area_id: int
    char_hash: int


@dataclass
class Session:
    session_id: int
    a_peer: int
    b_peer: int
    a_addr: tuple[str, int]
    b_addr: tuple[str, int]


@dataclass
class State:
    ttl: float = 60.0
    peers: dict[int, Peer] = field(default_factory=dict)
    signs: dict[int, Sign] = field(default_factory=dict)
    sessions: dict[int, Session] = field(default_factory=dict)
    _next_peer: int = 1
    _next_sign: int = 1
    _next_session: int = 1

    def new_peer(self, name: str, addr, game_hash: int) -> Peer:
        p = Peer(self._next_peer, name, addr, game_hash, time.monotonic())
        self._next_peer += 1
        self.peers[p.peer_id] = p
        return p

    def touch(self, peer_id: int) -> bool:
        p = self.peers.get(peer_id)
        if not p:
            return False
        p.last_seen = time.monotonic()
        return True

    def add_sign(self, peer_id: int, area_id: int, char_hash: int) -> Sign:
        s = Sign(self._next_sign, peer_id, area_id, char_hash)
        self._next_sign += 1
        self.signs[s.sign_id] = s
        return s

    def add_session(self, a: Peer, b: Peer) -> Session:
        s = Session(self._next_session, a.peer_id, b.peer_id, a.addr, b.addr)
        self._next_session += 1
        self.sessions[s.session_id] = s
        return s

    def sweep(self) -> None:
        now = time.monotonic()
        dead = [pid for pid, p in self.peers.items() if now - p.last_seen > self.ttl]
        for pid in dead:
            del self.peers[pid]
        if dead:
            self.signs = {sid: s for sid, s in self.signs.items() if s.peer_id not in dead}
            self.sessions = {
                sid: s for sid, s in self.sessions.items()
                if s.a_peer not in dead and s.b_peer not in dead
            }

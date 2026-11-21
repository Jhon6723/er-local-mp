"""Loopback functional test: REGISTER -> SIGN_UP -> SIGN_LIST -> JOIN -> RELAY."""
import socket
import struct
import threading
import time
import unittest

from matchbox import proto
from matchbox.main import serve
from matchbox.state import State

HOST = "127.0.0.1"


def client_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    s.bind((HOST, 0))
    return s


def rpc(sock, box, mtype, payload=b"", seq=1, wait=True):
    sock.sendto(proto.pack(mtype, seq, payload), box)
    if not wait:
        return None
    d, _ = sock.recvfrom(65535)
    return proto.unpack(d)


class FakeMod:
    """Minimal client speaking the matchbox protocol."""

    def __init__(self, box, name, game_hash=0xE1DE):
        self.sock = client_sock()
        self.box = box
        self.name = name
        self.game_hash = game_hash
        self.seq = 0
        self.peer_id = None

    def _seq(self):
        self.seq += 1
        return self.seq

    def call(self, mtype, payload=b""):
        return rpc(self.sock, self.box, mtype, payload, self._seq())

    def register(self):
        ip, port = self.sock.getsockname()
        p = struct.pack("<B", len(self.name)) + self.name.encode() + struct.pack(
            "<IHI", proto.ip2i(ip), port, self.game_hash)
        t, _, pl = self.call(proto.T_REGISTER, p)
        assert t == proto.T_REGISTER_ACK
        self.peer_id = struct.unpack_from("<I", pl)[0]
        return self.peer_id

    def sign_up(self, area_id=100, char_hash=0xCAFE):
        t, _, pl = self.call(proto.T_SIGN_UP,
                             struct.pack("<III", self.peer_id, area_id, char_hash))
        assert t == proto.T_SIGN_UP_ACK
        return struct.unpack_from("<I", pl)[0]

    def sign_list(self, area_id=0):
        t, _, pl = self.call(proto.T_SIGN_LIST,
                             struct.pack("<II", self.peer_id, area_id))
        assert t == proto.T_SIGN_LIST_ACK
        n = struct.unpack_from("<H", pl)[0]
        return [struct.unpack_from("<IIII", pl, 2 + 16 * i) for i in range(n)]

    def join(self, sign_id, want_mode=proto.MODE_RELAY):
        t, _, pl = self.call(
            proto.T_JOIN,
            struct.pack("<IIB", self.peer_id, sign_id, want_mode))
        assert t == proto.T_JOIN_ACK
        host_peer, host_ip, host_port, mode, session = struct.unpack_from("<IIHBI", pl)
        return {"host_peer": host_peer, "host": (proto.i2ip(host_ip), host_port),
                "mode": mode, "session": session}

    def keepalive(self):
        self.sock.sendto(proto.pack(proto.T_KEEPALIVE, self._seq(),
                                    struct.pack("<I", self.peer_id)), self.box)

    def relay_send(self, session_id, data):
        self.sock.sendto(proto.pack(proto.T_RELAY, 0,
                                    proto.enc_relay(session_id, data)), self.box)

    def recv(self):
        d, _ = self.sock.recvfrom(65535)
        return proto.unpack(d)

    def close(self):
        self.sock.close()


class MatchboxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stop = threading.Event()
        cls.state = State(ttl=1.0)
        cls.srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls.srv.bind((HOST, 0))
        cls.box = cls.srv.getsockname()
        cls.thread = threading.Thread(
            target=serve,
            args=(cls.srv, cls.state),
            kwargs={"stop_flag": cls.stop.is_set},
            daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.stop.set()
        cls.thread.join(timeout=3)
        cls.srv.close()

    def test_full_flow_relay(self):
        a = FakeMod(self.box, "hostA")
        b = FakeMod(self.box, "guestB")
        a.register()
        b.register()
        self.assertNotEqual(a.peer_id, b.peer_id)

        sign_id = a.sign_up(area_id=100)
        signs = b.sign_list(area_id=100)
        self.assertEqual(len(signs), 1)
        self.assertEqual(signs[0][0], sign_id)

        ack = b.join(sign_id, want_mode=proto.MODE_RELAY)
        self.assertEqual(ack["mode"], proto.MODE_RELAY)
        self.assertEqual(ack["host_peer"], a.peer_id)

        # host receives NOTIFY_JOIN with joiner endpoint
        t, _, pl = a.recv()
        self.assertEqual(t, proto.T_NOTIFY_JOIN)
        sid, joiner, jip, jport, mode = struct.unpack_from("<IIIHB", pl)
        self.assertEqual(sid, ack["session"])
        self.assertEqual(joiner, b.peer_id)
        self.assertEqual((proto.i2ip(jip), jport), b.sock.getsockname())

        # sign was consumed
        self.assertEqual(b.sign_list(area_id=100), [])

        # relay carries opaque payload both ways
        a.relay_send(sid, b"PING-from-host")
        t, _, pl = b.recv()
        self.assertEqual(t, proto.T_RELAY)
        sid2, data = proto.dec_relay(pl)
        self.assertEqual((sid2, data), (sid, b"PING-from-host"))

        b.relay_send(sid, b"PONG-from-guest")
        t, _, pl = a.recv()
        self.assertEqual(t, proto.T_RELAY)
        self.assertEqual(proto.dec_relay(pl)[1], b"PONG-from-guest")
        a.close(); b.close()

    def test_errors(self):
        c = FakeMod(self.box, "c")
        c.register()
        # JOIN a nonexistent sign -> ERR_NO_SIGN
        t, _, pl = c.call(proto.T_JOIN, struct.pack("<IIB", c.peer_id, 999, 0))
        self.assertEqual(t, proto.T_ERROR)
        self.assertEqual(pl[1], proto.ERR_NO_SIGN)
        # SIGN_UP with unregistered peer -> ERR_UNKNOWN_PEER
        t, _, pl = c.call(proto.T_SIGN_UP, struct.pack("<III", 777, 1, 1))
        self.assertEqual(t, proto.T_ERROR)
        self.assertEqual(pl[1], proto.ERR_UNKNOWN_PEER)
        c.close()

    def test_direct_mode_endpoint(self):
        a = FakeMod(self.box, "h")
        b = FakeMod(self.box, "g")
        a.register(); b.register()
        sid = a.sign_up()
        ack = b.join(sid, want_mode=proto.MODE_DIRECT)
        self.assertEqual(ack["mode"], proto.MODE_DIRECT)
        self.assertEqual(ack["host"], a.sock.getsockname())
        a.close(); b.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)

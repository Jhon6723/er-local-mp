"""matchbox server entry point.

Usage: python -m matchbox.main --port 37015 [--relay]
"""
import argparse
import socket
import time

from . import control, proto, relay
from .state import State

DEFAULT_PORT = 37015
SWEEP_INTERVAL = 15.0


def serve(sock: socket.socket, state: State, force_relay: bool = False,
          stop_flag=None) -> None:
    last_sweep = time.monotonic()
    sock.settimeout(1.0)
    while not (stop_flag and stop_flag()):
        try:
            dgram, addr = sock.recvfrom(65535)
        except socket.timeout:
            pass
        else:
            try:
                mtype, seq, payload = proto.unpack(dgram)
            except ValueError:
                continue
            if mtype == proto.T_RELAY:
                out = relay.handle_relay(state, payload, addr)
            else:
                out = control.dispatch(state, mtype, seq, payload, addr, force_relay)
            for dest, mtype_out, seq_out, p_out in out:
                sock.sendto(proto.pack(mtype_out, seq_out, p_out), dest)
        now = time.monotonic()
        if now - last_sweep > SWEEP_INTERVAL:
            state.sweep()
            last_sweep = now


def main() -> None:
    ap = argparse.ArgumentParser(prog="matchbox")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--relay", action="store_true",
                    help="force MODE_RELAY for all sessions")
    ap.add_argument("--ttl", type=float, default=60.0, help="peer TTL seconds")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    print(f"matchbox listening on {args.host}:{args.port} (relay={args.relay}, ttl={args.ttl})")
    serve(sock, State(ttl=args.ttl), force_relay=args.relay)


if __name__ == "__main__":
    main()

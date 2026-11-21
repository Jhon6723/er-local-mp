# fnserver.py — servidor FN local para Elden Ring (protocolo visto en waygate-server).
# Escucha ws://127.0.0.1:10901 (el mod redirige WinHttpConnect a este puerto).
#
# Handshake:
#   C -> 00 00 01 00                       hello
#   S -> nonce24 || box(pk_srv||nonce_srv||nonce_cli)   session advertisement
#   C -> nonce24 || mac16 || box(pk_cli)   clave publica efimera
#   (ambos derivan rx/tx con crypto_kx)
#   C -> mac16 || secretbox(msg)           request CreateSession/RestoreSession
#   S -> mac16 || secretbox(resp)
import asyncio, secrets, struct, sys, time

import websockets
import nacl.bindings as nacl

# Mismo par que el DLL escribe en el hook kx-derive.
CLIENT_PK = bytes.fromhex("cdefd8783a91b446640e2e1f95599db35e484a0071bd2182b3b60d0812c10c70")
SERVER_SK = bytes.fromhex("5353535353535353535353535353535353535353535353535353535353535353")

HOST, PORT = "0.0.0.0", 10901
NONCE, MAC = 24, 16


def inc(b):
    return (int.from_bytes(b, "little") + 1).to_bytes(len(b), "little")


def u32(v): return struct.pack("<I", v)
def i32(v): return struct.pack("<i", v)
def i64(v): return struct.pack("<q", v)

def s(v):
    b = v.encode("utf-8")
    return u32(len(b)) + b


def build_create_session(seq, player_id, external_id):
    # ResponseCreateSessionParams: variant 0
    now = int(time.time())
    cookie = secrets.token_hex(32)
    body = u32(0)  # variant CreateSession
    body += i32(player_id)
    body += s(external_id)
    body += s("127.0.0.1")
    body += i64(1) + i64(now - 43200) + i64(now + 43200) + s(cookie)
    body += s("")
    return bytes([5]) + u32(seq) + bytes([1]) + body


def build_restore_session(seq):
    now = int(time.time())
    cookie = secrets.token_hex(32)
    body = u32(2)  # variant RestoreSession
    body += i64(1) + i64(now - 43200) + i64(now + 43200) + s(cookie)
    body += s("")
    return bytes([5]) + u32(seq) + bytes([1]) + body


def build_error(seq):
    return bytes([5]) + u32(seq) + bytes([0]) + u32(0)


def build_ok(seq, variant, extra=b""):
    return bytes([5]) + u32(seq) + bytes([1]) + u32(variant) + extra


# --- Almacen de bloodmessages (simula otros jugadores) -----------------------
import json, os
BM_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bloodmessages.json")

def _load_bms():
    try:
        raw = json.load(open(BM_FILE))
        for e in raw:
            e["data"] = bytes.fromhex(e["data"])
        return raw
    except Exception:
        return []

def _save_bms():
    try:
        raw = [dict(e, data=e["data"].hex()) for e in BLOODMESSAGES]
        json.dump(raw, open(BM_FILE, "w"))
    except Exception as ex:
        print(f"[fn] save bms err: {ex}")

BLOODMESSAGES = _load_bms()
_next_ident = [max([e["id"] for e in BLOODMESSAGES], default=999) + 1]

# --- Almacen de ghostdata (fantasmas translucidos de otros jugadores) --------
GHOSTDATA = []

def parse_create_ghostdata(m):
    p = 9
    play_region, area = struct.unpack_from("<II", m, p); p += 8
    dlen = struct.unpack_from("<I", m, p)[0]; p += 4
    data = m[p:p + dlen]; p += dlen
    gcount = struct.unpack_from("<I", m, p)[0]; p += 4
    gps = []
    for _ in range(gcount):
        sl = struct.unpack_from("<I", m, p)[0]; p += 4
        gps.append(m[p:p + sl].decode("utf-8", "replace")); p += sl
    return dict(play_region=play_region, area=area, data=data, gps=gps)

def ghostdata_entry(e):
    out = u32(e["play_region"]) + u32(e["area"]) + i64(e["id"])
    out += u32(len(e["data"])) + e["data"]
    out += u32(len(e["gps"])) + b"".join(s(g) for g in e["gps"])
    return out

# --- Almacen de bloodstains (manchas de sangre / replays de muerte) ----------
BLOODSTAINS = []

def parse_create_bloodstain(m):
    p = 9
    play_region, area = struct.unpack_from("<II", m, p); p += 8
    alen = struct.unpack_from("<I", m, p)[0]; p += 4
    adv = m[p:p + alen]; p += alen
    rlen = struct.unpack_from("<I", m, p)[0]; p += 4
    replay = m[p:p + rlen]; p += rlen
    gps = _parse_strs(m, p)
    return dict(play_region=play_region, area=area, adv=adv, replay=replay,
                gps=gps)

def bloodstain_entry(e):
    out = u32(e["play_region"]) + u32(e["area"]) + i64(e["id"])
    out += u32(len(e["adv"])) + e["adv"]
    out += u32(len(e["gps"])) + b"".join(s(g) for g in e["gps"])
    return out

def _parse_search_areas(m):
    n = struct.unpack_from("<I", m, 9)[0]
    areas = set()
    for i in range(n):
        pr, ar = struct.unpack_from("<II", m, 13 + i * 8)
        areas.add((pr, ar))
    return areas

# --- Signos de invocacion (co-op) + Lobbies P2P ------------------------------
SIGNS = []
CLIENTS = {}      # player_id -> FNClient (con ws activo)
LOBBIES = {}      # lobby_id (u64) -> {"owner": u64, "members": [u64, ...]}
PEERS_NET = {}    # steam_id (u64) -> (ip_str, udp_port)
_next_lobby = [1]

def _fmt_lobby(lid):
    lb = LOBBIES.get(lid)
    if not lb:
        return b"err nolobby"
    mems = []
    for sid in lb["members"]:
        ip, port = PEERS_NET.get(sid, ("127.0.0.1", 27016))
        mems.append(f"{sid}:{ip}:{port}")
    return f"ok {lb['owner']} {','.join(mems)}".encode()

def _skip_match_params(m, p):
    # MatchingParameters: u32 reg_ver, u32 sell_region, u8 cross_disabled,
    # u32 unk1, u8 platform, u32 char_level, u32 unk2, u32 game_clear,
    # str password, u32 vow_type, u16 max_reinforce, u16 max_spirit_ash
    p += 8 + 1 + 4 + 1 + 12
    slen = struct.unpack_from("<I", m, p)[0]; p += 4 + slen
    p += 4 + 2 + 2
    return p

def _parse_strs(m, p):
    n = struct.unpack_from("<I", m, p)[0]; p += 4
    out = []
    for _ in range(n):
        sl = struct.unpack_from("<I", m, p)[0]; p += 4
        out.append(m[p:p + sl].decode("utf-8", "replace")); p += sl
    return out

def parse_create_sign(m):
    p = 9
    play_region, area = struct.unpack_from("<II", m, p); p += 8
    p = _skip_match_params(m, p)
    unk0 = struct.unpack_from("<I", m, p)[0]; p += 4
    dlen = struct.unpack_from("<I", m, p)[0]; p += 4
    data = m[p:p + dlen]; p += dlen
    gps = _parse_strs(m, p)
    return dict(play_region=play_region, area=area, data=data, gps=gps, unk0=unk0)

def sign_entry(e):
    out = i32(e["player_id"]) + i64(e["id"])
    out += u32(e["play_region"]) + u32(e["area"])
    out += u32(len(e["data"])) + e["data"]
    out += s(e["external_id"])
    out += u32(0)  # unk1
    out += u32(len(e["gps"])) + b"".join(s(g) for g in e["gps"])
    return out

def parse_create_bloodmessage(m):
    p = 9
    play_region, area = struct.unpack_from("<II", m, p); p += 8
    char_id = struct.unpack_from("<i", m, p)[0]; p += 4
    dlen = struct.unpack_from("<I", m, p)[0]; p += 4
    data = m[p:p + dlen]; p += dlen
    unk = struct.unpack_from("<i", m, p)[0]; p += 4
    gcount = struct.unpack_from("<I", m, p)[0]; p += 4
    gps = []
    for _ in range(gcount):
        sl = struct.unpack_from("<I", m, p)[0]; p += 4
        gps.append(m[p:p + sl].decode("utf-8", "replace")); p += sl
    return dict(play_region=play_region, area=area, char_id=char_id,
                data=data, unk=unk, gps=gps)

def bloodmessage_entry(e):
    out = i32(e.get("player_id", 7777)) + i32(e["char_id"]) + i64(e["id"])
    out += i32(e.get("good", 0)) + i32(e.get("bad", 0))
    out += u32(len(e["data"])) + e["data"]
    out += u32(e["play_region"]) + u32(e["area"])
    out += u32(len(e["gps"])) + b"".join(s(g) for g in e["gps"])
    return out


# --- Invasiones (BreakInTarget / PvP) ---------------------------------------
STRICT_MATCHING = False  # True = rangos de nivel/arma estilo waygate
BREAKIN_POOL = {}      # player_id -> dict(level, weapon, play_region)
BREAKIN_ATTEMPTS = {}  # (host_pid, invader_pid) -> (FNClient invasor, ts)

class Cur:
    def __init__(self, m, p=9):
        self.m, self.p = m, p
    def u32(self):
        v = struct.unpack_from("<I", self.m, self.p)[0]; self.p += 4; return v
    def u16(self):
        v = struct.unpack_from("<H", self.m, self.p)[0]; self.p += 2; return v
    def u8(self):
        v = self.m[self.p]; self.p += 1; return v
    def str_(self):
        n = self.u32(); b = self.m[self.p:self.p + n]; self.p += n; return b
    def vec_u32(self):
        return [self.u32() for _ in range(self.u32())]
    def vec_i32(self):
        return [struct.unpack_from("<i", self.m, self.p + 4 * i)[0]
                for i in range(self.u32())]
    def skip(self, n):
        self.p += n

def parse_update_player_status(m):
    c = Cur(m)
    c.u32()                        # unk1
    play_region = c.u32()
    c.skip(6 * 4)                  # game_clear..hosts_killed
    # CharacterData
    c.skip(8); c.u8()              # reg_ver, sell_region, cross_disabled
    level = c.u32()
    c.str_()                       # character_name (ShiftJis)
    c.u8()                         # furled_finger_enabled
    c.skip(4 + 4 + 4)              # runes, total_runes, archetype
    c.u8()                         # gender
    c.skip(9 * 4)                  # stats
    c.skip(9 * 4)                  # attributes
    c.skip(3 * 4)                  # equip_load, max_equip_load, poise
    c.skip(4)                      # discovery
    c.skip(6 * 4)                  # attack_power
    c.skip(8 * 4)                  # defense
    c.skip(8 * 4)                  # unused_resistances
    c.skip(4 * 4)                  # gauges
    c.skip(4 * 4)                  # unused_gauge_timers
    c.skip(4 * 4)                  # hp_flasks, fp_flasks, unk1, unk2
    c.vec_u32()                    # owned_dlcs
    c.vec_u32()                    # visited_areas
    c.skip(7 * 4)                  # scadutree, spirit_ash, beat_dlc, unk3[4]
    c.u32()                        # solo_break_in_point
    max_reinforce = c.u32()
    c.u8(); c.u32(); c.skip(11)    # unk4 u8, unk5 u32, unk6[11]
    # multiplayer_data
    c.u32(); c.u8()                # unk1, platform
    player_count = c.u32()
    c.u8()                         # unk2
    invadeable = c.u8()
    c.skip(3)                      # rune_mem, hunter, sinner_hunter
    c.u8()                         # unk3
    c.vec_u32()                    # chr_team_types
    c.vec_u32()                    # unk7
    c.str_()                       # password (aqui ya tenemos todo)
    return dict(play_region=play_region, level=level,
                max_reinforce=max_reinforce, player_count=player_count,
                invadeable=invadeable)

def _lvl_ok(host, inv):
    lo = inv - inv // 10
    hi = 713 if inv >= 301 else inv + -(-inv // 10) + 20
    return lo <= host <= hi

def _push_to(self, tgt_client, variant_u32, payload):
    body = u32(1) + i64(secrets.randbelow(2**62))
    body += u32(variant_u32) + payload
    tgt_client.push_queue.put_nowait(
        tgt_client.encrypt_push(bytes([6, 0]) + body))


_next_player_id = [1001]

class FNClient:
    def __init__(self, peer_ip="127.0.0.1"):
        self.state = 0
        self.peer_ip = peer_ip
        self.epk, self.esk = nacl.crypto_box_keypair()  # par efimero del "servidor"
        self.server_nonce = secrets.token_bytes(NONCE)
        self.client_nonce = secrets.token_bytes(NONCE)
        self.rx = self.tx = None
        self.player_id = _next_player_id[0]; _next_player_id[0] += 1
        self.external_id = f"{(0x0110000100002000 + self.player_id):x}"
        self.push_queue = asyncio.Queue()
        self.log = lambda *a: print(f"[p{self.player_id}]", *a)

    def _sync_ticket_identity(self, m):
        idx = m.find(b"ERLOCALMP_TICKET")
        if idx >= 0 and idx + 22 <= len(m):
            acct_id, uport = struct.unpack_from("<IH", m, idx + 16)
            if acct_id > 0:
                sid = 0x0110000100000000 | acct_id
                self.external_id = f"{sid:x}"
                if uport > 0:
                    PEERS_NET[sid] = (self.peer_ip, uport)
                self.log(f"[fn] ticket acct={acct_id:#x} external_id={self.external_id} udp={self.peer_ip}:{uport}")

    def feed(self, data):
        if self.state == 0:
            if data != b"\x00\x00\x01\x00":
                raise ValueError(f"hello invalido: {data.hex()}")
            self.state = 1
            plain = self.epk + self.server_nonce + self.client_nonce
            n0 = secrets.token_bytes(NONCE)
            boxed = nacl.crypto_box(plain, n0, CLIENT_PK, SERVER_SK)
            self.log(f"[fn] hello OK -> advertisement ({24 + len(boxed)}B)")
            return n0 + boxed

        if self.state == 1:
            n0, mac_ct = data[:NONCE], data[NONCE:]
            cpk = nacl.crypto_box_open(mac_ct, n0, CLIENT_PK, SERVER_SK)
            self.rx, self.tx = nacl.crypto_kx_server_session_keys(self.epk, self.esk, cpk)
            self.log(f"[fn] client pk {cpk.hex()[:16]}.. -> session keys derivadas")
            self.state = 2
            return None

        mac_ct = data
        plain = nacl.crypto_secretbox_open(mac_ct, self.client_nonce, self.rx)
        self.client_nonce = inc(self.client_nonce)
        self.log(f"[fn] rx plain ({len(plain)}B): {plain[:64].hex()}")
        resp = self.handle(plain)
        if resp is None:
            return None
        out = nacl.crypto_secretbox(resp, self.server_nonce, self.tx)
        self.server_nonce = inc(self.server_nonce)
        self.log(f"[fn] tx ({len(out)}B)")
        return out

    def handle(self, m):
        t = m[0]
        if t == 4:  # Request
            seq, variant = struct.unpack_from("<II", m, 1)
            self.log(f"[fn] request seq={seq} variant={variant} len={len(m)} body={m[9:48].hex()}")
            if variant == 0:
                self._sync_ticket_identity(m)
                return build_create_session(seq, self.player_id, self.external_id)
            if variant == 2:
                self._sync_ticket_identity(m)
                return build_restore_session(seq)
            if variant == 6:  # GetAnnounceMessageList { changes: [], notices: [] }
                return build_ok(seq, variant, u32(0) + u32(0))
            if variant == 7:  # CreateSign -> guardar signo de invocacion
                e = parse_create_sign(m)
                e["id"] = _next_ident[0]; _next_ident[0] += 1
                e["kind"] = "playregion"
                e["player_id"] = self.player_id
                e["external_id"] = self.external_id
                SIGNS.append(e)
                self.log(f"[fn] sign #{e['id']} area={e['area']} "
                         f"region={e['play_region']} data={len(e['data'])}B")
                return build_ok(seq, variant, i64(e["id"]))
            if variant == 8:  # CreateMatchAreaSign -> signo en effigy/puddle
                p = 9
                match_area, flags = struct.unpack_from("<IQ", m, p); p += 12
                p = _skip_match_params(m, p)
                unk2 = struct.unpack_from("<i", m, p)[0]; p += 4
                dlen = struct.unpack_from("<I", m, p)[0]; p += 4
                data = m[p:p + dlen]; p += dlen
                gps = _parse_strs(m, p)
                e = dict(id=_next_ident[0], kind="puddle", match_area=match_area,
                         flags=flags, play_region=0, area=0, data=data, gps=gps,
                         player_id=self.player_id, external_id=self.external_id)
                _next_ident[0] += 1
                SIGNS.append(e)
                self.log(f"[fn] matchsign #{e['id']} match_area={match_area} "
                         f"flags={flags:x} data={dlen}B")
                return build_ok(seq, variant, i64(e["id"]))
            if variant == 9:  # UpdateSign {identifier, unk0} -> eco
                ident, unk0 = struct.unpack_from("<qI", m, 9)
                return build_ok(seq, variant, i64(ident) + u32(unk0))
            if variant == 10:  # GetSignList -> signos de OTROS en las areas
                n = struct.unpack_from("<I", m, 9)[0]
                known = [struct.unpack_from("<q", m, 13 + i * 8)[0]
                         for i in range(n)]
                p = 13 + n * 8
                n2 = struct.unpack_from("<I", m, p)[0]; p += 4
                areas = set()
                for i in range(n2):
                    areas.add(struct.unpack_from("<II", m, p + i * 8))
                pool = [e for e in SIGNS if e["kind"] == "playregion"
                        and (e["play_region"], e["area"]) in areas
                        and e["player_id"] != self.player_id]
                still = [e["id"] for e in pool if e["id"] in known]
                match = [e for e in pool if e["id"] not in known]
                entries = b"".join(sign_entry(e) for e in match)
                self.log(f"[fn] GetSignList -> {len(match)} signos "
                         f"(de {len(SIGNS)}, known {len(still)}/{len(known)})")
                return build_ok(seq, variant,
                                u32(len(still)) + b"".join(i64(i) for i in still)
                                + u32(len(match)) + entries)
            if variant == 11:  # GetMatchAreaSignList -> signos en puddles
                n = struct.unpack_from("<I", m, 9)[0]
                known = [struct.unpack_from("<q", m, 13 + i * 8)[0]
                         for i in range(n)]
                p = 13 + n * 8
                np = struct.unpack_from("<I", m, p)[0]; p += 4
                puddles = []
                for i in range(np):
                    pid = struct.unpack_from("<I", m, p)[0]; p += 4
                    fl = struct.unpack_from("<I", m, p)[0]; p += 4
                    fu = 0
                    for b in m[p:p + fl]:
                        if b < 64: fu |= 1 << b
                    p += fl
                    puddles.append((pid, fu))
                pool = [e for e in SIGNS if e["kind"] == "puddle"
                        and any(e["match_area"] == ma and e["flags"] & fu
                                for ma, fu in puddles)
                        and e["player_id"] != self.player_id]
                still = [e["id"] for e in pool if e["id"] in known]
                match = [e for e in pool if e["id"] not in known]
                entries = b"".join(
                    i32(e["player_id"]) + i64(e["id"]) +
                    u32(e["match_area"]) + struct.pack("<Q", e["flags"]) +
                    u32(len(e["data"])) + e["data"] + s(e["external_id"]) +
                    u32(0) + u32(len(e["gps"])) +
                    b"".join(s(g) for g in e["gps"])
                    for e in match)
                self.log(f"[fn] GetMatchAreaSignList -> {len(match)} signos "
                         f"(puddles={len(puddles)})")
                return build_ok(seq, variant,
                                u32(len(still)) + b"".join(i64(i) for i in still)
                                + u32(len(match)) + entries)
            if variant == 12:  # RemoveSign {identifier}
                ident = struct.unpack_from("<q", m, 9)[0]
                SIGNS[:] = [e for e in SIGNS if e["id"] != ident]
                self.log(f"[fn] RemoveSign #{ident}")
                return build_ok(seq, variant)
            if variant == 13:  # SummonSign {player_id:i32, identifier:i64, join_data:Vec<u8>}
                target_pid, sign_id = struct.unpack_from("<iq", m, 9)
                dlen = struct.unpack_from("<I", m, 21)[0]
                join_data = m[25:25 + dlen]
                tgt = CLIENTS.get(target_pid)
                if tgt and tgt.tx:
                    body = u32(1) + i64(secrets.randbelow(2**62))
                    body += u32(6)  # JoinPayload::SummonSign
                    body += i32(self.player_id)
                    body += s(self.external_id)
                    body += i32(target_pid)
                    body += i64(sign_id)
                    body += u32(len(join_data)) + join_data
                    tgt.push_queue.put_nowait(
                        tgt.encrypt_push(bytes([6, 0]) + body))
                    self.log(f"[fn] SummonSign #{sign_id} -> push a p{target_pid} "
                             f"(join_data {dlen}B)")
                else:
                    self.log(f"[fn] SummonSign #{sign_id} -> p{target_pid} OFFLINE")
                return build_ok(seq, variant)
            if variant == 14:  # RejectSign {sign_id, summoner_pid, reason}
                sign_id, summoner, reason = struct.unpack_from("<qii", m, 9)
                tgt = CLIENTS.get(summoner)
                if tgt and tgt.tx:
                    body = u32(1) + i64(secrets.randbelow(2**62))
                    body += u32(7)  # JoinPayload::RejectSign
                    body += i64(sign_id) + i32(self.player_id)
                    tgt.push_queue.put_nowait(
                        tgt.encrypt_push(bytes([6, 0]) + body))
                self.log(f"[fn] RejectSign #{sign_id} -> p{summoner} "
                         f"reason={reason}")
                return build_ok(seq, variant)
            if variant == 15:  # CreateBloodMessage -> guardar y responder identifier
                e = parse_create_bloodmessage(m)
                e["id"] = _next_ident[0]; _next_ident[0] += 1
                e["player_id"] = self.player_id
                e["good"] = e["bad"] = 0
                BLOODMESSAGES.append(e); _save_bms()
                self.log(f"[fn] bloodmessage #{e['id']} area={e['area']} "
                         f"region={e['play_region']} data={len(e['data'])}B")
                return build_ok(seq, variant, i64(e["id"]))
            if variant == 16:  # RemoveBloodMessage {identifier:i64} solo autor
                ident = struct.unpack_from("<q", m, 9)[0]
                before = len(BLOODMESSAGES)
                BLOODMESSAGES[:] = [e for e in BLOODMESSAGES
                                    if not (e["id"] == ident
                                            and e["player_id"] == self.player_id)]
                _save_bms()
                self.log(f"[fn] RemoveBloodMessage #{ident} "
                         f"({before - len(BLOODMESSAGES)} borrados)")
                return build_ok(seq, variant)
            if variant == 19:  # EvaluateBloodMessage {identifier:i64, rating:u32}
                ident, rating = struct.unpack_from("<qI", m, 9)
                e = next((x for x in BLOODMESSAGES if x["id"] == ident), None)
                if not e or rating > 1:
                    return build_error(seq)
                key = "good" if rating == 0 else "bad"
                e[key] = e.get(key, 0) + 1
                _save_bms()
                self.log(f"[fn] EvaluateBloodMessage #{ident} rating={rating} "
                         f"-> good={e.get('good', 0)} bad={e.get('bad', 0)}")
                tgt = CLIENTS.get(e["player_id"])
                if tgt and tgt.tx:
                    body = u32(1) + i64(secrets.randbelow(2**62))
                    body += u32(1)  # JoinPayload::EvaluateBloodMessage
                    body += i32(0) + i64(ident) + u32(rating)
                    tgt.push_queue.put_nowait(
                        tgt.encrypt_push(bytes([6, 0]) + body))
                return build_ok(seq, variant)
            if variant == 20:  # GetBloodMessageDetail (sin params) -> vacio
                return build_ok(seq, variant)
            if variant == 21:  # CreateBloodstain -> mancha + replay de muerte
                e = parse_create_bloodstain(m)
                e["id"] = _next_ident[0]; _next_ident[0] += 1
                e["player_id"] = self.player_id
                BLOODSTAINS.append(e)
                self.log(f"[fn] bloodstain #{e['id']} area={e['area']} "
                         f"region={e['play_region']} adv={len(e['adv'])}B "
                         f"replay={len(e['replay'])}B")
                return build_ok(seq, variant, i64(e["id"]))
            if variant == 22:  # GetBloodstainList -> manchas de OTROS jugadores
                regions = {pr for pr, _ in _parse_search_areas(m)}
                match = [e for e in BLOODSTAINS
                         if e["play_region"] in regions
                         and e["player_id"] != self.player_id][:64]
                entries = b"".join(bloodstain_entry(e) for e in match)
                self.log(f"[fn] GetBloodstainList -> {len(match)} manchas "
                         f"(de {len(BLOODSTAINS)}, regiones={len(regions)})")
                return build_ok(seq, variant, u32(len(match)) + entries)
            if variant == 23:  # GetDeadingGhost {area, identifier} -> replay
                _, _, ident = struct.unpack_from("<IIq", m, 9)
                e = next((x for x in BLOODSTAINS if x["id"] == ident), None)
                if not e:
                    return build_error(seq)
                self.log(f"[fn] GetDeadingGhost #{ident} -> "
                         f"replay {len(e['replay'])}B")
                return build_ok(seq, variant,
                                i32(0) + i32(0) + i64(e["id"]) +
                                u32(len(e["replay"])) + e["replay"])
            if variant == 24:  # CreateGhostData -> guardar replay del fantasma
                e = parse_create_ghostdata(m)
                e["id"] = _next_ident[0]; _next_ident[0] += 1
                e["player_id"] = self.player_id
                GHOSTDATA.append(e)
                self.log(f"[fn] ghostdata #{e['id']} area={e['area']} "
                         f"region={e['play_region']} data={len(e['data'])}B")
                return build_ok(seq, variant, i64(e["id"]))
            if variant == 25:  # GetGhostDataList -> fantasmas de OTROS jugadores
                regions = {pr for pr, _ in _parse_search_areas(m)}
                match = [e for e in GHOSTDATA
                         if e["play_region"] in regions
                         and e["player_id"] != self.player_id]
                entries = b"".join(ghostdata_entry(e) for e in match)
                self.log(f"[fn] GetGhostDataList -> {len(match)} entradas "
                         f"(de {len(GHOSTDATA)}, regiones={len(regions)})")
                return build_ok(seq, variant, u32(len(match)) + entries)
            if variant == 18:  # GetBloodMessageList -> devolver mensajes guardados
                # body: u32 count, luego pares (play_region, area)
                areas = _parse_search_areas(m)
                match = [e for e in BLOODMESSAGES
                         if (e["play_region"], e["area"]) in areas]
                entries = b"".join(bloodmessage_entry(e) for e in match)
                self.log(f"[fn] GetBloodMessageList -> {len(match)} entradas "
                         f"(de {len(BLOODMESSAGES)}, areas={len(areas)})")
                return build_ok(seq, variant, u32(len(match)) + entries)
            if variant == 17:  # ReentryBloodMessage { identifiers[], unk }
                n = struct.unpack_from("<I", m, 9)[0]
                ids = [struct.unpack_from("<q", m, 13 + i * 8)[0] for i in range(n)]
                have = {e["id"] for e in BLOODMESSAGES}
                ok = [i for i in ids if i in have]
                self.log(f"[fn] ReentryBloodMessage {n} ids -> {len(ok)} validos")
                return build_ok(seq, variant, u32(len(ok)) +
                              b"".join(i64(i) for i in ok))
            if variant == 26:  # UpdateLoginPlayerCharacter { character_id, unk1-6 }
                return build_ok(seq, variant, u32(1) + u32(0) * 6)
            if variant == 27:  # UpdatePlayerStatus -> mantener pool de invasion
                try:
                    st = parse_update_player_status(m)
                    was = self.player_id in BREAKIN_POOL
                    if st["invadeable"]:
                        BREAKIN_POOL[self.player_id] = st
                    else:
                        BREAKIN_POOL.pop(self.player_id, None)
                    if (self.player_id in BREAKIN_POOL) != was:
                        self.log(f"[fn] pool_breakin {'ENTRA' if st['invadeable'] else 'SALE'} "
                                 f"lvl={st['level']} w={st['max_reinforce']} "
                                 f"pr={st['play_region']} jugadores={st['player_count']}")
                    if not getattr(self, "_st_ok", False):
                        self._st_ok = True
                        self.log(f"[fn] status parseado: lvl={st['level']} "
                                 f"invadeable={st['invadeable']} "
                                 f"pr={st['play_region']} "
                                 f"jugadores={st['player_count']}")
                except Exception as ex:
                    self.log(f"[fn] status parse err: {ex}")
                return build_ok(seq, variant)
            if variant == 28:  # BreakInTarget {unk0, play_region, target_pid, unkc}
                unk0, pr, target, unkc = struct.unpack_from("<IIiI", m, 9)
                tgt = CLIENTS.get(target)
                if not tgt or not tgt.tx:
                    self.log(f"[fn] BreakInTarget -> p{target} OFFLINE")
                    return build_error(seq)
                BREAKIN_ATTEMPTS[(target, self.player_id)] = (self, time.time())
                _push_to(self, tgt, 2,  # JoinPayload::BreakInTarget
                         i32(self.player_id) + s(self.external_id) +
                         u32(0) + u32(0) + u32(pr))
                self.log(f"[fn] BreakInTarget p{self.player_id} invade a "
                         f"p{target} pr={pr}")
                return build_ok(seq, variant)
            if variant == 29:  # GetBreakInTargetList {pr, max, match_params, unk48}
                pr, maxc = struct.unpack_from("<II", m, 9)
                cl = struct.unpack_from("<I", m, 9 + 8 + 14)[0]  # char_level en MP
                now = time.time()
                for k, (inv_c, ts) in list(BREAKIN_ATTEMPTS.items()):
                    if now - ts > 30:
                        BREAKIN_ATTEMPTS.pop(k, None)
                match = [(pid, e) for pid, e in BREAKIN_POOL.items()
                         if pid != self.player_id
                         and (not STRICT_MATCHING
                              or (e["play_region"] == pr
                                  and _lvl_ok(e["level"], cl)))][:maxc or 8]
                entries = b"".join(
                    i32(pid) + s(CLIENTS[pid].external_id)
                    for pid, _ in match if pid in CLIENTS)
                self.log(f"[fn] GetBreakInTargetList pr={pr} -> {len(match)} "
                         f"hosts (pool={len(BREAKIN_POOL)}, lvl={cl})")
                return build_ok(seq, variant,
                                u32(pr) + u32(len(match)) + entries)
            if variant == 30:  # RejectBreakInTarget {invader_pid, reason, pr, unkc}
                inv_pid, reason = struct.unpack_from("<ii", m, 9)
                BREAKIN_ATTEMPTS.pop((self.player_id, inv_pid), None)
                tgt = CLIENTS.get(inv_pid)
                if tgt and tgt.tx:
                    _push_to(self, tgt, 4,  # JoinPayload::RejectBreakInTarget
                             i32(inv_pid) + i32(reason) + s("") + u32(0))
                self.log(f"[fn] RejectBreakIn host p{self.player_id} -> "
                         f"p{inv_pid} reason={reason}")
                return build_ok(seq, variant)
            if variant == 31:  # AllowBreakInTarget {invader_pid, join_data, unk1}
                inv_pid = struct.unpack_from("<i", m, 9)[0]
                dlen = struct.unpack_from("<I", m, 13)[0]
                join_data = m[17:17 + dlen]
                BREAKIN_ATTEMPTS.pop((self.player_id, inv_pid), None)
                tgt = CLIENTS.get(inv_pid)
                if tgt and tgt.tx:
                    _push_to(self, tgt, 3,  # JoinPayload::AllowBreakInTarget
                             i32(inv_pid) + u32(len(join_data)) + join_data +
                             u32(0))
                    self.log(f"[fn] AllowBreakIn p{inv_pid} <- host "
                             f"p{self.player_id} ({dlen}B join_data)")
                else:
                    self.log(f"[fn] AllowBreakIn -> p{inv_pid} OFFLINE")
                return build_ok(seq, variant)
            if variant == 38:  # GetMatchDensity { areas[], blue[], red[], unk1 }
                return build_ok(seq, variant, u32(0) * 4)
            if variant == 76:  # PollMatchingTicket { unk0: u32 }
                return build_ok(seq, variant, u32(0))
            # Respuestas con struct vacio (Join/LeaveMultiplay, *Log, SendRegulationHash, etc.)
            if variant in (35, 36, 37, 79, 81, 88) or (40 <= variant <= 65):
                return build_ok(seq, variant)
            return build_error(seq)
        if t == 6:  # ACK de push del cliente
            self.log(f"[fn] push ACK ({len(m)}B)")
            return None
        if t == 7:  # heartbeat 07 64 -> responder 07 64 para evitar timeout de sesion larga
            return b"\x07\x64"
        self.log(f"[fn] msg type={t} ignorado")
        return None

    def encrypt_push(self, plain):
        ct = nacl.crypto_secretbox(plain, self.server_nonce, self.tx)
        self.server_nonce = inc(self.server_nonce)
        return ct


async def pumper(c, ws):
    try:
        while True:
            data = await c.push_queue.get()
            await ws.send(data)
    except Exception:
        pass


async def handler(ws):
    peer = ws.remote_address
    print(f"[fn] conexion de {peer}")
    c = FNClient(peer[0] if peer else "127.0.0.1")
    CLIENTS[c.player_id] = c
    pump = asyncio.ensure_future(pumper(c, ws))
    try:
        async for msg in ws:
            if isinstance(msg, str):
                msg = msg.encode()
            try:
                resp = c.feed(msg)
                if resp:
                    await ws.send(resp)
            except Exception as e:
                print(f"[fn] error estado={c.state}: {e} data={msg[:48].hex()}")
                break
    except websockets.ConnectionClosed:
        pass
    pump.cancel()
    CLIENTS.pop(c.player_id, None)
    SIGNS[:] = [e for e in SIGNS if e["player_id"] != c.player_id]
    BREAKIN_POOL.pop(c.player_id, None)
    for k in [k for k in BREAKIN_ATTEMPTS if c.player_id in k]:
        BREAKIN_ATTEMPTS.pop(k, None)
    print(f"[fn] desconectado {peer} (estado={c.state})")


class CtrlProtocol(asyncio.DatagramProtocol):
    """Canal de control UDP :37017 — inyectar mensajes 'de otros jugadores'."""
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            resp = self.handle(data, addr)
        except Exception as e:
            resp = f"err {e}".encode()
        if resp:
            self.transport.sendto(resp, addr)

    def handle(self, data, addr=("127.0.0.1", 0)):
        if data.startswith(b"lcreate "):
            _, sid_b, port_b = data.split(b" ", 2)
            sid, port = int(sid_b), int(port_b)
            PEERS_NET[sid] = (addr[0], port)
            lid = 0x0184000000000000 | _next_lobby[0]
            _next_lobby[0] += 1
            LOBBIES[lid] = {"owner": sid, "members": [sid]}
            print(f"[lobby] create {lid:#x} owner={sid:#x} ({addr[0]}:{port})")
            return f"ok {lid}".encode()
        if data.startswith(b"ljoin "):
            _, lid_b, sid_b, port_b = data.split(b" ", 3)
            lid, sid, port = int(lid_b), int(sid_b), int(port_b)
            PEERS_NET[sid] = (addr[0], port)
            lb = LOBBIES.setdefault(lid, {"owner": sid, "members": []})
            if sid not in lb["members"]:
                lb["members"].append(sid)
            print(f"[lobby] join {lid:#x} member={sid:#x} ({addr[0]}:{port}) total={len(lb['members'])}")
            return _fmt_lobby(lid)
        if data.startswith(b"lpoll "):
            _, lid_b, sid_b, port_b = data.split(b" ", 3)
            lid, sid, port = int(lid_b), int(sid_b), int(port_b)
            if port > 0:
                PEERS_NET[sid] = (addr[0], port)
            return _fmt_lobby(lid)
        if data.startswith(b"lleave "):
            _, lid_b, sid_b = data.split(b" ", 2)
            lid, sid = int(lid_b), int(sid_b)
            lb = LOBBIES.get(lid)
            if lb and sid in lb["members"]:
                lb["members"].remove(sid)
                if not lb["members"]:
                    LOBBIES.pop(lid, None)
                elif lb["owner"] == sid:
                    lb["owner"] = lb["members"][0]
            print(f"[lobby] leave {lid:#x} member={sid:#x}")
            return b"ok"
        if data == b"dump":
            out = []
            for e in BLOODMESSAGES:
                out.append(f"id={e['id']} pr={e['play_region']} a={e['area']} "
                           f"char={e['char_id']} data={e['data'].hex()}")
            return ("\n".join(out) or "empty").encode()
        if data == b"dup":
            if not BLOODMESSAGES:
                return b"empty"
            import copy
            e = copy.deepcopy(BLOODMESSAGES[-1])
            e["id"] = _next_ident[0]; _next_ident[0] += 1
            e["good"] = 42
            BLOODMESSAGES.append(e); _save_bms()
            print(f"[ctl] dup -> #{e['id']} (player 8888)")
            return f"dup {e['id']}".encode()
        if data.startswith(b"inject "):
            # inject <play_region> <area> <hexdata> [char_id]
            parts = data.split(b" ", 5)
            _, pr, a, hx = parts[0], parts[1], parts[2], parts[3]
            cid = int(parts[4]) if len(parts) > 4 else 1
            pid = int(parts[5]) if len(parts) > 5 else 7777
            # heredar gps/unk de un mensaje real del area (el juego los usa
            # para decidir donde renderizar el signo)
            src = next((x for x in reversed(BLOODMESSAGES)
                        if x["gps"]), None)
            e = dict(id=_next_ident[0], play_region=int(pr), area=int(a),
                     char_id=cid, player_id=pid,
                     data=bytes.fromhex(hx.decode()),
                     unk=src["unk"] if src else 0,
                     gps=list(src["gps"]) if src else [],
                     good=42, bad=0)
            _next_ident[0] += 1
            BLOODMESSAGES.append(e); _save_bms()
            print(f"[ctl] inject -> #{e['id']} area={a} ({len(e['data'])}B)")
            return f"injected {e['id']}".encode()
        if data.startswith(b"rate "):
            _, ident, good = data.split(b" ", 2)
            for e in BLOODMESSAGES:
                if e["id"] == int(ident):
                    e["good"] = int(good)
                    return b"ok"
            return b"notfound"
        if data == b"signs":
            out = []
            for e in SIGNS:
                out.append(f"id={e['id']} pid={e['player_id']} kind={e['kind']} "
                           f"pr={e['play_region']} a={e['area']} "
                           f"ma={e.get('match_area')} data={e['data'].hex()}")
            return ("\n".join(out) or "empty").encode()
        return b"cmds: dump|dup|inject <pr> <a> <hex>|rate <id> <n>|signs"


async def main():
    print(f"[fn] escuchando ws://{HOST}:{PORT} + ctl udp 37017")
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(CtrlProtocol, local_addr=(HOST, 37017))
    async with websockets.serve(handler, HOST, PORT):
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)

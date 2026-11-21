# scan_1172.py — landmarks de er-local-mp sobre eldenring.exe v1.17.2
# (build F9118FEA…, image base 0x140000000). Busca strings clave y todas las
# referencias rip-relative en .text que apuntan a ellos / a slots de la IAT EOS.
import struct, sys

EXE = r"C:\Games\Elden Ring\ELDEN RING\eldenring.exe"
data = open(EXE, "rb").read()

pe = struct.unpack_from("<I", data, 0x3c)[0]
opt = pe + 24
image_base = struct.unpack_from("<Q", data, opt + 24)[0]
numsec = struct.unpack_from("<H", data, pe + 6)[0]
secs = []
for i in range(numsec):
    o = opt + 240 + i * 40
    name = data[o:o+8].rstrip(b'\0').decode('ascii', 'replace')
    vs, va, rs, rp = struct.unpack_from("<IIII", data, o + 8)
    secs.append({"name": name, "va": va, "vs": vs, "rp": rp, "rs": rs})

def rva2off(rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + s["vs"]:
            o = s["rp"] + (rva - s["va"])
            return o if o < s["rp"] + s["rs"] else None

def off2rva(o):
    for s in secs:
        if s["rp"] <= o < s["rp"] + s["rs"]:
            return s["va"] + (o - s["rp"])

def sec_of_rva(rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + s["vs"]:
            return s["name"]

def va(rva): return image_base + rva

text = next(s for s in secs if s["name"] == ".text")
T_RP, T_RS, T_VA = text["rp"], text["rs"], text["va"]

def find_all(pat, label=""):
    hits, start = [], 0
    while True:
        i = data.find(pat, start)
        if i < 0: break
        hits.append(i)
        start = i + 1
    for i in hits:
        rva = off2rva(i)
        print(f"  str '{label}' @ file 0x{i:x} -> RVA 0x{rva:x} (sec {sec_of_rva(rva)})")
    return [off2rva(i) for i in hits]

# escaneo vectorizado de .text: en cada posición, un disp32 rip-relative que
# resuelva a `target_rva` es un hit (target = pos_rva + 4 + disp).
def refs_to(target_rva, limit=40):
    hits = []
    buf = data[T_RP:T_RP + T_RS]
    for a in range(4):
        n = (len(buf) - a) // 4
        if n <= 0: continue
        import numpy as np
        vals = np.frombuffer(buf, dtype=np.uint32, count=n, offset=a).astype(np.int64)
        pos_rva = T_VA + a + 4 * np.arange(n, dtype=np.int64) + 4
        m = np.where(pos_rva + vals - 0x100000000 * (vals >= 0x80000000) == target_rva)[0]
        for k in m:
            hits.append(pos_rva[k] - 4)  # rva del campo disp32
    hits.sort()
    for h in hits[:limit]:
        print(f"    xref disp @ RVA 0x{h:x}")
    if len(hits) > limit: print(f"    ... +{len(hits)-limit} más")
    return hits

try:
    import numpy as np
except ImportError:
    print("numpy requerido para refs_to"); sys.exit(1)

print("=== strings ===")
STRS = [b"SekiroMutex", b"SteamMatchMaking009", b"SteamNetworking006",
        b"SteamUser021", b"SteamFriends017", b"SteamUtils010",
        b"SteamInternal_FindOrCreateUserInterface", b"expand 32-byte k",
        b"steam_api64.dll", b"EOSSDK-Win64-Shipping.dll"]
rv = {}
for s in STRS:
    rv[s.decode('ascii','replace')] = find_all(s, s.decode('ascii','replace'))

print("\n=== xrefs a strings (RipRel en .text) ===")
for s in STRS:
    for rva in rv.get(s.decode('ascii','replace'), []):
        print(f"  -> {s.decode('ascii','replace')} @ 0x{rva:x}:")
        refs_to(rva, limit=12)

print("\n=== xrefs a slots EOS IAT (base 0x3D61CC8) ===")
EOS_IAT_RVA = 0x3D61CC8
for slot, name in [(15, "Platform_Tick"), (24, "AddNotifyPeerAuthStatusChanged"),
                   (26, "AC_BeginSession"), (27, "AC_EndSession"),
                   (28, "AC_PollStatus"), (29, "AC_RegisterPeer"),
                   (30, "AC_UnregisterPeer"), (31, "AC_ReceiveMessageFromPeer")]:
    print(f"  slot[{slot}] {name} -> IAT RVA 0x{EOS_IAT_RVA + slot*8:x}:")
    refs_to(EOS_IAT_RVA + slot * 8, limit=14)

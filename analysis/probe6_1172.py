# probe6_1172.py — ronda 5: AOB kx (pattern waygate), g_eosMgr, globals Steam cacheados,
# handler auth real, mutex xref, func ranges
import struct, bisect
from capstone import *
from capstone.x86 import *

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

pdata = next(s for s in secs if s["name"] == ".pdata")
text = next(s for s in secs if s["name"] == ".text")
funcs = []
for o in range(pdata["rp"], pdata["rp"] + pdata["rs"], 12):
    b, e, _u = struct.unpack_from("<III", data, o)
    funcs.append((b, e))
funcs.sort()
begins = [f[0] for f in funcs]

def func_of(rva):
    i = bisect.bisect_right(begins, rva) - 1
    if i >= 0 and funcs[i][0] <= rva < funcs[i][1]:
        return funcs[i]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def disasm_range(begin, end):
    off = rva2off(begin)
    if off is None: return []
    return list(md.disasm(data[off:off + (end - begin)], image_base + begin))

# ---------- 1) kx AOB (pattern de waygate client-sodium.rs) ----------
print("=== 1) kx-derive AOB ===")
KXPAT = [None,0x53,None,0x83,0xEC,0x50,None,0x8B,0x05,None,None,None,None,None,
         0x33,0xC4,None,0x89,0x44,None,None,None,0x8B,0xC0,None,0x8B,0xD9,None,
         0x8B,0xC2,None,0x8D,0x4C,None,0x20,None,0x8B,0xD0]
tp, ts = text["rp"], text["rs"]
hits = []
L = len(KXPAT)
for o in range(tp, tp + ts - L):
    ok = True
    for i, m in enumerate(KXPAT):
        if m is not None and data[o + i] != m:
            ok = False; break
    if ok:
        hits.append(o)
print(f"  {len(hits)} match(es)")
for o in hits[:10]:
    rva = off2rva(o)
    f = func_of(rva)
    print(f"  RVA 0x{rva:x}  fn 0x{f[0]:x}..0x{f[1]:x}" if f else f"  RVA 0x{rva:x}")

# ---------- 2) g_eosMgr: rip-rel loads de .data dentro del watchdog ----------
print("\n=== 2) watchdog fn: loads rip-relative a .data ===")
wb, we = 0xde3150, 0xde4818
DATA_LO, DATA_HI = 0x3B18000, 0x4000000
seen = {}
for i in disasm_range(wb, wb + 0x400):
    is_rip = any(op.mem.base == X86_REG_RIP for op in i.operands)
    if i.mnemonic in ("mov", "lea", "cmp", "add") and is_rip:
        for op in i.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = i.address + i.size + op.mem.disp
                trva = tgt - image_base
                if DATA_LO <= trva < DATA_HI:
                    seen[trva] = (i.address, i.mnemonic, i.op_str)
for trva in sorted(seen):
    a, mn, ops = seen[trva]
    print(f"  .data 0x{trva:x}  <- 0x{a:x}: {mn} {ops}")

# ---------- 3) globals Steam cacheados: resolver fns ----------
print("\n=== 3) resolvers de interface: stores a .data ===")
RESOLVERS = [
    (0x23fb004, "SteamMatchMaking009"),
    (0x2644b54, "SteamNetworking006"),
    (0x258e874, "SteamUser021"),
    (0xe76884,  "SteamUser021#2"),
    (0xe74df4,  "SteamFriends017"),
    (0xe74e1c,  "SteamUtils010"),
    (0x27f45e9, "SteamUser021#3"),
    (0x27f3fe1, "SteamUtils010#2"),
]
for xref, tag in RESOLVERS:
    f = func_of(xref)
    if not f:
        print(f"  {tag}: xref 0x{xref:x} sin fn"); continue
    print(f"  {tag}: fn 0x{f[0]:x}..0x{f[1]:x}")
    for i in disasm_range(max(f[0], xref - 0x120), min(f[1], xref + 0x160)):
        is_rip = any(op.mem.base == X86_REG_RIP for op in i.operands)
        if not is_rip: continue
        for op in i.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = i.address + i.size + op.mem.disp
                trva = tgt - image_base
                if DATA_LO <= trva < DATA_HI and i.mnemonic in ("mov", "lea", "cmp"):
                    print(f"     0x{i.address:x}: {i.mnemonic} {i.op_str}  -> .data 0x{trva:x}")

# ---------- 4) handler auth: fn que contiene la escritura -1.0f @0xde5561 ----------
print("\n=== 4) handler PeerAuthStatusChanged ===")
f = func_of(0xde5561)
print(f"  fn 0x{f[0]:x}..0x{f[1]:x}" if f else "  sin fn")
# confirmar el lea r9 en la fn de AddNotify (0xde5b80..0xde61ac)
for i in disasm_range(0xde5b80, 0xde61ac):
    is_rip = any(op.mem.base == X86_REG_RIP for op in i.operands)
    if i.mnemonic == "lea" and is_rip:
        for op in i.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = i.address + i.size + op.mem.disp - image_base
                if 0xdd0000 <= tgt <= 0xe00000:
                    print(f"  0x{i.address:x}: {i.op_str} -> 0x{tgt:x}")

# ---------- 5) SekiroMutex: xref del string wide + caller CreateMutexW ----------
print("\n=== 5) SekiroMutex wide @ RVA 0x2b9b6c6 ===")
strva = image_base + 0x2b9b6c6
for o in range(tp, tp + ts - 7):
    if data[o] == 0x48 and data[o+1] == 0x8D:
        # lea reg,[rip+disp]
        for ins in md.disasm(data[o:o+8], image_base + off2rva(o), count=1):
            if ins.mnemonic == "lea" and any(op.mem.base == X86_REG_RIP for op in ins.operands):
                tgt = ins.address + ins.size + ins.operands[1].mem.disp
                if tgt == strva:
                    print(f"  lea @ 0x{ins.address:x}: {ins.op_str}")
                    f = func_of(off2rva(o))
                    if f: print(f"    en fn 0x{f[0]:x}..0x{f[1]:x}")
                    break

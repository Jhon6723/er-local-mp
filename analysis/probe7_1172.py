# probe7_1172.py — ronda 6: kx prologue , g_eosMgr , resolver ,
# CreateMutexW caller + SekiroMutex , SteamUser021#3  fn
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
funcs.sort(); begins = [f[0] for f in funcs]
def func_of(rva):
    i = bisect.bisect_right(begins, rva) - 1
    return funcs[i] if i >= 0 and funcs[i][0] <= rva < funcs[i][1] else None
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
def disasm_range(begin, end):
    off = rva2off(begin)
    return list(md.disasm(data[off:off + (end - begin)], image_base + begin)) if off else []

# ---------- 1) kx fn prologue ----------
print("=== 1) kx fn 0x1e6cb10 prologue ===")
o = rva2off(0x1e6cb10)
print("  bytes:", data[o:o+24].hex(' '))
for i in disasm_range(0x1e6cb10, 0x1e6cb7f):
    print(f"  0x{i.address:x}: {i.mnemonic} {i.op_str}")

# ---------- 2) EOS IAT callers： g_eosMgr （Platform_Create/Initialize ） ----------
EOS_IAT = image_base + 0x3D61CC8
print("\n=== 2) EOS delay-IAT call sites (slot -> caller fn) ===")
tp, ts = text["rp"], text["rs"]
for o in range(tp, tp + ts - 7):
    if data[o] == 0xFF and data[o+1] == 0x15:  # call [rip+disp]
        disp = struct.unpack_from("<i", data, o+2)[0]
        rva = off2rva(o)
        if rva is None: continue
        tgt = image_base + rva + 6 + disp
        slot = (tgt - EOS_IAT) // 8
        if 0 <= slot < 32 and tgt == EOS_IAT + slot * 8:
            f = func_of(rva)
            print(f"  call @0x140{rva:x} -> EOS[{slot}]  fn 0x{f[0]:x}..0x{f[1]:x}" if f else f"  call @0x140{rva:x} -> EOS[{slot}]")

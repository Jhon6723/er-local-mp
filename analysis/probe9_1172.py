# probe9_1172.py — ronda 8: resolver fn  g_eosMgr  fn start,
# mutex fn 0x25006e8 caller
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
DATA_LO, DATA_HI = 0x3B18000, 0x4100000

print("=== 1)  resolvers  ===")
for tag, b, e in [("MM", 0x23faff0, 0x23fb017), ("NET", 0x2644b40, 0x2644b67),
                  ("USER", 0x258e850, 0x258e890), ("FRD", 0xe74de0, 0xe74e07),
                  ("UTL", 0xe74e10, 0xe74e31)]:
    print(f"  -- {tag} 0x{b:x}..0x{e:x}")
    for i in disasm_range(b, e):
        extra = ""
        for op in i.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = i.address + i.size + op.mem.disp - image_base
                extra = f"   -> 0x{t:x}"
        print(f"     0x{i.address:x}: {i.mnemonic} {i.op_str}{extra}")

print("\n=== 2) fn 0xde83c0  rbx  ===")
for i in disasm_range(0xde83c0, 0xde83c0 + 0x140):
    extra = ""
    for op in i.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            t = i.address + i.size + op.mem.disp - image_base
            if DATA_LO <= t < DATA_HI:
                extra = f"   -> .data 0x{t:x}"
    if i.mnemonic in ("mov", "lea", "xor", "push", "sub") or extra:
        print(f"     0x{i.address:x}: {i.mnemonic} {i.op_str}{extra}")

print("\n=== 3) callers of fn 0x25006e8 (mutex  ) ===")
tp, ts = text["rp"], text["rs"]
tgt_va = image_base + 0x25006e8
for o in range(tp, tp + ts - 5):
    if data[o] == 0xE8:
        disp = struct.unpack_from("<i", data, o+1)[0]
        rva = off2rva(o)
        if rva is not None and image_base + rva + 5 + disp == tgt_va:
            f = func_of(rva)
            print(f"  call @0x140{rva:x} fn 0x{f[0]:x}..0x{f[1]:x}" if f else f"  call @0x140{rva:x}")
            for i in disasm_range(rva - 0x80, rva):
                for op in i.operands:
                    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                        t = i.address + i.size + op.mem.disp - image_base
                        print(f"     0x{i.address:x}: {i.mnemonic} {i.op_str} -> 0x{t:x}")

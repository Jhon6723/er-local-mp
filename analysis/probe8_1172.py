# probe8_1172.py — ronda 7: g_eosMgr Connect_Login client_data / session fn ,
# CreateMutexW caller + SekiroMutex ，resolver    .data stores
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

# ---------- 1) Connect_Login callsites client_data (r8)  ----------
print("=== 1) Connect_Login callsites   g_eosMgr  ===")
for call_rva in (0xde85d8, 0xdea977):
    print(f"  -- callsite 0x140{call_rva:x}")
    for i in disasm_range(call_rva - 0x60, call_rva + 0x10):
        rip_mem = [op for op in i.operands if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
        mark = ""
        for op in rip_mem:
            tgt = i.address + i.size + op.mem.disp - image_base
            if DATA_LO <= tgt < DATA_HI:
                mark = f"   -> .data 0x{tgt:x}"
        print(f"     0x{i.address:x}: {i.mnemonic} {i.op_str}{mark}")

# ---------- 2) session fn 0xde5b80  200B mgr / client_data  ----------
print("\n=== 2) fn 0xde5b80  0x120 .data  ===")
for i in disasm_range(0xde5b80, 0xde5b80 + 0x300):
    for op in i.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            tgt = i.address + i.size + op.mem.disp - image_base
            if DATA_LO <= tgt < DATA_HI:
                print(f"     0x{i.address:x}: {i.mnemonic} {i.op_str}  -> .data 0x{tgt:x}")

# ---------- 3) CreateMutexW IAT callers ----------
print("\n=== 3) CreateMutexW (IAT 0x4C1439C) callers ===")
MUTEX_IAT = image_base + 0x4C1439C
tp, ts = text["rp"], text["rs"]
for o in range(tp, tp + ts - 7):
    if data[o] == 0xFF and data[o+1] == 0x15:
        disp = struct.unpack_from("<i", data, o+2)[0]
        rva = off2rva(o)
        if rva is None: continue
        if image_base + rva + 6 + disp == MUTEX_IAT:
            f = func_of(rva)
            print(f"  call @0x140{rva:x}  fn 0x{f[0]:x}..0x{f[1]:x}" if f else f"  call @0x140{rva:x}")
            #  r9/name 
            for i in disasm_range(rva - 0x60, rva):
                for op in i.operands:
                    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                        tgt = i.address + i.size + op.mem.disp - image_base
                        print(f"     0x{i.address:x}: {i.mnemonic} {i.op_str} -> 0x{tgt:x}")

# ---------- 4) resolver callers → store  ----------
print("\n=== 4) resolver callers: call rel32 -> fn,  .data stores ===")
RES = {"MM": 0x23faff0, "NET": 0x2644b40, "USER": 0x258e850,
       "FRD": 0xe74de0, "UTL": 0xe74e10}
for tag, tgt_rva in RES.items():
    tgt_va = image_base + tgt_rva
    callers = []
    for o in range(tp, tp + ts - 5):
        if data[o] == 0xE8:
            disp = struct.unpack_from("<i", data, o+1)[0]
            rva = off2rva(o)
            if rva is not None and image_base + rva + 5 + disp == tgt_va:
                callers.append(rva)
    print(f"  {tag} resolver 0x{tgt_rva:x}: {len(callers)} callers")
    for crva in callers[:4]:
        f = func_of(crva)
        stores = []
        for i in disasm_range(crva, crva + 0x40):
            if i.mnemonic in ("jmp", "ret"): break
            for op in i.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = i.address + i.size + op.mem.disp - image_base
                    if DATA_LO <= t < DATA_HI:
                        stores.append((i.address, i.mnemonic, i.op_str, t))
        extra = "".join(f" | 0x{a:x}: {mn} {op} -> .data 0x{t:x}" for a, mn, op, t in stores)
        print(f"    call @0x140{crva:x} (fn 0x{f[0]:x}){extra}")

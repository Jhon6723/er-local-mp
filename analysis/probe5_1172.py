# probe5_1172.py — ronda 4: localizar o handler auth real dentro da fn
# 0xde5b80..0xde61ac e confirmar a escrita -1.0f no timer do peer
import struct
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

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
EOS_IAT_VA = 0x140000000 + 0x3D61CC8

def disasm_fn(begin, end):
    off = rva2off(begin)
    code = data[off:off + (end - begin)]
    return list(md.disasm(code, image_base + begin))

print("=== fn 0xde5b80..0xde61ac: IAT calls + lea r9 handlers ===")
ins = disasm_fn(0xde5b80, 0xde61ac)
last_lea_r9 = None
for i in ins:
    is_rip = any(op.mem.base == X86_REG_RIP for op in i.operands)
    if i.mnemonic == "lea" and "r9," in i.op_str and is_rip:
        tgt = i.address + i.size + i.operands[1].mem.disp
        last_lea_r9 = (i.address, tgt)
        print(f"  0x{i.address:x}: lea r9 -> 0x{tgt:x}")
    if i.mnemonic == "call" and is_rip:
        tgt = i.address + i.size + i.operands[0].mem.disp
        slot = (tgt - EOS_IAT_VA) // 8
        tag = f"EOS slot {slot}" if 0 <= slot < 32 and tgt == EOS_IAT_VA + slot*8 else f"0x{tgt:x}"
        print(f"  0x{i.address:x}: call -> {tag}   (last lea r9 -> 0x{last_lea_r9[1] if last_lea_r9 else 0:x})")
    if i.mnemonic == "call" and not is_rip:
        print(f"  0x{i.address:x}: call {i.op_str}")

print("\n=== varredura: escrita de -1.0f (0xbf800000) em +0x54 no módulo 0xdd0000..0xe00000 ===")
# padrão: mov dword ptr [reg + 0x54], 0xbf800000
text = next(s for s in secs if s["name"] == ".text")
for o in range(text["rp"], text["rp"] + text["rs"] - 8, 1):
    if struct.unpack_from("<I", data, o + 4)[0] == 0xbf800000 and data[o+3] == 0x54:
        rva = off2rva(o)
        if rva and 0xdd0000 <= rva <= 0xe00000:
            f = func_of if False else None
            print(f"  mov [reg+0x54], -1.0f @ RVA 0x{rva:x}")

# probe4_1172.py — ronda 4: handler auth, watchdog loop, FN/WinHTTP módulo
import struct
from capstone import *

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
md = Cs(CS_ARCH_X86, CS_MODE_64)
def disasm(rva, count, filt=None):
    off = rva2off(rva)
    code = data[off:off + count * 15]
    c = 0
    for i in md.disasm(code, image_base + rva):
        if filt is None or filt(i):
            print(f"  0x{i.address:x}: {i.mnemonic} {i.op_str}")
        c += 1
        if c >= count: break

print("=== handler candidato 0xde6728 (deve ter mov [r+0x54], 0xbf800000) ===")
disasm(0xde6728, 90, lambda i: True)
print("\n=== handler candidato 0xde6eac ===")
disasm(0xde6eac, 40, lambda i: any(k in i.op_str for k in ("0x54", "0xbf800000")) or True)

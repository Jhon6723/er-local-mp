# probe2_1172.py — ronda 2: mutex wide, RTTI corregido, watchdog 120f, módulo FN
import struct, sys
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
def sec_of_rva(rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + s["vs"]: return s["name"]

md = Cs(CS_ARCH_X86, CS_MODE_64)

print("=== 1) wide strings cerca de 0x2b9b6c6 ===")
o = rva2off(0x2b9b6c6)
ws = data[o:o+160]
chars = [ws[i] for i in range(0, 160, 2) if ws[i+1] == 0]
print("  .", bytes(chars).decode('ascii', 'replace')[:80])
o2 = rva2off(0x2b9b6d2)
ws = data[o2:o2+160]
chars = [ws[i] for i in range(0, 160, 2) if ws[i+1] == 0]
print("  .", bytes(chars).decode('ascii', 'replace')[:80])

print("\n=== 2) RTTI vtables (COL RVA vs puntero absoluto) ===")
def rtti(mangled):
    name = mangled.encode()
    i = data.find(name)
    if i < 0:
        print(f"  {mangled}: sin nombre"); return
    td_rva = off2rva(i) - 0x10
    col_rva = None
    pos = 0
    while True:
        o = data.find(struct.pack("<I", td_rva), pos)
        if o < 0: break
        cand = o - 0xC
        if cand >= 0 and struct.unpack_from("<I", data, cand)[0] == 1:
            col_rva = off2rva(cand); break
        pos = o + 4
    if not col_rva:
        print(f"  {mangled}: td@0x{td_rva:x} sin COL"); return
    # probar qword = col_rva (RVA) y qword = image_base+col_rva (VA)
    for want, tag in [(col_rva, "rva"), (image_base + col_rva, "va")]:
        pos = 0
        while True:
            o = data.find(struct.pack("<Q", want), pos)
            if o < 0: break
            vt_rva = off2rva(o)
            if vt_rva and sec_of_rva(vt_rva) in (".rdata", ".data"):
                slot0 = struct.unpack_from("<Q", data, o + 8)[0]
                print(f"  {mangled}: vt({tag}) @ 0x{vt_rva + 8:x}  fn0 -> 0x{slot0 - image_base:x}")
                return
            pos = o + 8
    print(f"  {mangled}: COL@0x{col_rva:x} sin vtable")

for m in [".?AVManagerImplSteam@DLNR3D@@", ".?AVSteamConnection@DLNW3D@@",
          ".?AVSteamConnectionManager@DLNW3D@@", ".?AVSteamServiceImpl@DLNW3D@@",
          ".?AVMTInternalThreadSteamSocketManager@DLNW3D@@",
          ".?AVSocketManagerHolder@DLNR3D@@", ".?AVCSNetAntiCheat@@",
          ".?AVSessionManagerSteam@@", ".?AVCSSessionManager@@"]:
    rtti(m)

print("\n=== 3) watchdog: float 120.0f (0x42F00000) usado en módulo de* ===")
pat = struct.pack("<f", 120.0)
pos = 0; flts = []
while True:
    o = data.find(pat, pos)
    if o < 0: break
    r = off2rva(o)
    if r and sec_of_rva(r) in (".rdata", ".data"): flts.append(r)
    pos = o + 1
print(f"  {len(flts)} float 120.0 en .rdata/.data")
# xref a cada uno dentro del rango del módulo EOS (0xdd0000..0xdf0000)
import numpy as np
tbuf = data[secs[0]["rp"]:secs[0]["rp"]+secs[0]["rs"]]  # .text primero? buscar la seccion
text = next(s for s in secs if s["name"] == ".text")
tbuf = data[text["rp"]:text["rp"]+text["rs"]]
for fr in flts:
    hits = []
    for a in range(4):
        n = (len(tbuf)-a)//4
        vals = np.frombuffer(tbuf, dtype=np.uint32, count=n, offset=a).astype(np.int64)
        pr = text["va"] + a + 4*np.arange(n, dtype=np.int64) + 4
        m = np.where(pr + vals - 0x100000000*(vals >= 0x80000000) == fr)[0]
        for k in m:
            d = pr[k]-4
            if 0xdd0000 <= d <= 0xdf5000: hits.append(d)
    if hits:
        print(f"  120.0f @ 0x{fr:x} <- .text {[hex(h) for h in hits]}")

print("\n=== 4) prologo de la fn que contiene 0xde5d59 ===")
# escanear hacia atrás hasta push rbp/mov rbp,rsp típico
off = rva2off(0xde5d59)
for back in range(0xde5d59 - 0x400, 0xde5d59, 8):
    o2 = rva2off(back)
    for i in md.disasm(data[o2:o2+16], image_base + back):
        if i.mnemonic == "push" and i.op_str == "rbp":
            nxt = image_base + back + i.size
            i2 = next(md.disasm(data[o2+i.size:o2+i.size+8], nxt), None)
            if i2 and i2.mnemonic == "mov" and "rbp, rsp" in i2.op_str:
                print(f"  prologo candidato @ 0x{back:x}")

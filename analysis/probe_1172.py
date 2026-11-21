# probe_1172.py — verificación de landmarks sobre eldenring.exe v1.17.2
# 1) mutex: variantes de nombre; 2) RTTI de clases de sesión;
# 3) desensamblado alrededor de callsites EOS (RegisterPeer, AddNotifyPeerAuth)
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
md.detail = True

def disasm(rva, n, base=None):
    off = rva2off(rva)
    code = data[off:off + n * 16]
    cnt = 0
    for i in md.disasm(code, image_base + rva):
        print(f"  0x{i.address:x}: {i.mnemonic} {i.op_str}")
        cnt += 1
        if cnt >= n: break

print("=== 1) mutex / strings de instancia ===")
for pat in [b"SekiroMutex", b"Sekiro", b"Mutex", b"ELDENRING", b"eldenring",
            b"ER_MUTEX", b"Global\\"]:
    i = data.find(pat)
    cnt = 0
    pos = 0
    offs = []
    while True:
        j = data.find(pat, pos)
        if j < 0: break
        offs.append(j); pos = j + 1; cnt += 1
        if cnt > 8: break
    print(f"  {pat}: {cnt} hits", [hex(off2rva(o) or o) for o in offs[:6]])
# wide
for pat in [b"S\x00e\x00k\x00i\x00r\x00o", b"M\x00u\x00t\x00e\x00x"]:
    i = data.find(pat)
    print(f"  wide {pat[:10]}...: {'0x%x' % (off2rva(i) or i) if i>=0 else 'none'}")

print("\n=== 2) RTTI (nombre mangled -> vtable RVA) ===")
def rtti(mangled):
    name = mangled.encode()
    i = data.find(name)
    if i < 0:
        print(f"  {mangled}: nombre no encontrado"); return
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
    # vtable ref: qword == col_rva-8, 16 bytes antes del slot0
    want = col_rva - 8
    pos = 0
    while True:
        o = data.find(struct.pack("<Q", want), pos)
        if o < 0: break
        vt = off2rva(o) + 0x10
        if sec_of_rva(vt) in (".rdata", ".data"):
            print(f"  {mangled}: vtable @ 0x{vt:x}  slot0 -> 0x{struct.unpack_from('<Q', data, o+0x10)[0]-image_base:x}")
            return
        pos = o + 8
    print(f"  {mangled}: COL@0x{col_rva:x} sin vtable")

for m in [".?AVSessionManagerSteam@@", ".?AVManagerImplSteam@DLNR3D@@",
          ".?AVSteamConnection@DLNW3D@@", ".?AVSteamConnectionManager@DLNW3D@@",
          ".?AVSteamServiceImpl@DLNW3D@@", ".?AVCSSessionManager@@",
          ".?AVCSNetAntiCheat@@", ".?AVMTInternalThreadSteamSocketManager@DLNW3D@@",
          ".?AVSocketManagerHolder@DLNR3D@@"]:
    rtti(m)

print("\n=== 3) callsites EOS ===")
print("-- RegisterPeer caller @ 0xde401d (contexto -0x40..+0x30)")
disasm(0xde401d - 0x40, 40)
print("-- AddNotifyPeerAuthStatusChanged caller @ 0xde5d59 (buscar lea r9 handler)")
disasm(0xde5d59 - 0x30, 30)
print("-- Platform_Tick caller @ 0xde31b9")
disasm(0xde31b9 - 0x20, 16)

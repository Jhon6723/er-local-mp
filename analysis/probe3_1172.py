# probe3_1172.py — ronda 3: rangos de función vía .pdata, watchdog, handler auth,
# módulo FN/kx (WinHTTP callers) y rangos de código de sesión
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

pdata = next(s for s in secs if s["name"] == ".pdata")
funcs = []  # (begin, end)
for o in range(pdata["rp"], pdata["rp"] + pdata["rs"], 12):
    b, e, _u = struct.unpack_from("<III", data, o)
    funcs.append((b, e))
funcs.sort()
import bisect
begins = [f[0] for f in funcs]
def func_of(rva):
    i = bisect.bisect_right(begins, rva) - 1
    if i >= 0 and funcs[i][0] <= rva < funcs[i][1]: return funcs[i]
    return None

md = Cs(CS_ARCH_X86, CS_MODE_64)
def disasm(rva, count):
    off = rva2off(rva)
    code = data[off:off + count * 15]
    c = 0
    for i in md.disasm(code, image_base + rva):
        print(f"  0x{i.address:x}: {i.mnemonic} {i.op_str}")
        c += 1
        if c >= count: break

# IAT helpers
def iat_rva(name):
    # leer ImportAddressTable del delay import EOSSDK -> fijo en este doc
    return None
EOS_IAT = 0x3D61CC8

print("=== 1) fn que contiene xref AddNotifyPeerAuth @ 0xde5d59 ===")
f = func_of(0xde5d59)
print(f"  fn 0x{f[0]:x}..0x{f[1]:x} ({f[1]-f[0]}B)")
# buscar 'lea' que cargue handler en módulo de* dentro de la fn
off = rva2off(f[0])
code = data[off:off + (f[1]-f[0])]
for i in md.disasm(code, image_base + f[0]):
    if i.mnemonic in ("lea", "mov") and "rip" in i.op_str:
        # estimar destino
        try:
            disp = int(i.op_str.split("0x")[-1].rstrip("]"), 16)
            tgt = i.address + i.size + disp - image_base
            if 0xdd0000 <= tgt <= 0xe00000:
                print(f"  0x{i.address:x}: {i.mnemonic} {i.op_str}  -> 0x{tgt:x}")
        except Exception:
            pass

print("\n=== 2) fn del watchdog @ 0xde4481 ===")
f = func_of(0xde4481)
print(f"  fn 0x{f[0]:x}..0x{f[1]:x} ({f[1]-f[0]}B)")
off = rva2off(f[0])
code = data[off:off + (f[1]-f[0])]
for i in md.disasm(code, image_base + f[0]):
    if any(k in i.op_str for k in ("+ 0x54", "+ 0x58", "0x88]", "comiss", "ucomiss")) or "0x29ced60" in i.op_str:
        print(f"  0x{i.address:x}: {i.mnemonic} {i.op_str}")

print("\n=== 3) fns conteniendo xrefs de interfaces Steam ===")
for rva, tag in [(0x23fb004, "SteamMatchMaking009"), (0x258e874, "SteamUser021"),
                 (0x2644b54, "SteamNetworking006"), (0xe74df4, "SteamFriends017"),
                 (0xe74e1c, "SteamUtils010"), (0xe76884, "SteamUser021#2"),
                 (0x27f45e9, "SteamUser021#3"), (0x27f3fe1, "SteamUtils010#2")]:
    f = func_of(rva)
    print(f"  {tag}: xref en fn 0x{f[0]:x}..0x{f[1]:x}" if f else f"  {tag}: sin fn")

print("\n=== 4) IAT WinHTTP callers ===")
# localizar IAT de WINHTTP en imports regulares: leerlo del descriptor
# (llvm-readobj ya lo imprimió antes; aquí escaneo .idata por el thunk)
# alternativa: buscar en .idata el nombre 'winhttp.dll' no sirve; usar readobj fuera.
# Simplemente escaneo .idata por qwords dentro de [IAT_WINHTTP] si la conozco luego.
# Por ahora: listar imports WINHTTP desde el descriptor de imports normal.
print("  (ver paso aparte con readobj)")

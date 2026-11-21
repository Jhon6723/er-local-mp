import struct, sys

data = open(r"C:\Games\Elden.Ring.REPACK-KaOs\eldenring.exe","rb").read()
pe = struct.unpack_from("<I", data, 0x3c)[0]
opt = pe+24
image_base = struct.unpack_from("<Q", data, opt+24)[0]
numsec = struct.unpack_from("<H", data, pe+6)[0]
secs=[]
for i in range(numsec):
    o=opt+240+i*40
    name=data[o:o+8].rstrip(b'\0').decode('ascii','replace')
    vs,va,rs,rp = struct.unpack_from("<IIII", data, o+8)
    secs.append({"name":name,"va":va,"vs":vs,"rp":rp,"rs":rs})
def rva2off(rva):
    for s in secs:
        if s["va"]<=rva<s["va"]+s["vs"]:
            o = s["rp"]+(rva-s["va"])
            return o if o < s["rp"]+s["rs"] else None
def off2rva(o):
    for s in secs:
        if s["rp"]<=o<s["rp"]+s["rs"]:
            return s["va"]+(o-s["rp"])
def sec_of_rva(rva):
    for s in secs:
        if s["va"]<=rva<s["va"]+s["vs"]: return s["name"]

def find_rtti(cls_mangled):
    name = cls_mangled.encode()
    i = data.find(name)
    if i < 0: return None
    td_rva = off2rva(i) - 0x10
    # COL: u32 == td_rva located at col+0xC, col[0] must be 1 (COL_SIG on x64)
    col_rva = None
    for o in range(0, len(data)-4, 4):
        if struct.unpack_from("<I", data, o)[0] == td_rva:
            cand = o - 0xC
            if cand >= 0 and struct.unpack_from("<I", data, cand)[0] == 1:
                col_rva = off2rva(cand)
                if col_rva: break
    if col_rva is None:
        return {"td": td_rva, "col": None, "vt": None, "methods": []}
    # vftable: u64 absolute VA == image_base + col_rva at vt-8
    target = struct.pack("<Q", image_base + col_rva)
    vt_rva = None
    for o in range(0, len(data)-8, 4):
        if data[o:o+8] == target:
            r = off2rva(o)
            if r and sec_of_rva(r) in (".rdata",".data"):
                vt_rva = r + 8
                break
    methods = []
    if vt_rva:
        o = rva2off(vt_rva)
        while o:
            fn_va = struct.unpack_from("<Q", data, o)[0]
            if fn_va < image_base or sec_of_rva(fn_va - image_base) != ".text": break
            methods.append(fn_va); o += 8
    return {"td": td_rva, "col": image_base+col_rva, "vt": vt_rva and image_base+vt_rva, "methods": methods}

for c in sys.argv[1:]:
    r = find_rtti(c)
    print(f"=== {c}")
    if not r: print("  not found"); continue
    print(f"  col={r['col'] and hex(r['col'])}  vftable={r['vt'] and hex(r['vt'])}")
    for j,m in enumerate(r["methods"][:24]):
        print(f"    [{j}] {m:#x}")

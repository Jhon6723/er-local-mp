# Analysis 09 — Port de offsets a Elden Ring 1.17.2

**Fecha:** 2026-11-21 · **Build:** `eldenring.exe` `sha256 f9118fea…b328` (v1.17.2, ~86.97MB)
**Método:** `analysis/probe6..9_1172.py` (AOB scan, xref rip-relative, caller tracing, IAT walk, disasm dirigido capstone). Imports volcados en `analysis/imports_1172.txt`.

## Tabla de port (viejo → nuevo)

| Pieza | Build vieja `5d0b85d2` | Build 1.17.2 `f9118fea` | Verificación |
|---|---|---|---|
| EOS delay-IAT base | `0x3d5ac58` | `0x3d61cc8` | readobj delay-imports; callsites confirman slots (ver abajo) |
| kx-derive (sodium) | `0x1e69570` | `0x1e6cb10` | AOB `SODIUM_KX_KEY_DERIVE_PATTERN` (waygate client-sodium.rs) → **único match**; prólogo idéntico (21B stolen, disp cookie en +9) |
| IAT WINHTTP base | `0x4c0cc6c` | `0x4c14c6c` | readobj `ImportAddressTableRVA`; mismo orden |
| IAT steam_api64 base | `0x4c0d09c` | `0x4c1509c` | readobj; resolver fns llaman `->0x4c1509c/0x4c150ac` (FindOrCreate/GetHSteamUser) ✓ |
| g_eosMgr (singleton) | `0x3d855c8` | `0x3d8c660` | `mov rcx,[rip]->0x3d8c660` antes de watchdog/session en fns `0xc91a90`, `0xdec990`, `0xded4b0`, `0xded8d0` |
| Handler PeerAuthStatusChanged | `0xde1e60` | `0xde5370` | `lea r9 -> 0xde5370` en `0x140de5d45` (fn AddNotify `0xde5b80..0xde61ac`); escribe `-1.0f` en `[peer+0x54]` @ `0x140de5561` |
| Watchdog EOS 120s | `0xde3150..` + comiss `0x1429c9d60` | `0xde3150..0xde4818`; `120.0f` en `0x29ced60`, uso en `0x140de4481` | mapa de peers `[r15+0x88]`, timers `+0x54/+0x58` conservados |
| RegisterPeer callsite | — | `0x140de401b` (EOS[29] → `0x3d61db0`) | scan FF 15 → IAT |
| CreateMutexW (SekiroMutex) | IAT `0x4c0c5ec` | **DOS** descriptores KERNEL32: `0x4c1439c` (módulo integridad) y `0x4c145ec` (single-instance) | fn `0x140c91c90`: `lea r8->0x2b9b6b8` = `"Global\SekiroMutex"` (UTF-16), `GetLastError==0xb7` check |
| "SekiroMutex" string | ASCII | UTF-16 `0x2b9b6b8` ("Global\SekiroMutex"; cola en `0x2b9b6c6`) | lea r8 en `0x140c91ccb` |
| Cached-interface globals | `0x3b48a10/0x3b489e0/0x3b489f8/0x3c51c10/0x3c602c0` | **no existen** — las interfaces se guardan en CAMPOS de objetos | fns resolver `0x23faff0`(MM)/`0x2644b40`(NET)/`0xe74de0`(FRD)/`0xe74e10`(UTL): `GetHSteamUser`+`FindOrCreate`+`mov [rbx],rax` |
| GetSteamID band DLNR3D/DLNW3D | `0x23f0000..0x2660000` | conservada (resolver MM `0x23faff0`, USER `0x258e850`, NET `0x2644b40` dentro; integridad en `0x250xxxx` — fuera) | hipótesis — validar en runtime |

## EOS delay-IAT slots verificados por callsite (build nueva)

| slot | API | IAT RVA | callsite |
|---|---|---|---|
| 8 | EOS_Connect_Login | `0x3d61d08` | `0x140de85d8`, `0x140dea977` (client_data=rbx=mgr; cb `lea r9->0x140de6850`/`…`) |
| 15 | Platform_Tick | `0x3d61d40` | `0x140de31b7` (watchdog fn) |
| 22 | AddNotifyX | `0x3d61d78` | `0x140de5c91` (cb `lea r9->0xde4a60`) |
| 24 | AddNotifyPeerAuthStatusChanged | `0x3d61d88` | `0x140de5d57` (cb `lea r9->0xde5370`) |
| 26 | AC_BeginSession | `0x3d61d98` | `0x140de6139` |
| 28 | AC_PollStatus | `0x3d61da8` | `0x140de3252` (frame tick `0xc91a90` → watchdog) |
| 29 | AC_RegisterPeer | `0x3d61db0` | `0x140de401b` |
| 30 | AC_UnregisterPeer | `0x3d61db8` | `0x140de8101`, `0x140de82e9` |
| 31 | AC_ReceiveMessageFromPeer | `0x3d61dc0` | `0x140de43a0` |
| otros | ByteArray_ToString=0, ProductUserId_IsValid=1, ToString=2, FromString=3, Shutdown=5, Platform_Release=7, CreateUser=9, GetLoginStatus=10, AddNotify=11/13/21/22, RemoveNotify=12/14/23/25, Get*Interface=16/17/18, Logging=19/20, EndSession=27 | — | scan FF15→IAT completo en probe7 |

**Notas:**
- `EOS_Platform_Create` (slot 6) y `EOS_Initialize` (slot 4) **no tienen callsites directos FF15** — probablemente invocados via thunks delay-load (`jmp [IAT]`); el parche de IAT cubre ambos caminos igualmente.
- `0x3c61e20` es `__security_cookie` (NO eosMgr) — `mov rax,[rip]; xor rax,rsp` en prólogos.
- `0x4849de0` es un singleton lazy de runtime (getter `0x141ed2070`) — NO eosMgr.

## Bootstrap de steam_api64 sin cliente Steam (descubierto en runtime)

Con `steam_api64.dll` **real de Valve** y sin cliente Steam, el juego se
autodestruía tras `Init`. Análisis del crash WER (`0xc0000005`) + disasm:

**Función bootstrap @ `0x140e8dda0`** (llamada al inicio de la red):
```asm
mov  ecx, 0x1301b4            ; AppId 1245620
call [IAT 0x4c150cc]          ; SteamAPI_RestartAppIfNecessary -> debe ser false
test al,al / jne exit
call [IAT 0x4c150bc]          ; SteamAPI_Init -> debe ser true
test al,al / je exit
lea  rcx, [&ctx]              ; objeto .data
call [IAT 0x4c150a4]          ; SteamInternal_ContextInit -> ctx*
mov  rcx, [rax]               ; ctx -> objeto
mov  rax, [rcx]               ; objeto -> vtable      (crash original 0xe8ddd2)
call [rax+0x30]               ; vfunc "¿todo ok?" -> debe ser true
test al,al / jne ok ; si no: SteamAPI_Shutdown + exit
```

**Hooks necesarios (11 slots steam IAT, base `0x4c1509c`)**: además de las
7 originales (FOC, CreateInterface, callbacks), hay que interceptar
`Init→true`, `RestartAppIfNecessary→false`, `GetHSteamUser→1` y
`ContextInit→ctx*` donde ctx = `{&obj}` con obj = vtable de 64 slots
todos → `return true` (vtable escasa causó crash `RIP=0` al llamar slot
no poblado). En modo directo NUNCA se llama al impl real (puede crashear
sin cliente); en `session=steam` se delega todo.

**Hallazgo**: con esto el modo directo queda **100% autónomo** — juego
llega a 5.4GB cargado sin Steam, sin OnlineFix, sin ningún servicio
externo. OnlineFix/Steam solo se requiere para `session=steam`.

## mode=steam (híbrido)

`[net] session=direct|steam` en `er_local_mp.ini`:
- `direct` (default): comportamiento actual — transporte UDP propio, lobbies sintéticos, CSteamID sintético por instancia.
- `steam`: `route_interface` pasa todo a la `steam_api64.dll` cargada (OnlineFix emu) sin wrapping; `net_sid` se lee del `GetSteamID` real (vtable[2] del iface `SteamUser021` de la emu). WinHTTP shim + EOS shim + mutex siguen activos — `fnserver.py` sigue necesario para el protocolo FN (signos, mensajes, manchas, fantasmas, invasiones); OnlineFix solo cubre lobby/P2P por SteamID64.
- **Identidad:** en steam mode el juego ve el SteamID64 real de la emu en red y save (sin split) — `external_id` FN = SteamID64 emu. Dos instancias en UN PC compartirían emu ID → para pruebas de 2 PCs reales; 2-inst-1-PC en steam mode no soportado (colisión de lobby members).

## Re-derivación rápida si la build vuelve a cambiar

1. `llvm-readobj --coff-imports` → IAT bases (WINHTTP, steam_api64, KERNEL32×2, EOS delay).
2. `probe6_1172.py` → AOB kx, watchdog rip-loads, resolver stores, handler auth, mutex xref.
3. `probe7_1172.py` → mapa completo de callsites EOS slot→fn.
4. `probe8_1172.py` → Connect_Login client_data (mgr), CreateMutexW callers, resolver callers.
5. `probe9_1172.py` → resolver fn bodies, g_eosMgr via caller chain, mutex fn.

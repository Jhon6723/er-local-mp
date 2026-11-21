# Analysis 08 — Stack Seamless Co-op + OnlineFix (build 1.17.2)

**Fecha:** 2026-11-21 · **Objetivo:** entender cómo funciona el stack que el
usuario instaló (`SeamlessCoop/ersc.dll` + `OnlineFix64.dll` +
`ersc_launcher.exe` + `winmm.dll`) sobre la nueva build
`eldenring.exe` v1.17.2 (`SHA-256 F9118FEA…B328`, 86.97 MB), compararlo con
`er-local-mp` y extraer lo reutilizable para un eventual port.

**Fuentes:** análisis PE con `llvm-readobj`/`llvm-strings` (toolchain local) +
repo MIT `micthiesen/unseamless-coop` (clonado en `analysis/unseamless-coop`,
rewrite Rust clean-room de ERSC — 40+ docs de RE con RVAs documentados sobre
una build 1.17.x de la misma familia). `ersc.dll` está protegido con
**Themida/WinLicense** (sección `ERSC` de 11.2 MB con payload virtualizado;
solo 8 imports stub) — su código fuente es cerrado; los internals se infieren
por comportamiento + el rewrite.

## 1. Cadena de carga

```
ersc_launcher.exe ── CreateProcess suspendido ──► eldenring.exe
                        │ inject "mod dll" (ersc.dll)     │
                        ▼                               ▼
                 ersc.dll (ModEngine2 ext,        winmm.dll (proxy hijack)
                  exporta modengine_ext_init)     └─ export OnlineFix
                  Themida-packed, AOB sig-scan        └─► OnlineFix64.dll
                                                      (emu Steamworks →
                                                       steam_api64.dll 265KB
                                                       → Steam real, Spacewar
                                                       appid 480 → 1245620)
```

- `dlllist.txt` = `OnlineFix64.dll` (el loader de la propia emu).
- `OnlineFix.ini`: `RealAppId=1245620` (Elden Ring), `FakeAppId=480`
  (Spacewar — el truco estándar para lobbies Steam sin licencia).
- EAC: `EasyAntiCheat/` trae el instalador real; `ersc_launcher` arranca el
  juego fuera de EAC (el repack lo permite). `start_protected_game.exe` es la
  vía "oficial" con EAC.

## 2. Modelo de conexión ERSC (la idea central)

> **"Offline" ≠ sin red.** Sin EAC lo único que falla es el login/matchmaking
> de FromSoft (popup "Starting in offline mode" — ERSC lo deja pasar). El
> gameplay co-op viaja por **Steam P2P**, no por servidores FromSoft; el
> servidor de FromSoft solo es el *matchmaker*.

ERSC entonces: **salta el matchmaking de FromSoft → encuentra el peer por
lobby Steam con contraseña → corre la sesión normal del juego sobre Steam
P2P**. No implementa transporte propio: *conduce* la pila de sesión del juego.

Piezas concretas (confirmadas por imports/strings del binario + RE de
unseamless):

- **Descubrimiento**: `SteamMatchMaking009` — lobby claveado por password
  (`cooppassword` en `ersc_settings.ini`); quien "Open World" crea el lobby,
  "Join world" entra. Sobre OnlineFix ese lobby viaja por Spacewar (Steam
  real) — funciona LAN e Internet.
- **Canal lateral del mod**: `ISteamNetworkingMessages002` (handshake,
  ConfigSync, acciones de sesión, heartbeat). ERSC real lo usa igual (importa
  `SteamNetworkingMessages002` + `SteamNetworking006`).
- **Transporte del juego**: la `SteamConnection@DLNW3D` interna usa
  **`ISteamNetworking006` (legacy P2P) direccionado solo por `CSteamID`** —
  `SendP2PPacket`/`ReadP2PPacket`/`AcceptP2PSessionWithUser`. El peer se
  siembra en `SteamConnection+0x128`; el relay de Steam hace NAT/rendezvous.
  Probado por unseamless que **funciona offline entre dos máquinas** sin
  matchmaking.
- **`join_data` (blob opaco de los pushes FromNet) es peso muerto para el
  socket**: la conexión clavea solo en SteamID64. Lo mismo que descubrimos
  nosotros (nuestro lobby coordina `{ip, udp}` y el sid sintético).

## 3. Qué añade "seamless" sobre la sesión vainilla

(índice en `unseamless-coop/docs/FEATURES.md`; RVAs para build 1.17.x —
**verificar contra nuestro binario antes de usar**):

- **Stay-connected**: suprimir `leave_session` (`0x140cae730`, único escritor
  out-of-line de `lobby_state=OnLeaveSession`, 24 callers + gemelo inline en
  `0x140cb0840`). Una flag armada al inicio neutraliza *todas* las salidas
  dirigidas por el juego (muerte de boss, transición de área, muerte, timeout)
  sin romper el teardown genuino por pérdida de peer (`0x1423f46d0`, no tocar).
- **Session limit**: `CSSessionManager.session_player_limit_override` (u32,
  escribir por frame; 2..=6).
- **Roam anywhere**: `CSStayInMultiplayAreaWarpData.disable_multiplay_restriction`
  (held write; "ir a cualquier parte del mapa").
- **Boss-area warp**: `multiplay_start_area_id = 0` lo desactiva.
- **Scaling**: sobrescribir filas `SpEffectParam` referenciadas por
  `MultiPlayCorrectionParam` (38 filas de corrección mapeadas) — una vez al
  cargar, no por frame.
- **Saves separados**: hook `CreateFileW` y reescribir extensión
  `.sl2 → .co2` (co-op nunca toca el save vainilla).
- **Quitados**: mensajes/manchas/fantasmas/signos/invasiones oficiales
  (seamless elimina el MP asíncrono por diseño; invasiones existen como
  `allow_invaders` interno del mod, no por FN).

## 4. Comparación honesta vs. `er-local-mp`

| | **er-local-mp (nuestro)** | **ERSC + OnlineFix** |
|---|---|---|
| Dependencias externas | **cero** — LAN pura, ni Steam | Steam emu o Steam real (Spacewar) |
| Matchmaking | `fnserver.py` — **protocolo FN completo** (signos, mensajes, manchas, fantasmas, invasiones) | lobby Steam por password (solo co-op) |
| Transporte | UDP P2P propio (multicanal) | **el del propio juego** (legacy Steam P2P) |
| Sesión | vainilla (tether, timers, boss-kick) salvo watchdog EOS | seamless (persistente, roam, 4→6) |
| MP asíncrono | implementado + verificado | eliminado por diseño |
| Invasiones | pipeline FN implementado | flag interno del mod |
| Madurez | 2 instancias verificadas, 1 PC | millones de usuarios, multiplataforma |
| Mantenimiento offsets | hardcodeados (nos toca re-cazar) | AOB signatures (toleran parches) |
| Naturaleza | reescritura del stack (académico, control total) | conducción del stack nativo |

**Lectura clave**: los dos modelos son compatibles en lo esencial — ambos
reemplazan el matchmaker (nosotros con FN server, ellos con lobby Steam) y
ambos terminan en un P2P keyed por SteamID. La diferencia filosófica:
**nosotros somos dueños de todo el stack** (incluido el broker → invasores,
mensajes, manchas funcionan), ERSC **se apoya en la superficie Steam que ya
exista** (mínimo RE, máximo leverage del código nativo) a cambio de depender
de un `steam_api64` funcional.

## 5. Lo reutilizable para un port a 1.17.2

1. **`unseamless-coop/docs/*` como mapa de offsets de 1.17.x**: `leave_session`,
   `CSSessionManager`, `session_player_limit_override`, DLNW3D factory
   (`0x142638b40`), `SteamConnection+0x128`, `ManagerImplSteam 0x1423f4870` —
   misma familia de versión; aceleran el re-offset si verifican en nuestro exe.
2. **`fromsoftware-rs` SDK** (`vswarte/fromsoftware-rs`): singletons tipados +
   RVAs mantenidos por comunidad — alternativa a mantener offsets a mano.
3. **Patrón AOB-signature** para tolerancia de versión (lección de diseño:
   nuestros offsets hardcodeados mueren en cada update; las AOBs sobreviven).
4. **Features "seamless" transplantables** al nuestro si quisiéramos:
   suppress-leave, limit-override, roam-anywhere, `.co2` saves — todos son
   held-writes/hooks pequeños documentados.
5. **Confirmación de diseño**: el insight `SteamID64-keyed` valida nuestra
   arquitectura (nuestro lobby ya hace lo equivalente con `{ip,udp}`).

## 6. Riesgos/notas de convivencia

- `steam_api64.dll` aquí es la **emu OnlineFix** (265 KB), no la real —
  nuestras shims H3-H6 asumen la superficie Steamworks; podrían interceptar
  la emu (misma ABI vtable) pero habría doble emulación: para pista limpia,
  nuestro modo exige desactivar `winmm.dll`/`dlllist.txt` o aislar perfiles.
- `ersc.dll` y nuestro mod **no pueden coexistir** (ambos quieren la capa de
  sesión). Modos de lanzamiento separados.
- Los RVAs citados son de la build de unseamless (1.17.x retail); nuestro
  repack puede diferir en padding/sections → re-verificar con capstone antes
  de usar cualquier dirección.
- Higiene clean-room: `ersc.dll` es propietario — estudio conductual solamente
  (nada de pseudocódigo copiado). `unseamless-coop` es MIT → sí referenciable.

# 04 — Estado final y roadmap

**Estado:** implementada (núcleo, build vieja) · en progreso (port a 1.17.2)

## Resumen ejecutivo

**Objetivo alcanzado (build vieja `5d0b85d2`):** multijugador **local y
offline** entre dos instancias reales de Elden Ring en el mismo PC, **sin
servidores de FromSoftware, sin Steam y sin anticheat**. El tráfico FN
cifrado del juego se sirve con `matchbox/fnserver.py`, la coordinación de
lobbies y la sesión co-op se resuelven sobre UDP local.

**Estado actual (build 1.17.2 `f9118fea`):** la instalación vieja se perdió
al actualizar; el port de offsets a 1.17.2 está hecho y el DLL compila
limpio (tabla completa en `analysis/09-port-1172-offsets.md`). Además se
añadió el modo híbrido **`[net] session=steam`**: las interfaces Steamworks
pasan a la `steam_api64.dll` de OnlineFix sin wrapping (SteamID64 real como
identidad), mientras `fnserver.py` conserva el protocolo FN — pendiente de
verificación en runtime. Snapshot funcional de la build vieja: commit
inicial del repo + `backups/er_local_mp-5d0b85d2.dll`.

## Verificado en juego (sesiones reales)

| Sistema | Estado | Detalle |
|---|---|---|
| Login FN cifrado (handshake kx/secretbox) | ✅ | menú "CONECTADO" en ambas instancias |
| Heartbeat `07 64` + sesiones largas | ✅ | sin timeout en sesiones >120 s |
| Mensajes (bloodmessages) | ✅ | create/list/evaluate/remove/reentry + push al autor + persistencia `bloodmessages.json` |
| Manchas de sangre (bloodstains) | ✅ | create/list + replay de muerte `GetDeadingGhost` reproducido en el otro jugador |
| Fantasmas blancos (ghostdata) | ✅ | create/list, renderizados en el otro mundo |
| Signos dorados + effigy/puddle | ✅ | create/list/update/remove/summon/reject |
| Co-op real (summon → lobby → P2P) | ✅ | invocado entró al mundo del host y peleó Margit >2 min sin desconexión |
| Watchdog EOS peer-auth (120 s) | ✅ desactivado | callback `PeerAuthStatusChanged(status=2)` tras `RegisterPeer`, sin parchear `.text` |
| Dos instancias en 1 PC | ✅ | `eldenring_p2.exe` + mutex renombrado por proceso + UDP `27016/27017` dinámicos |
| Invasiones (BreakIn) | 🟡 implementado | pipeline completo en `fnserver.py`; pendiente de verificación en juego |

## Arquitectura final

```
 eldenring.exe            eldenring_p2.exe        <- 2 procesos en el mismo PC
  └ er_local_mp.dll       └ er_local_mp.dll       (WinHTTP/EOS/Steam shims,
   │ udp :27016            │ udp :27017             transporte P2P multicanal)
   │                       │
   ├── ws ──── fnserver.py :10901 ──── ws ─────────┤   (protocolo FN cifrado)
   │             │
   └── udp ───── ctl/lobby :37017 ──── udp ────────┘   (registro de peers,
   │             │                                    lobbies, pools)
   └── udp :37015 matchbox (rendezvous/relay opcional)

   P2P directo: udp 27016 <-> 27017  (canales 0x69/0x6a/0x6b/...)
```

## Componentes

- **`mod/src/`** → `build\er_local_mp.dll` (via `mod\build.bat`, LLVM-MinGW
  estático). Deploy: copiar a `mods\er_local_mp.dll` junto al juego.
  - `hooks/winhttp_shim.cpp` — redirige FN `*.fromsoftware-game.net` →
    `ws://127.0.0.1:10901` + rename de mutex por proceso.
  - `hooks/eos_shim.cpp` — EOS offline completo; captura
    `AddNotifyPeerAuthStatusChanged` y dispara `status=2` en
    `EOS_Platform_Tick` por cada peer registrado.
  - `hooks/hooks.cpp` — SteamUser/Friends/Utils/MatchMaking/Networking;
    `CSteamID` sintético por instancia; lobbies vía UDP `:37017`.
  - `transport/transport.cpp` — UDP multicanal, bind dinámico `:27016+`,
    cabecera `{magic, channel, sender_sid}`.
  - `matchbox/client.cpp` — registro de peer + ticket `ERLOCALMP_TICKET`.
- **`matchbox/fnserver.py`** — servidor FN + coordinador: sesiones, heartbeats,
  bloodmessages/bloodstains/ghostdata, signos, lobbies, `BREAKIN_POOL`,
  canal de control UDP.
- **`matchbox/matchbox/`** — rendezvous/relay original (tests en
  `test_matchbox.py`, 3/3 OK).

## Identidad y sesión (clave)

- `ERLOCALMP_TICKET` (`acct_id u32 + udp u16`) → server deriva
  `external_id = hex(0x0110000100000000 | acct_id)` → CSteamID individual válido.
- `fake_GetSteamID` filtra por RVA del caller: `0x23f0000..0x2660000`
  (SessionManagerSteam) → SID sintético único; resto (SaveData) → SID real de
  RUNE (`76561197960271872`). Saves intactos.
- `net_sid` distinto por proceso (`acct = pid<<16 | udp`).

## Watchdog EOS de 120 s (lección clave)

`EOS_AntiCheatClient_RegisterPeer` inicia un timer `[peer+0x54]` comparado
contra `120.0f` (`0x1429c9d60`); al expirar, expulsa al peer. La vía legítima:
`EOS_AntiCheatClient_AddNotifyPeerAuthStatusChanged` con `AuthStatus=2`
escribe `-1.0f` y apaga el timer (`0x140de2051`). El shim lo sintetiza en
`EOS_Platform_Tick` sin tocar `.text` (compatible con checksums de Arxan).
Evidencia: co-op pasó de ~120 s a sesión estable hasta muerte natural.

## Limitaciones conocidas

- **Offsets fijos a la build** (`eldenring.exe` 2.6.0.0, SHA-256 en AGENTS.md);
  otra versión requiere re-análisis.
- `BLOODSTAINS`/`GHOSTDATA`/`SIGNS`/`BREAKIN_POOL` viven en memoria del
  servidor (se pierden al reiniciar `fnserver.py`); solo bloodmessages persiste.
- `is_invadeable` es estado nativo del cliente: requiere Lengua de provocador
  o cooperador presente; `STRICT_MATCHING=False` relaja nivel/región pero no
  ese flag.
- `char_level` en `GetBreakInTargetList` se lee con offset aproximado en
  `MatchingParameters` (suficiente para log/matching local; refinar si se
  activa `STRICT_MATCHING`).
- 3+ jugadores: el lobby admite `max=4` pero nunca se probó con una tercera
  instancia (haría falta otro exe con mutex renombrado).
- QuickMatch/arena, Visit (hunter), ReentryBloodMessage edge-cases, y
  `SendRegulationHash` real: sin implementar / sin probar.
- Comportamientos nativos que el mod no controla: signos dorados ocultos con
  jefe de zona muerto, posición exacta de signos/manchas, filtros de
  contraseña.

## Próximos pasos (roadmap)

1. **Verificar invasión end-to-end** — host con Lengua (o cooperador) +
   invasor con dedo → confirmar `BreakInTarget → AllowBreakIn → lobby join →
   spawn rojo` en `fnserver.log` + ambos `er_local_mp*.log`.
2. **LAN real entre 2 PCs** — `er_local_mp.ini` ya soporta `matchbox_ip`/
   `fn.host`; falta probarlo y documentar la config (abrir firewall UDP/WS).
3. **Persistencia** de manchas/fantasmas/signos (JSON como bloodmessages).
4. **QuickMatch/arena** (variantes 66-72, 78 + pushes 0xB/0xC) y **Visit**
   (32-34 + `pool_visitor`/`can_be_hunter`).
5. **3+ jugadores** — validar con tercer exe y lobby multi-miembro.
6. **Empaquetado** — launcher único (fnserver + matchbox + ambos exes),
   `er_local_mp.ini` de ejemplo y guía de usuario final.
7. **Hardening** — `STRICT_MATCHING` real con tabla de refuerzo de armas de
   waygate; timeouts de signos/manchas; rate-limit de pushes.
8. **Revalidación** de offsets si cambia la build del binario.

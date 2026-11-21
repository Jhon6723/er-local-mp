# 04 — Estado final y roadmap

**Estado:** implementada (núcleo, build vieja) · **verificado en runtime (1.17.2, co-op entre 2 PCs por Tailscale)**

## Resumen ejecutivo

**Objetivo alcanzado (build vieja `5d0b85d2`):** multijugador **local y
offline** entre dos instancias reales de Elden Ring en el mismo PC, **sin
servidores de FromSoftware, sin Steam y sin anticheat**. El tráfico FN
cifrado del juego se sirve con `matchbox/fnserver.py`, la coordinación de
lobbies y la sesión co-op se resuelven sobre UDP local.

**Verificado (build 1.17.2 `f9118fea`, 2026-11-21):** **co-op real entre
dos PCs por Internet** — ambos clientes en el mismo tailnet de Tailscale,
`matchbox_ip` apuntando a la IP `100.x` del host. Flujo completo
verificado: login FN → `CreateSign`/`SummonSign` → lobby `lcreate`/`ljoin`
→ **P2P UDP directo PC↔PC** → fantasma dorado en el mundo del host
(`Anfitrión de Dedos`). Los bloodmessages también se verificaron cruzados
(escrito en un PC, visible en el otro tras el siguiente poll de
`GetBloodMessageList`).

**Modo `session=direct` es 100 % autónomo en 1.17.2:** el juego arranca,
restaura el perfil de guardado real, aparece en español (`latam`) y hace
login FN **sin Steam, sin OnlineFix y sin `steam_api64` real**. El modo
híbrido `session=steam` sigue existiendo como opción pero ya no es
necesario para el flujo principal. Snapshot funcional de la build vieja:
commit inicial del repo + `backups/er_local_mp-5d0b85d2.dll`.

## Verificado en juego (sesiones reales)

| Sistema | Estado | Detalle |
|---|---|---|
| Login FN cifrado (handshake kx/secretbox) | ✅ | menú "CONECTADO"; en 1.17.2 con `session=direct` sin Steam |
| Heartbeat `07 64` + sesiones largas | ✅ | sin timeout en sesiones >120 s |
| Mensajes (bloodmessages) | ✅ | create/list/evaluate/remove/reentry + push al autor + persistencia `bloodmessages.json`; **verificado entre 2 PCs** (visible en el otro tras un ciclo de `GetBloodMessageList`) |
| Manchas de sangre (bloodstains) | ✅ | create/list + replay de muerte `GetDeadingGhost` reproducido en el otro jugador |
| Fantasmas blancos (ghostdata) | ✅ | create/list, renderizados en el otro mundo |
| Signos dorados + effigy/puddle | ✅ | create/list/update/remove/summon/reject; **verificado entre 2 PCs** |
| Co-op real (summon → lobby → P2P) | ✅ | **entre 2 PCs por Tailscale (1.17.2)**: fantasma dorado dentro del mundo del host; antes en build vieja, Margit >2 min sin desconexión |
| Watchdog EOS peer-auth (120 s) | ✅ desactivado | callback `PeerAuthStatusChanged(status=2)` tras `RegisterPeer`, sin parchear `.text` |
| Bootstrap Steam sin cliente | ✅ | `session=direct` 1.17.2: `Init`→true, `ContextInit` ejecuta el inicializador del juego, interfaces falsas autocontenidas (Apps/UserStats/Client/User/Friends/Utils/MatchMaking) |
| Perfil de guardado real | ✅ | `GetSteamID` detecta el dir de `%APPDATA%\EldenRing\<sid>` con `ER0000.sl2` más reciente; saves intactos |
| Idioma sin Steam | ✅ | `SteamApps::GetCurrentGameLanguage` → `[player] language` del ini (`latam` por defecto) |
| Dos instancias en 1 PC | ✅ | `eldenring_p2.exe` + mutex renombrado por proceso + UDP `27016/27017` dinámicos |
| Duelo PvP (Duelist sign) | ✅ | **entre 2 PCs por Tailscale (1.17.2)**: `CreateSign → SummonSign → push → lobby → fantasma rojo` en el mundo del host |
| Invasiones (BreakIn) | 🟡 implementado | `GetBreakInTargetList`/`BREAKIN_POOL` operan (host con cooperador ENTRA al pool, `jugadores=2`); pendiente: la Lengua Burlona no se activa en el cliente — posible estado de sesión EOS residual tras co-op (investigar teardown de lobby) |

## Arquitectura final

```
 PC-A (host de sesión)        PC-B / eldenring_p2.exe   <- misma máquina o
  └ er_local_mp.dll            └ er_local_mp.dll           PCs distintas
   │ udp :27016                 │ udp :27016/27017         (WinHTTP/EOS/Steam
   │                            │                          shims + P2P multicanal)
   │                            │
   ├─ ws ──── fnserver.py :10901 ── ws ────────────────────┤   (protocolo FN
   │           │                                            cifrado, LAN o VPS)
   └─ udp ──── ctl/lobby :37017 ──── udp ──────────────────┘   (peers, lobbies,
   │           │                                                pools)
   └─ udp :37015 matchbox (rendezvous/relay opcional)

   P2P directo: udp 27016 <-> udp del peer  (canales 0x69/0x6a/0x6b/...)
   Entre PCs: atraviesa Tailscale (WireGuard NAT-traversal) o Internet
   abierto si hay conectividad UDP directa.
```

**Topologías verificadas:** 2 procesos en 1 PC (build vieja) y **2 PCs por
Tailscale (1.17.2)**. Regla clave: `matchbox_ip` del `.ini` de **todos** los
clientes debe apuntar a la IP donde corre `fnserver.py` (`100.x` de Tailscale
hoy, IP pública del VPS mañana) — el servidor registra cada peer por la IP de
origen de su paquete UDP de control, y esa es la dirección que reciben los
demás para el P2P.

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

1. **Servidor en VPS** — mover `fnserver.py` + `matchbox` de la PC del host a
   una VM permanente (spec en `docs/05-despliegue-vps.md`). Un solo dato
   crítico: los clientes se registran por IP de origen UDP, así que con VPS
   pública el P2P entre hogares necesita NAT-traversal — la ruta segura es
   correr la VPS dentro del mismo tailnet.
2. **Verificar invasión end-to-end** — host con Lengua (o cooperador) +
   invasor con dedo → confirmar `BreakInTarget → AllowBreakIn → lobby join →
   spawn rojo` en `fnserver.log` + ambos `er_local_mp*.log`.
3. **Persistencia** de manchas/fantasmas/signos (JSON como bloodmessages).
4. **QuickMatch/arena** (variantes 66-72, 78 + pushes 0xB/0xC) y **Visit**
   (32-34 + `pool_visitor`/`can_be_hunter`).
5. **3+ jugadores** — validar con tercer exe y lobby multi-miembro.
6. **Empaquetado** — launcher único (fnserver + matchbox + ambos exes),
   `er_local_mp.ini` de ejemplo y guía de usuario final.
7. **Hardening** — `STRICT_MATCHING` real con tabla de refuerzo de armas de
   waygate; timeouts de signos/manchas; rate-limit de pushes.
8. **Revalidación** de offsets si cambia la build del binario.

### Verificado en esta iteración (1.17.2, 2026-11-21)

- ~~LAN real entre 2 PCs~~ — **hecho por Tailscale**: `matchbox_ip` apuntando
  a la IP `100.x` del host en ambos `.ini`; lobby `lcreate`/`ljoin` registra
  los endpoints `100.x:27016` reales y el P2P UDP cruza el túnel WireGuard.
- Bootstrap Steam completo sin cliente (`session=direct`): ver tabla.
- Restauración de perfil de guardado y `language = latam` sin OnlineFix.
- Paquete de amigo: `dist/er-local-mp-p2p-v1.17.2.zip` + `INSTALAR.txt`.

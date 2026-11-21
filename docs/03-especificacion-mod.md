# 03 — Especificación del mod (er_local_mp.dll)

**Estado:** aprobada

DLL inyectada vía EldenModLoader (`dinput8.dll` → `mods/`). Mismo pipeline que
`souls_vision.dll`: se copia a `mods/` + línea en `mod_loader_config.ini`.
Desarrollo y artefactos fuera del directorio del juego.

## Secuencia de arranque

1. `DllMain` → hilo propio
2. `config`: lee `er_local_mp.ini` junto al ejecutable: `matchbox_ip`, `matchbox_port`,
   `fn.port`, `player_name`, `mode`, `listen_port`
3. `transport`: abre socket UDP `listen_port` (con fallback incremental `+1..+31`
   si el puerto está en uso por otra instancia local); inicia hilo de recepción multicanal
4. `matchbox client`: REGISTER con el puerto UDP real asignado → obtiene `peer_id` único
5. `hooks`: instala shims sobre WinHTTP+kx (`fnserver.py`), EOS delay-IAT, y las
   interfaces de sesión/P2P de `steam_api64.dll` (`SteamUser021`, `SteamFriends017`,
   `SteamUtils010`, `SteamMatchMaking009`, `SteamNetworking006`)

## Hooks — contrato con el binario (`analysis/05` y `analysis/06`)

| # | Objetivo | Acción | Estado REA |
|---|---|---|---|
| H1 | `WinHttpConnect` / `WinHttpOpenRequest` + `kx` (`0x1e69570`) | redirigir tráfico FromNet a `ws://127.0.0.1:[fn]port` con par libsodium conocido | verificado en juego |
| H2 | `EOS_*` (32 slots delay-IAT `0x3d5ac58`) | resolver login offline y stubs de `EOS_AntiCheatClient_*`; capturar `AddNotifyPeerAuthStatusChanged` y disparar `AuthStatus=2` en `EOS_Platform_Tick` para apagar el watchdog de 120 s (`0x1429c9d60`) sin parchear `.text` | verificado en juego (co-op >120 s) |
| H3 | `SteamUser021` (`GetSteamID`, `EncryptedAppTicket`, `AuthSession`) | `CSteamID` sintético `0x0110000100002000+peer_id` para `DLNR3D/DLNW3D` preservando el ID real para `ER0000.sl2`; tickets + callback `0x8f` (20B) | verificado en binario (`0x1423f4881`, `0x1423f8380`) |
| H4 | `SteamFriends017::GetFriendPersonaName` | devolver nombre no vacío para miembros sintéticos del lobby | verificado (`0x1423fe6f4`) |
| H5 | `SteamMatchMaking009` + `SteamUtils010` | coordinar `CreateLobby`/`JoinLobby`/`LeaveLobby`/miembros contra `fnserver.py` UDP `:37017`; servir `0x201` (16B), `0x1f8` (24B) y disparar `0x1fa` (`LobbyChatUpdate_t`, 32B) | verificado (`0x1423fea00..0x1423ff215`) |
| H6 | `SteamNetworking006` (`SendP2PPacket`, `ReadP2PPacket`, `AcceptP2PSessionWithUser`, `CloseP2PChannelWithUser`) | transporte UDP directo multicanal (`channel` + `sender_steam_id` en cabecera de 12B) + callback `0x4b2` (`P2PSessionRequest_t`, 8B) | verificado (`0x142640310..0x142641127`) |

Regla (AGENTS.md): todo offset/vtable/AOB solo en `mod/hooks/` + `analysis/`.

## Identidad de peers

El juego habla de `CSteamID` (64 bit). El emu asigna IDs derivados de
`AccountId` del ini — **colisionan si dos jugadores usan el mismo ini**.
El mod mantiene `peer_id (u32 matchbox) ↔ steamID (u64 juego)`; el módulo
`session` fabrica steamIDs sintéticos consistentes para los phantoms.

## Transporte

- `transport` expone: `send(peer_id, bytes)` / `recv() -> (peer_id, bytes)` /
  `pump()`.
- `mode=direct`: envía a `host_ip:host_port` de JOIN_ACK.
- `mode=relay`: envuelve en `RELAY{session_id}` hacia matchbox.
- Hilo rx alimenta la cola que H2/H3 consumen; `pump()` en el game loop (hook
  del tick de red si Ghidra muestra uno; si no, polling desde hilo).

## Requisitos de despliegue (Windows)

- **Smart App Control (SAC)**: solo en Windows 11. Si está en `On`, bloquea
  cualquier DLL sin firma/reputación (`LoadLibrary` falla, error 4551) —
  incluido `dinput8.dll` del loader, no solo el mod. Requisito: SAC en
  `Off`/`Evaluation`, o binario firmado. Verificar con
  `Get-MpComputerStatus.SmartAppControlState`.
- **SmartScreen**: aviso "Windows protegió su PC" al descargar — salvable con
  "Ejecutar de todas formas". Distribución seria requeriría firma OV/EV.
- **Defender/AV**: mods con injection/detours pueden ser marcados como
  HackTool aun firmados; documentar exclusión si aparece.
- Estado SAC en la máquina de dev: **Off** (verificado 2026-11-19, era el
  bloqueo de los load fail 4551).

## Criterios de aceptación (de AGENTS.md)

1. El juego carga `er_local_mp.dll` sin crashear y llega al menú.
2. `er_local_mp.log` muestra REGISTER_ACK con `peer_id`.
3. Instancia A crea marca (Furled Finger) → instancia B la lista.
4. B invoca → JOIN_ACK con endpoint de A → paquetes UDP fluyen en ambos sentidos.
5. Phantom de B visible en el mundo de A (aceptación final, REA-verificada).

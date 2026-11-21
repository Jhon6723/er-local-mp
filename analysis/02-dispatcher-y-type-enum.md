# Analysis 02 — Dispatcher FromNet y enum de requests

**Fecha:** 2026-11-19 · **Build:** `eldenring.exe` `5d0b85d2…`
**Método:** RTTI walk (`rtti_walk.py`) + desensamblado dirigido (capstone) de métodos de vtable.

## Hallazgo principal: choke point de requests

Cada método `FN*Impl` empaqueta un request en un frame de pila de `0x418` bytes
con su **type_id** en `[rsp+0x400]` y llama a un dispatcher común:

- **`0x141df3a80`** — dispatcher principal de requests (llamado por todos los
  `FN*Impl`; segundo call `0x141deff60` = future/result setter).
- Dispatchers secundarios observados: `0x141df7b10`, `0x141df7b90`,
  `0x141df7e20`, `0x141df7ea0`, `0x141df8350`, `0x141dfac60`, `0x141dfad80`,
  `0x141dfaea0` — probablemente consultas de lista/estado (GetSignList es
  streaming) y accesores del servant.

**Implicación para el mod**: un hook en `0x141df3a80` + `0x141deff60` permite
(a) saber qué op envía el juego (leer type_id) y (b) fabricar la respuesta
localmente (escribir el ResponseParams en el future). Es la frontera exacta
mod↔juego para todo FromNet.

## Enum de request types (del FNTypeList del binario, orden verificado)

request N → response N. Parcial, relevante al mod:

| id | op | | id | op |
|---|---|---|---|---|
| 0 | CreateSession | | 14 | RejectSign |
| 1 | DeleteSession | | 15-25 | BloodMessage/Bloodstain/Ghost ops |
| 2 | RestoreSession | | 26 | UpdateLoginPlayerCharacter |
| 3 | DebugCommand | | 27 | UpdatePlayerStatus |
| 4 | ServerPing | | 28 | BreakInTarget |
| 5 | CheckAlive | | 29 | GetBreakInTargetList |
| 6 | GetAnnounceMessageList | | 30 | RejectBreakInTarget |
| 7 | **CreateSign** | | 31 | AllowBreakInTarget |
| 8 | CreateMatchAreaSign | | 32 | Visit |
| 9 | **UpdateSign** | | 33 | GetVisitorList |
| 10 | **GetSignList** | | 34 | RejectVisit |
| 11 | GetMatchAreaSignList | | 35 | NotifyAreaEvent |
| 12 | **RemoveSign** | | 36 | **JoinMultiplay** |
| 13 | **SummonSign** | | 37 | LeaveMultiplay |

| 38 | GetMatchDensity | | 39 | GetPlayZoneIDList |
| 75 | SendArxanInfo | | 79 | SendRegulationHash |

## Vtables etiquetadas (método → op)

`FNSignImpl` `0x1430822c8`: `[3]` UpdateSign(9), `[4]` RemoveSign(12),
`[8]` RejectSign+RemoveSign, resto = accesores de lista/estado por los
dispatchers secundarios (CreateSign/GetSignList/SummonSign pendiente de
etiqueta fina — probablemente en `[1]/[2]/[9]/[10]/[11]`).

`FNMultiplayImpl` `0x143080bb0`: `[1]` JoinMultiplay(36),
`[2]` LeaveMultiplay(37), `[3]/[4]` GetPlayZoneIDList(39).

`FNBreakInImpl` `0x143080968`: mezcla de BreakInTarget(28),
GetBreakInTargetList(29), Reject(30), Allow(31) repartidos en `[0]-[7]`.

## Pendiente para Ghidra/x64dbg

- Mapeo fino de métodos `[1],[2],[5]-[7],[9]-[11]` de FNSignImpl (qué slot es
  CreateSign/GetSignList/SummonSign).
- Estructura del frame de request `0x418` (dónde van los params por tipo) para
  poder *fabricar* requests/respuestas sintéticas — eso sale de descompilar
  `0x141df3a80` y `0x141deff60`.
- El camino servant→WSS (dónde `FNClientServant` envía el paquete) — objetivo
  del stub de login.

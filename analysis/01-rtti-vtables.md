# Analysis 01 — Mapa de vtables RTTI

**Fecha:** 2026-11-19 · **Build:** `eldenring.exe` SHA-256 `5d0b85d2…`
**Método:** `rtti_walk.py` — TypeDescriptor → CompleteObjectLocator → vftable (VAs absolutas, image base `0x140000000`).

## Capa FromNet (frontera con el servidor de From)

| Clase | vftable | métodos | rol |
|---|---|---|---|
| `FNSignImpl` | `0x1430822c8` | 12 @ `0x141dfb5c0-0x141dfb7b0` | sign ops → servidor (CreateSign/GetSignList/SummonSign/RemoveSign) |
| `FNMultiplayImpl` | `0x143080bb0` | 5 @ `0x141df5fb0-0x141df60d0` | join/leave multiplay |
| `FNBreakInImpl` | `0x143080968` | 8 @ `0x141df5230-0x141df5510` | invasión (BreakInTarget) |
| `FNClientImpl` | `0x14307d8c8` | 24 @ `0x141de5210-0x141de57d0` | handshake/login WSS al servidor |

**Candidato de stub principal**: `FN*Impl` — sustituir la vtable de la
instancia (o detour por método) para devolver "éxito" local en vez de ir a
`wss://gr-prod-steam…`.

## Capa sesión DLNR3D (P2P lógica)

| Clase | vftable | métodos |
|---|---|---|
| `SessionManagerSteam` | `0x1431f9140` | 24 @ `0x1423f5b90-0x1423f6f90` |
| `SessionSteam` | `0x1431fa248` | 24 @ `0x1423faac0-0x1423ff2f0` |
| `SessionMemberSteam` | `0x1431fa978` | 21 @ `0x1424006d0-0x142403080` |

## Capa socket DLNW3D (transporte — candidato a reemplazar por UDP)

| Clase | vftable | métodos |
|---|---|---|
| `MTDispatchedSteamSocketManager` | `0x143276b50` | 14 @ `0x142637bb0-0x1426396e0` |
| `MTDispatchedSteamSocket` | `0x143276e38` | 8 @ `0x142638c80-0x14263c550` |
| `NWMTSteamSocketManager<*>` | (2 instancias de template, pendiente) | — |

## Capa juego CS (jobs del flujo de marcas — puntos de hook por UX)

| Clase | vftable | métodos |
|---|---|---|
| `CSSosSignCreateSignJob` | `0x142b3a9c8` | 6 @ `0x140744e90…` |
| `CSSosSignDownloadSignListJob` | `0x142b3aa70` | 6 |
| `CSSosSignSummonJob` | `0x142b3aaa8` | 6 |
| `SessionCreateJob` | `0x142b3bc48` | 3 |
| `JoinSessionJob` | `0x142b3a630` | 4 |
| `JoinSessionWaitJob` | `0x142b3bc88` | 3 |
| `SessionLeaveJob` | `0x142b3bc68` | 3 |
| `CSSessionManagerImp` (singleton) | `0x142b9a0c0` | 2 (la lógica vive en no-virtuales) |
| `CSNetworkUserManagerImp` | `0x142b99220` | 2 |
| `CSPlatformNetworkManImp` | `0x142b9dc08` | 1 |
| `SosSignMan` | `0x142a8a500` | 1 |
| `PlayerNetworkSession` | `0x142b9eb30` | 10 @ `0x140cc5090-0x140cc5560` |

## Familia completa de jobs (reservada para invasiones/visitas v2)

`BreakInRequestJob`, `BreakInJoinSessionJob`, `CSBreakInTargetListJob`,
`CSBreakInAllowJob`, `CSBreakInRejectJob`, `CSBreakInOneRequestJob`,
`CSVisitorRequestVisitJob`, `CSVisitorWaitingVisitJob`,
`CSVisitorListDownloadJob`, `CSVisitorRejectVisitJob`,
`CSMultiplayNotifyJoinJob`, `CSMultiplayNotifyLeaveJob`,
`CSMultiplayGetMatchDensityJob`, `CSMultiplayPrivilegeCheckStep` —
todos localizables con `rtti_walk.py "<mangled>"`.

## Siguiente paso

Los métodos están sin nombre semántico (índice de vtable). Asignar rol a cada
`[i]` requiere: (a) descompilación Ghidra (análisis completo corriendo), o
(b) x64dbg en vivo con breakpoints en item-use. Los `[0]`/`[1]` compartidos
entre jobs (`0x140744e90`, `0x1407aa2e0`, `0x140a225d0`) son virtuals del
`FD4StepBase`/job base común.

# Analysis 04 — Path de login/conexión WSS

**Fecha:** 2026-11-19 · **Build:** `eldenring.exe` `5d0b85d2…`
**Método:** xref scan IAT→WinHTTP + entry-point recovery por prólogos MSVC.

## Evidencia en vivo (test en juego 2026-11-19)

- `er_local_mp.dll` carga vía EldenModLoader sin crash, coexiste con
  `souls_vision.dll`. REGISTER a matchbox OK (`peer=1`).
- Detour H1 (`SteamInternal_CreateInterface`→FakeNet) instalado en proceso
  real: `0x7ff8cc3a1510`.
- **El login nunca llega a Steam**: el flujo muere en el connect WSS antes
  de pedir `SteamNetworking006` → el primer stub necesario es el connect,
  no el P2P.

## Mapa del path de conexión (call sites a WinHTTP por IAT)

| función | rango | rol |
|---|---|---|
| `~0x141e61a02` | 0x141e619ad–0x141e61ba6 | **connect WSS**: WinHttpOpen, WinHttpConnect, OpenRequest, SendRequest, SetStatusCallback(`FUN_141e60550`) |
| `~0x141e608e8` | 0x141e608db–0x141e6092d | **accept/upgrade**: ReceiveResponse + WebSocketCompleteUpgrade |
| `~0x141e604b6` | 0x141e604cb | loop `WebSocketReceive` |
| `~0x141e61ce8` | 0x141e61d60/0x141e61da9 | `WebSocketSend` |
| `~0x141e615e0` | 0x141e615f6+ | close/cleanup |
| `~0x141e64eea` | 0x141e64ef4 | CrackUrl (parsea `wss://gr-prod-steam.fromsoftware-game.net:10901`, VA string `0x142b3bf7e`) |
| `~0x141e60a90` | 0x141e60ad8+ | cierre de handles + callback ctx |

El URL `wss://...` NO tiene xrefs RIP directos — se carga indirectamente
(probablemente copia a buffer o struct de config). `FUN_141e60550` = status
callback → notifica progreso/resultado del connect al estado del servant.

## Vtables del path (de rtti_walk, ya en el dump)

| clase | vtable | notas |
|---|---|---|
| `FromNet::FNClientServant` | `0x143088e88` | solo 3 slots dump — vtable primaria pequeña o multi-herencia |
| `FromNet::FNClientServantModule` | `0x143086d48` | dtor [2]=0x141e16650 |
| `FromNet::FNClientProxy` | `0x143088c70` | dtor [2]=0x141e22280 |
| `FromNet::FNClientImpl` | `0x14307d8c8` | 26 slots — wrappers de ops |

Los dtors [0]/[1] compartidos (`0x141e7ba70/0x141e7ba80`) = base común.

## Cadena real decodificada (dump dirigido)

- `lea 0x141e61b57 -> FUN_141e60550` confirma que el callback se pasa
  a `WinHttpSetStatusCallback` dentro de la fn de connect.
- **`FUN_141e60550` ES la máquina de estados** (decomp en `0x141e605bd`):
  switch sobre `dwInternetStatus`:
  - `0x10` RESOLVING_NAME → `FUN_141e607d0`
  - `0x200` REQUEST_SENT → `FUN_141e61160`
  - `0x200000` DATA_AVAILABLE → check `0x141e63910` → `FUN_141e61160`
  - `0x400000` READ_COMPLETE → `FUN_141e60850` (path upgrade/lectura)
  Cada paso invoca el siguiente task via `(**vtable)()` — la propagación
  del estado "conectado" es una cadena de tasks, no un return.
- `FUN_141e55110` = task de envío: serializa op → `FUN_141e61e20` (WSSend);
  retorna 0/1/4.
- Bootstrap del servant: fn ~`0x141e10489` (entry estimado, decomp
  con bad-data al inicio — verificar entry real) llama ctor
  `0x141e23950` y métodos `0x141e23870/890/8f0/a30/a70`.
- `0x141dfe6a0` (región dispatch) llama `0x141e23870` — enlace
  request-layer → servant.

## Opciones de bypass del login (decisión pendiente)

A. **Shim completo de WinHTTP** (recomendada): detour de las ~10
   importaciones WinHTTP que usa el juego. `SetStatusCallback` captura
   cb+ctx; `SendRequest` scriptea la secuencia de estados;
   `WebSocketSend` captura los paquetes FN salientes (¡es el canal de
   señalización real!) y `WebSocketReceive` entrega respuestas
   fabricadas. Equivale a un "servidor FromSoft local" emulado a nivel
   API — self-contained, sin TLS ni cert store.
B. Stub de estado a nivel task: más quirúrgico pero requiere mapear la
   cadena de tasks y su objeto de estado — frágil.
C. Servidor WSS loopback real + redirect de CrackUrl/Connect: el TLS
   de schannel exige cert trust — invasivo fuera del juego.

## Evidencia adicional: las 3 compuertas reales del login (`CreateLoginJob`)

En las pruebas en vivo 2 y 3 (con IAT real de `winhttp.dll` en `0x144c0cc6c`,
probes de `ws2_32.dll`, e IAT real de `steam_api64.dll` en `0x144c0d09c`),
pulsar «INICIAR SESIÓN» **no invocó WinHTTP ni sockets**. El análisis dirigido
de `ExtractAuth.java` y `ExtractAuth2.java` reveló que antes de abrir el WSS de
FromNet, el juego ejecuta `CreateLoginJob` (`0x140de3d41..0x140de3ea2`):

1. **Compuerta 0 — Singleton `g_eosMgr` (`0x143d855c8`) inicializado antes del delay de 5s**:
   - `0x140dec493` construye `g_eosMgr` (`0x118` bytes) en el arranque (`t = 0s`), antes
     de que `EldenModLoader` (`load_delay = 5000`) inyecte `er_local_mp.dll`.
   - Sin EAC en el arranque, `g_eosMgr+0x00` (`hPlatform`) y/o `g_eosMgr+0x10`
     (`hAntiCheatClient`) quedan en `0` y `g_eosMgr+0x78` / `+0x7c` marcan fallo.
   - Al pulsar «INICIAR SESIÓN», `0x14082177b` (`0x140ddfb30`), `0x140839ab6`
     (`0x140ddfb40`) y `CreateLoginJob` (`0x140ddec30` en `0x140dded22..0x140dded46`)
     verifican `*g_eosMgr != 0` y `*(g_eosMgr + 0x10) != 0`; si son `0`, abortan antes
     siquiera de encolar el paso 1 del job. Rehabilitar `g_eosMgr` en memoria desbloquea
     `CreateLoginJob`.
2. **Compuerta 1 — Steam Encrypted App Ticket (`0x140de3db0` → `0x140de7490` → `0x141dbfb30` → `0x141dbff50`)**:
   - Llama `ISteamUser::RequestEncryptedAppTicket(nullptr, 0)` (vtable `SteamUser021`
     slot 20, offset `+0xa0`) y registra un `CCallResult` (`m_iCallback = 0x9a` = 154,
     vtable `0x14307b768`, `slot[0]` = `Run(pvParam, bIOFailure, hSteamAPICall)`).
   - En RUNE offline, `RequestEncryptedAppTicket` devuelve fallo (`m_eResult = 3`,
     `k_EResultNoConnection`), por lo que `_OnEncryptedAppTicketResponse`
     (`0x140de56d0`) escribe `eosMgr+0xa0 = 1`, `eosMgr+0x70 = 1`, `eosMgr+0x74 = 10`
     y aborta inmediatamente sin tocar EOS ni WinHTTP.
2. **Compuerta 2 — EOS Connect Login (delay-load IAT `0x143d5ac58`, 32 funciones)**:
   - Si el ticket de Steam tiene éxito (`m_eResult == 1`), `0x140de56d0` llama
     `0x140de4eb0`: convierte el ticket con `EOS_ByteArray_ToString` e invoca
     `EOS_Connect_Login(hConnect, opts, eosMgr, 0x140de3340)`.
   - El callback `0x140de3340` espera `ResultCode == 0` (`+0x00`), `ClientData`
     (`+0x08` = `eosMgr`) y `LocalUserId` (`+0x10`), escribe `eosMgr+0x70 = 1`,
     `eosMgr+0x74 = 0`, y formatea `LocalUserId` en `eosMgr+0x20` vía
     `EOS_ProductUserId_ToString`.
3. **Compuerta 3 — Sesión local EOS (`0x140de3d41` → `0x140de2670` y tick `0x140ddfc40`)**:
   - `0x140de2670` verifica `*(eosMgr + 0x10) != 0` (`hAntiCheatClient`), registra
     notificaciones (`AddNotify*` deben retornar IDs `!= 0`), valida `LocalUserId`
     (`FromString` != 0, `IsValid` != 0) y llama `BeginSession` (`== 0`).
   - En cada frame (`0x140ddfc40`), `EOS_AntiCheatClient_PollStatus` debe retornar
     `0x12` (`18` = `EOS_NotFound`, cola limpia; `0` significa violación detectada)
     y `EOS_Connect_GetLoginStatus` debe retornar `2` (`EOS_LS_LoggedIn`).
4. **Compuerta 4 — FromNet WSS asíncrono (`0x141e618b0` → `0x141e60550` → `0x141e60850` → `0x141e60a80`)**:
   - `0x141e618b0` inserta la conexión en el mapa `*param_1 + 0xe0` **después** de
     `WinHttpSendRequest`. Por tanto, `WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE`
     (`0x00400000`) debe dispararse de forma **asíncrona** tras retornar `SendRequest`.
   - `0x141e60850` llama `WinHttpReceiveResponse` + `WinHttpWebSocketCompleteUpgrade`
     y encola `0x141e60a80`, que registra el segundo callback `0x141e606b0` en el
     handle WebSocket, deja pendiente `WinHttpWebSocketReceive` (retorna `0` =
     `ERROR_SUCCESS`, completando luego vía `READ_COMPLETE` `0x00080000`), y notifica
     conexión establecida vía `0x141e61220`, disparando el primer `WinHttpWebSocketSend`.

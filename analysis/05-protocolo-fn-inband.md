# 05 — Protocolo FN (RESUELTO vía waygate-server)

> Binario: `eldenring.exe` sha256 `5d0b85d2…` (convención FRONTERA BINARIO)

## RESUELTO — estado: CONECTADO con servidor local

El protocolo FN quedó resuelto gracias a `vswarte/waygate-server` (servidor de
matchmaking open-source) + waygate-client. Handshake real sobre el canal WSS:

1. `C -> 00 00 01 00`  hello fijo
2. `S -> nonce24 || mac16 || box(pk_srv||nonce_srv||nonce_cli)`  advertisement 120B
   - box = crypto_box_detached con par PRESHARED fijado en el binario
   - plain = server_ephemeral_pk(32) + server_nonce(24) + client_nonce(24)
3. `C -> nonce24 || mac16 || box(pk_cli_efimera)`  72B
4. Ambos derivan `crypto_kx_*_session_keys` -> rx/tx
5. `C -> mac16 || secretbox(request)` con client_nonce (++LE por msg)
   - request: `u8=4 | seq u32LE | variant u32LE | campos wire-serde`
   - variantes: 0 CreateSession, 2 RestoreSession, 6 GetAnnounceMessageList,
     15 CreateBloodMessage, 16 RemoveBloodMessage, 17 ReentryBloodMessage,
     18 GetBloodMessageList, 19 EvaluateBloodMessage, 20 GetBloodMessageDetail,
     21 CreateBloodstain, 22 GetBloodstainList, 23 GetDeadingGhost,
     24 CreateGhostData, 25 GetGhostDataList,
     27 UpdatePlayerStatus (puebla BREAKIN_POOL via `is_invadeable`),
     28 BreakInTarget, 29 GetBreakInTargetList,
     30 RejectBreakInTarget, 31 AllowBreakInTarget,
     75 CreateMatchingTicket, 76 PollMatchingTicket, 79 CreateRoom
   - pushes (JoinPayload): 0x1 EvaluateBloodMessage, 0x2 BreakInTarget,
     0x3 AllowBreakInTarget, 0x4 RejectBreakInTarget,
     0x6 SummonSign, 0x7 RejectSign
6. `S -> mac16 || secretbox(response)` con server_nonce
   - response: `u8=5 | seq u32LE | u8 status | [u32 err | u32 variant + campos]`
   - string = u32LE len + bytes; Vec = u32LE len + items; heartbeat = `07 64`

Login observado: CreateSession → PollMatchingTicket → GetAnnounceMessageList →
UpdatePlayerStatus (repite) → CreateMatchingTicket/CreateRoom → CONECTADO.

## Infraestructura desplegada

- `winhttp_shim.cpp` modo PASSTHROUGH: Connect(FN)→127.0.0.1:[fn]port,
  OpenRequest strip SECURE, resto a winhttp real.
- Hook kx-derive @ `base+0x1e69570` (pattern waygate `? 53 ? 83 EC 50 ? 8B 05…`):
  salto absoluto `mov rax,imm64; jmp rax` (stolen 21B, fixup rip disp@+9).
  Escribe SERVER_PK→pk, CLIENT_SK→sk. (detour_install E9 rel32 no alcanza
  >2GB — bug corregido con instalador propio `install_kx_hook`)
- `matchbox/fnserver.py`: servidor `ws://127.0.0.1:10901` con PyNaCl + websockets.
- Claves investigación: CLIENT_SK=`0x43`×32, SERVER_SK=`0x53`×32.

## Notas históricas: estados del parser SMWS (ya no en el camino)

## Capas de transporte (de arriba abajo)

```
SFRPCManagerImpl          (dispatch RPC, vtable +0xa8..+0xc0 por msg-type 0x04-0x07)
  └─ SFMessageManagerCrypto   (encriptación sodium: ECDH + SHA-512, vtable 0x14308fbd0)
      └─ SFMessageManagerCSM  (session manager, mayormente delega en *(this+0x10))
          └─ SFMessageManagerSMWS ("Socket Mgr WebSocket": handshake RFC 6455 IN-BAND)
              └─ SFMessageManagerWH   (WinHTTP transport, vtable 0x143091130)
                  └─ winhttp.dll IAT real 0x144c0cc6c… (parcheada por whs)
```

Cada capa guarda la inferior en `*(this+0x10)` y delega por offset de vtable
(+0x38 = connect, +0x88/0x90 = send helpers, +0xa0 = poll-recv…).

## El handshake descubierto (empírico + estático)

1. Cliente abre WSS real a `gr-prod-steam.fromsoftware-game.net:10901` (interpolado por el shim).
2. Tras `WebSocketCompleteUpgrade`, el cliente envía un preámbulo binario de 4 bytes:
   `00 00 01 00` (capturado en runtime; probable versión u32 `0x00000100`).
3. El stream entrante se parsea con `FUN_141e5e5e0` (0x141e5e5e0):
   - Si el buffer empieza con `0d 0a` (`\r\n`, magic en `0x142bf5678`) → headers completos.
   - Si no → `FUN_141e5ece0` parsea líneas `token: value` (espera `:` 0x3a, salta isspace).
   - Retorno 2 = faltan datos; si ya consumió `0x100` bytes → teardown.
4. Al completar headers, `FUN_141e50c70` valida el objeto respuesta (`FUN_141e5f5c0`):
   - `dword [resp+0x20] == 0x65` → **status HTTP 101 Switching Protocols**.
   - `FUN_141e4ffe0`: header `upgrade` == `websocket`
   - `FUN_141e50190`: header `connection` == `upgrade`
   - `FUN_141e50340`: header `sec-websocket-accept` presente/validado
5. Después del 101, el stream pasa a **frames estilo RFC 6455** (WS-in-WS):
   - Parser entrante `0x141e5e670`: u16 BE → FIN(15) | opcode(8-11) | mask(7) | len7,
     0x7e→u16BE, 0x7f→u64BE.
   - Writer saliente `FUN_141e53cf0`: escribe `0x82` (FIN+binary) + len.
   - Strings SMWS en `0x143090800+`: `ws tcp wss ssl`, `Host: `,
     `Sec-WebSocket-Key: `, GUID `258EAFA5-…`, `sec-websocket-protocol` → `rpc`.

## Datos runtime confirmados (log er_local_mp.log)

- El juego llamó `WinHttpWebSocketReceive` async ANTES de enviar el preámbulo:
  el parser de headers está armado esperando la respuesta 101.
- Tras no recibir nada cerró el WS con status `1000` (timeout limpio del juego),
  y reintentó una segunda conexión idéntica.

## Estrategia de inyección implementada

`winhttp_shim.cpp` (búsq. `rx_script`):

- `fn_rx` en `[test]` de `er_local_mp.ini` controla la inyección sin recompilar:
  - `auto101` (default): `HTTP/1.1 101 Switching Protocols` + `Upgrade: websocket`
    + `Connection: Upgrade` + `Sec-WebSocket-Accept: s3pPLMBi…` + `Sec-WebSocket-Protocol: rpc`.
  - `echo`: devuelve cada frame saliente como entrada (prueba de version-ack).
  - hex plano, `|` separa mensajes WS sucesivos.
- Entrega: tras el primer frame TX (`tx_seen`), copia el siguiente mensaje del
  script al `rx_buf` pendiente y dispara `READ_COMPLETE (0x80000)` con
  `WINHTTP_WEB_SOCKET_STATUS{bytes, BINARY_MESSAGE}` desde hilo worker.
- Modo síncrono (`read != nullptr`) completado en línea también.

## Resultado run 2 — status-line rechazada

`HTTP/1.1 101 Switching Protocols\r\n<headers>` → cierre inmediato (1000).
Causa: `parse_status_line` (`0x141e5e4df`, token espacio / dígitos→status /
reason / `\r\n`) **no tiene callers directos** — la respuesta NO lleva
status-line HTTP. `FUN_141e5ece0` trago `"HTTP/1.1 101 Switching Protocols
\r\nUpgrade"` como nombre del primer header (hasta el `:` de `Upgrade:`) →
el header `upgrade` nunca entro al mapa → `FUN_141e4ffe0` fallo → close.

**Formato correcto: headers puros** (default auto101 actualizado):

```
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Accept: <sha1>\r\n
Sec-WebSocket-Protocol: rpc\r\n
\r\n
```

El status `+0x40==0x65` se inicializa fuera del parser de líneas
(`FUN_141e5fd00` = append a deque de pares de 0x40; no escribe status).

## Pendiente

- Si headers-only tambien cierra → el status `+0x40` SI viene del stream:
  probar via ini `fn_rx` con pseudo-header `485454502f312e31203130310d0a…`
  (`HTTP/1.1 101` SIN texto de reason — `HTTP/1.1:` con colon parsearia como
  header valido) o `310d0a…` (`1\r\n`?).
- Si `00 00 01 00` requiere un version-ack binario previo, probar
  `fn_rx=00000100` o `echo`.
- Post-101: capturar el primer frame RPC (`0x82`-prefixed) → mapear msg-type
  contra `SFRPCManagerImpl[25]` (types 0x04-0x07) y la tabla de 81 handlers.
- Crypto sodium: si el login va cifrado tras el upgrade, evaluar neutralizar
  `SFEncryptorSodium` (identidad) para ver el protocolo en claro.

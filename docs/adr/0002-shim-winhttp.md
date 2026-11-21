# ADR 0002 — Shim de WinHTTP para el path de login

**Fecha:** 2026-11-19 · **Estado:** aceptado

## Contexto

El test en juego (2026-11-19) demostró que el login online muere en el
connect WSS a `gr-prod-steam.fromsoftware-game.net` **antes** de tocar
Steam Networking. El path de conexión vive en `FNClientServant` y usa la
API WinHTTP WebSocket como transporte de señalización FN (ver
`analysis/04-path-login-wss.md`).

## Decisión

Emular localmente las tres capas previas y el transporte de señalización dentro
del proceso (`er_local_mp.dll`), usando las tablas IAT reales del binario fijado:

1. **Ticket local de `SteamUser021` (`hooks.cpp`)**:
   - Envolver los slots `20` (`RequestEncryptedAppTicket`) y `21`
     (`GetEncryptedAppTicket`) de la instancia `SteamUser021`, más
     `SteamAPI_RegisterCallResult`, `SteamAPI_UnregisterCallResult` y
     `SteamAPI_RunCallbacks` en la IAT real (`0x4c0d09c..0x4c0d0fc`).
   - Entregar `EncryptedAppTicketResponse_t` con `m_eResult = 1` (`k_EResultOK`)
     y un ticket sintético local determinista (basado en `peer_id` de matchbox).
2. **Shim local offline de EOS (`eos_shim.cpp`)**:
   - Parchear los 32 slots delay-load de `EOSSDK-Win64-Shipping.dll` en
     `0x3d5ac58..0x3d5ad50` para resolver `EOS_Connect_Login` localmente en
     `EOS_Platform_Tick` con un `EOS_ProductUserId` sintético local, reportar
     `EOS_LS_LoggedIn` (`2`) y mantener `PollStatus` en `EOS_NotFound` (`18`)
     sin tráfico externo.
3. **Shim asíncrono de WinHTTP (`winhttp_shim.cpp`)**:
   - Parchear los 14 slots reales de `winhttp.dll` (`0x4c0cc6c..0x4c0ccd4`).
   - Delegar `WinHttpCrackUrl` a `winhttp.dll` real (sin I/O de red).
   - Disparar `WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE` (`0x00400000`) en
     hilo auxiliar tras retornar `WinHttpSendRequest` (evitando condición de
     carrera con el registro de la conexión en `*servant + 0xe0`).
   - Mantener `WinHttpWebSocketReceive` pendiente en modo asíncrono (`ERROR_SUCCESS`)
     y reensamblar fragmentos en `WinHttpWebSocketSend` para capturar los
     mensajes FromNet salientes y responder vía `READ_COMPLETE` (`0x00080000`).

## Consecuencias

- Equivale a emular el servidor FromSoft a nivel API dentro del proceso:
  self-contained, sin TLS, sin cert store, sin tocar el sistema.
- El callback se invoca de forma síncrona (v1). Si hay deadlock por
  reentrancia en los task objects, mover a worker thread (nota: WinHTTP
  real usa thread pool).
- V1 captura el formato real del protocolo FN en el log; las respuestas
  fabricadas se iteran después contra ese formato y los 81 handlers.

## Alternativas descartadas

- Stub de task concreto (B): frágil, requiere mapear toda la cadena.
- WSS loopback real (C): requiere cert trusted — invasivo fuera del juego.

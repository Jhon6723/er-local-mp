# Analysis 07 — Internos de `CSNetAntiCheat` / EOS AntiCheatClient

**Fecha:** 2026-11-20 · **Build:** `eldenring.exe` SHA-256 `5d0b85d2…`
**Evidencia:** desensamblado Capstone sobre `eldenring.exe` (rango
`0x140ddd000..0x140de9000`, módulo EOS/Arxan) + trazas en vivo
(`er_local_mp.log`, `er_local_mp_p2.log`, `fnserver.log`).
**Relacionado:** `analysis/06-sesion-lobby-p2p.md` §4, `mod/src/hooks/eos_shim.cpp`.

## 1. Tabla delay-IAT de EOS (32 slots @ `0x3d5ac58`)

Import diferido que el binario resuelve a `EOSSDK-Win64-Shipping.dll` y que
`eos_shim.cpp` sobreescribe completa (ver tabla `EOS_SLOTS`, líneas 249-280).
Entradas críticas:

| Slot | RVA | Función |
|---|---|---|
| [3] | `0x3d5ac70` | `EOS_ProductUserId_FromString` |
| [15] | `0x3d5acd0` | `EOS_Platform_Tick` (hook que dispara el callback auth) |
| [17] | `0x3d5ace0` | `EOS_Platform_GetAntiCheatClientInterface` |
| [21] | `0x3d5ad00` | `EOS_AntiCheatClient_AddNotifyMessageToPeer` |
| [22] | `0x3d5ad08` | `EOS_AntiCheatClient_AddNotifyPeerActionRequired` |
| [23] | `0x3d5ad10` | `EOS_AntiCheatClient_RemoveNotifyPeerActionRequired` |
| [24] | `0x3d5ad18` | `EOS_AntiCheatClient_AddNotifyPeerAuthStatusChanged` |
| [25] | `0x3d5ad20` | `EOS_AntiCheatClient_RemoveNotifyPeerAuthStatusChanged` |
| [26] | `0x3d5ad28` | `EOS_AntiCheatClient_BeginSession` |
| [27] | `0x3d5ad30` | `EOS_AntiCheatClient_EndSession` |
| [28] | `0x3d5ad38` | `EOS_AntiCheatClient_PollStatus` |
| [29] | `0x3d5ad40` | `EOS_AntiCheatClient_RegisterPeer` |
| [30] | `0x3d5ad48` | `EOS_AntiCheatClient_UnregisterPeer` |
| [31] | `0x3d5ad50` | `EOS_AntiCheatClient_ReceiveMessageFromPeer` |

## 2. Protocolo de mensajes `CSNetAntiCheat` (`0x69`/`0x6a`/`0x6b`)

Canal in-game de autenticación peer entre instancias (observado en ambos logs):

- `0x140de0633` (`edx = 0x69`) / `0x140de0c4e` (`edx = 0x6a`): envío del PUID
  local. El payload es el `EOS_ProductUserId` serializado como string de
  **`0x21` = 33 bytes** (32 hex + NUL, ej.
  `"00020000000000000000000000000001\0"`).
- Receptor del `0x6a`: `0x140de0af9` llama `EOS_ProductUserId_FromString` y
  `0x140de0b0b` llama `EOS_AntiCheatClient_RegisterPeer` → crea el nodo de
  peer e inicia el temporizador de verificación.
- `0x6b`: mensajes peer→peer posteriores (vía `ReceiveMessageFromPeer`).
  **Verificado: recibir `0x6b` NO resetea `[peer+0x54]`** — solo el callback
  de auth-status apaga el timer.

## 3. Estructura del mapa de peers (`g_eosMgr`)

- `g_eosMgr` (`r15`) tiene en `[r15 + 0x88]` un `std::map` (red-black tree) de
  peers registrados; el bucle `0x140de0f55..0x140de10c6` lo itera cada tick.
- Por nodo (`rbx`, datos del peer en `[rbx + 0x28]`):
  - `[peer + 0x54]`: **timer de auth** — `0.0f` al registrar, sube con `dt`;
    `-1.0f` lo desactiva.
  - `[peer + 0x58]`: **segundo timer** (kick inmediato vía `0x140dde420`).
- Rol: `[rcx + 0xc] == 3` → el peer es host de la sesión.

## 4. Bucle del watchdog (`0x140de0f6d..0x140de1047`)

- `0x140de0fbe` suma `dt` a `[rbx + 0x54]`; `comiss xmm0, xmm6` contra
  **`120.0f` @ `0x1429c9d60`**.
- Al expirar: host (`[rcx+0xc]==3`) → `0x140de8020` (expulsa al cooperador);
  cliente → `r12d = 1` ("error de conexión, volviendo a tu mundo").
- Latido: cada ~2 s `0x140de0ced` llama `0x140dde390(&g_eosMgr)` →
  `0x140de6690` + `0x140de6c00` (stubs de integridad Arxan/EAC sobre
  `g_eosMgr`).

## 5. Callback de apagado (`AddNotifyPeerAuthStatusChanged`)

- Registro: `0x140de2835: lea r9, [rip-0x9dc]` → handler **`0x140de1e60`**.
- Layout de `EOS_AntiCheatCommon_OnPeerAuthStatusChangedCallbackInfo`:
  `+0x00 ClientData` (= `g_eosMgr`), `+0x08 PeerHandle`, `+0x10 AuthStatus`.
- `AuthStatus`: `0 = Unauthenticated`, `1 = NetworkAuth`,
  **`2 = RemoteAuthComplete`** → `sub ecx,1; cmp ecx,1` cae en `0x140de1efd`
  → **`0x140de2051: mov dword ptr [rdi+0x54], 0xbf800000` (`-1.0f`)** — apaga
  el timer para siempre.

## 6. Nota Arxan (por qué el fix no toca `.text`)

El rango `0x140ddd000..0x140de9000` contiene los stubs de integridad
(`0x140de63d0/6690/6c00`) que Arxan checksuma periódicamente. Parchear bytes
de `.text` (p. ej. el `je` de `0x140de0f67`) es detectable en minutos. La
solución implementada opera **solo sobre el heap / API EOS** — captura el
callback registrado en el slot [24] y lo invoca con `AuthStatus=2` desde
`f_Platform_Tick` tras cada `RegisterPeer`, reproduciendo la vía legítima.

# Analysis 06 — Subsistema de sesión Steam Lobby + transporte P2P (`SessionSteam` / `SteamNetworking006`)

**Fecha:** 2026-11-20 · **Build:** `eldenring.exe` SHA-256 `5d0b85d2…`
**Evidencia:** `C:\tools\ghidra-dump.txt` (líneas 2959–4267) + desensamblado Capstone sobre `eldenring.exe` y trazas en vivo (`fnserver.log`, `er_local_mp.log`).

## 1. Descubrimiento clave: cero dependencia de EOS P2P

Barrido completo de cadenas e imports de `eldenring.exe`:
- **EOS**: solo `EOS_Connect_*` y `EOS_AntiCheatClient_*` (cubiertos por los 32 slots delay-IAT en `eos_shim.cpp`). No existe import alguno de `EOS_P2P_*` ni `ISteamNetworkingMessages` / `ISteamNetworkingSockets`.
- **Steam**: toda la negociación de sesión y el transporte P2P tras el `PushParams::Join(SummonSign)` ocurren exclusivamente sobre **4 interfaces Steamworks**:
  1. `SteamMatchMaking009` (contexto `0x143c51c00`)
  2. `SteamUtils010` (contexto `0x143b489e8`)
  3. `SteamNetworking006` (contexto `0x143c602b0`, init thunk `0x142640b20`)
  4. `SteamUser021` (contexto `0x143b48a00`) y `SteamFriends017` (contexto `0x143b489d0`)

## 2. Flujo exacto `SummonSign` → Lobby → P2P

1. **Anfitrión crea Lobby antes de enviar `SummonSign`**:
   - `SessionSteam[14]` (`0x1423fea00`): `SteamMatchMaking009->CreateLobby(2, maxMembers)` (`vt+0x68`) → retorna `SteamAPICall_t`.
   - `0x1423fea50` / `0x1423feae5`: pollea `SteamUtils010->IsAPICallCompleted` (`vt+0x58`) y lee `GetAPICallResult` (`vt+0x68`) esperando `iCallbackExpected = 0x201` (`LobbyCreated_t`, `0x10` bytes: `+0x00 u32 m_eResult = 1`, `+0x08 u64 m_ulSteamIDLobby`).
   - Guarda `m_ulSteamIDLobby` en `[session + 0x568]` y lo empaqueta en los 69 bytes TLV de `RequestSummonSignParams.data`.
2. **Servidor FN entrega push al cooperador**:
   - `SummonSign` (variant 13): `player_id: i32` (`+9`), `identifier: i64` (`+13`), `data: Vec<u8>` (`dlen` en `+21`, payload en `+25`).
   - `external_id` en `GetSignList` y `SummonSign` es el `CSteamID` individual en **hexadecimal minúsculas sin prefijo** (`format!("{steam_id:x}")`, ej. `110000100002001`).
3. **Cooperador entra al Lobby al recibir el push**:
   - Retira su signo (`RemoveSign`, variant 12) y ejecuta `SessionSteam[18]` (`0x1423ff070`): lee los 8 bytes de `steamIDLobby` en `[session + 0x568]` y llama `SteamMatchMaking009->JoinLobby(steamIDLobby)` (`vt+0x70`).
   - `0x1423ff100` / `0x1423ff195`: pollea `SteamUtils010->IsAPICallCompleted` y `GetAPICallResult` con `iCallbackExpected = 0x1f8` (`LobbyEnter_t`, `0x18` bytes: `+0x00 u64 m_ulSteamIDLobby`, `+0x08 u32 perms`, `+0x0c u8 locked`, `+0x10 u32 m_EChatRoomEnterResponse = 1`). Verifica que `m_ulSteamIDLobby == [session + 0x568]`.
4. **Sincronización de miembros del Lobby (`0x1423fe5d0` y `0x1423fec40`)**:
   - Ambos extremos consultan:
     - `GetLobbyOwner(this, &out, lobbyId)` (`vt+0x118`, retorno struct MSVC x64 en `RDX`)
     - `GetNumLobbyMembers(this, lobbyId)` (`vt+0x88`)
     - `GetLobbyMemberByIndex(this, &out, lobbyId, idx)` (`vt+0x90`, retorno struct en `RDX`)
     - `SteamFriends017->GetFriendPersonaName(memberId)` (`vt+0x38`): en `0x1423fe6f4` y `0x1423fed64` descarta al miembro si el puntero es nulo o `name[0] == '\0'`.
   - Al unirse o salir alguien, `SessionSteam` escucha el callback `0x1fa` (`506` = `LobbyChatUpdate_t`, `0x20` bytes verificados en `0x1423f8390`).
   - Validador de ID `0x1423fd960`: exige universo `1..4` (`0x01......`); para cuentas individuales tipo `1` exige instancia `1` (`0x01100001_xxxxxxxx`), y para lobbies tipo `8` (`0x01840000_xxxxxxxx`) pasa directo.
5. **Autenticación de miembro y transporte P2P**:
   - `SessionMemberSteam` (`0x142402d22..0x1424030d0`): usa `SteamUser021` `vt+0x68` (`GetAuthSessionTicket`), `vt+0x70` (`BeginAuthSession` → espera `0` y callback `0x8f` `ValidateAuthTicketResponse_t` de **`0x14` = 20 bytes** verificado en `0x1423f8380`, `#pragma pack(1)` sobre `CSteamID`), `vt+0x78` (`EndAuthSession`), `vt+0x80` (`CancelAuthTicket`).
   - `MTDispatchedSteamSocket` (`0x142640310..0x14264113b`) invoca únicamente 4 slots de `SteamNetworking006` pasando `CSteamID` por valor en `RDX` y `nChannel` explícito:
     - `vt+0x00` `SendP2PPacket(this, uint64_t remote, const void* data, uint32_t len, int sendType, int channel)` (`0x142640afb`)
     - `vt+0x10` `ReadP2PPacket(this, void* dest, uint32_t cap, uint32_t* outLen, uint64_t* outRemote, int channel)` (`0x142640d19`, sin llamar a `IsP2PPacketAvailable`)
     - `vt+0x18` `AcceptP2PSessionWithUser(this, uint64_t remote)` (`0x142640988`, tras callback `0x4b2` `P2PSessionRequest_t` de 8 bytes)
     - `vt+0x28` `CloseP2PChannelWithUser(this, uint64_t remote, int channel)` (`0x14264032a`, `0x142641127`)

## 3. Aislamiento de `GetSteamID` frente a `ER0000.sl2`

`ER0000.sl2` valida el `CSteamID` del propietario al cargar la partida, mientras que `SessionManagerSteam` lee su `CSteamID` local en `0x1423f4881` (`SteamUser021` `vt+0x10`). Devolver el `CSteamID` sintético (`0x0110000100000000 | acct_id`) únicamente cuando `_ReturnAddress()` cae en `DLNR3D/DLNW3D` (`RVA 0x23f0000..0x2660000`) permite que múltiples instancias en la misma PC carguen el save sin error de propietario y tengan identidades de red distintas.

## 4. Watchdog de 120 s de `EOS_AntiCheatClient` en sesiones co-op

Al entrar un cooperador al mundo, `0x140de0b0b` llama a `EOS_AntiCheatClient_RegisterPeer` (`0x3d5ad40`, `ApiVersion=3`, `PeerHandle` en `opts+0x08`, `AuthenticationTimeout=0x78` = 120 s) e inicializa el temporizador `[peer + 0x54] = 0.0f`. En cada frame, `0x140de0f80..0x140de1047` suma `dt` a `[peer + 0x54]` y lo compara contra `120.0f` (`0x1429c9d60`): si expira sin completar autenticación, el host invoca `0x140de8020` y el cliente marca desconexión, devolviendo al cooperador a su mundo exactamente a los 2 minutos.

El apagado legítimo ocurre en el callback registrado vía `EOS_AntiCheatClient_AddNotifyPeerAuthStatusChanged` (slot `[24]` = `0x3d5ad18`, handler `0x140de1e60`): al recibir `EOS_AntiCheatCommon_OnPeerAuthStatusChangedCallbackInfo { ClientData, PeerHandle, AuthStatus = 2 /*RemoteAuthComplete*/ }`, ejecuta `0x140de2051: mov dword ptr [rdi + 0x54], 0xbf800000` (`-1.0f`), desactivando el temporizador sin tocar `.text` (compatible con Arxan).

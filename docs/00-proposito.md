# 00 — Propósito

**Estado:** propuesta

## Objetivo

Habilitar el multiplayer de ELDEN RING en una build local **sin EasyAntiCheat,
sin Steam real y sin los servidores de FromSoftware**, preservando la mecánica
original de marcas de invocación (summon signs) e invasiones.

## Contexto del sistema original

El multiplayer oficial tiene tres dependencias externas:

| Dependencia | Función | Sustituto en este proyecto |
|---|---|---|
| Servidor From (`wss://gr-prod-steam.fromsoftware-game.net:10901`) | Matchmaking, marcas, sesiones, async features | `matchbox` (propio) |
| Steam P2P (`ISteamNetworking`) | Transporte de gameplay host↔phantoms | Socket UDP propio dentro del mod |
| Tickets Steam + EAC-EOS | Auth y anticheat | Stubs (la build ya los ignora) |

Hallazgo clave verificado (`analysis/`): el emulador `steam_api64.dll` (RUNE)
expone toda la superficie de SteamNetworking pero **no transporta paquetes**
(experimento `er-p2p-test`, 2026-11-19). El transporte hay que construirlo.

## Flujo objetivo

```
mod arranca       -> REGISTER {player, ip:port} en matchbox
host crea marca   -> hook CreateSign  -> SIGN_UP en matchbox
cliente lista     -> hook GetSignList -> SIGN_LIST devuelve marcas
cliente invoca    -> hook SummonSign  -> JOIN devuelve endpoint del host
                  -> conexión UDP directa (o RELAY si NAT lo impide)
                  -> el juego cree que la invocación tuvo éxito
```

## Alcance

- Co-op por invocación (SummonSign → phantom en mundo del host)
- Conectividad por IP directa / LAN / VPN; relay vía matchbox como fallback
- Dos o más instancias de la misma build del juego (SHA-256 fijado en AGENTS.md)

## Fuera de alcance (v1)

- Invasiones y QuickMatch/arena (mismo mecanismo, fase posterior)
- Bloodstains, mensajes en el suelo, fantasmas (async features de FromNet)
- NAT traversal por hole-punch puro (v1: IP directa y relay)
- Compatibilidad con otras builds del juego o con el juego oficial en Steam

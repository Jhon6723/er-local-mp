# 02 — Protocolo matchbox (borrador v0.1)

**Estado:** borrador

Un solo socket UDP (default **37015**) sirve control y relay. Datagramas
binarios, little-endian, con cabecera fija. Mensajes idempotentes; el cliente
reintenta hasta ACK o timeout (300 ms × 5).

## Cabecera común

```
offset  campo       tamaño  descripción
0       magic       2       0x4D 0x52  ("MR")
2       version     1       0x01
3       type        1       ver tabla
4       seq         2       id de petición (responder con el mismo)
6       payload     N       según type
```

## Tipos de mensaje

| type | nombre | dirección | propósito |
|---|---|---|---|
| 0x01 | REGISTER   | mod→box | anunciar presencia `{name_len u8,name,ip u32,port u16,game_hash u32}` |
| 0x02 | REGISTER_ACK | box→mod | `{peer_id u32}` asignado |
| 0x03 | SIGN_UP    | mod→box | publicar marca `{peer_id u32, area_id u32, char_hash u32}` |
| 0x0B | SIGN_UP_ACK | box→mod | `{sign_id u32}` |
| 0x04 | SIGN_LIST  | mod→box | pedir marcas `{peer_id u32, area_id u32}` (area_id=0 = todas) |
| 0x05 | SIGN_LIST_ACK | box→mod | `{count u16, [sign_id, peer_id, char_hash, area_id] u32*}` |
| 0x06 | SIGN_DOWN  | mod→box | retirar marca `{peer_id, sign_id}` → GENERIC_ACK |
| 0x07 | JOIN       | mod→box | activar marca `{peer_id u32, sign_id u32, want_mode u8}` |
| 0x08 | JOIN_ACK   | box→mod | `{host_peer_id, host_ip u32, host_port u16, mode u8, session_id u32}` |
| 0x09 | PUNCH      | box→mod | "abre UDP hacia ip:port" `{peer_id, ip, port}` (hole-punch, v2) |
| 0x0A | KEEPALIVE  | mod→box | `{peer_id}` cada 15 s; TTL de registro 60 s; sin respuesta |
| 0x0C | GENERIC_ACK | box→mod | payload vacío; ack genérico con el seq de la petición |
| 0x0D | NOTIFY_JOIN | box→host | `{session_id u32, joiner_peer_id u32, joiner_ip u32, joiner_port u16, mode u8}` |
| 0x10 | RELAY      | ambos   | `{session_id u32, data*}` reenvío de gameplay |
| 0x7F | ERROR      | box→mod | `{req_type u8, code u8}` code: 1=unknown_peer 2=no_sign 3=full |

mode: 0=directo 1=relay. `want_mode` en JOIN pide el modo; el servidor puede
forzar relay (`--relay`).

## Semántica

- El endpoint **observado** (origen del datagrama) es el autoritativo para
  enrutar; el `ip:port` de REGISTER es informativo.
- `REGISTER` devuelve `peer_id` efímero; expira si no hay KEEPALIVE en 60 s.
- `SIGN_UP` responde `sign_id`; una marca muere si muere su peer.
- `JOIN` es atómico: consume la marca (`SIGN_DOWN` implícito), crea una sesión
  `session_id`, devuelve el endpoint del host + `mode`, y notifica al host con
  `NOTIFY_JOIN` (joiner endpoint + mismo `session_id` para relay).
- `RELAY`: el box conmuta por `session_id` ↔ par de endpoints; no interpreta
  `data` (paqueTLS del juego pasa opaco). Solo reenvía si el origen es miembro.
- `ERROR` usa el `seq` de la petición original.

## Registro de decisiones pendientes

- ¿`char_hash` = hash del save/personaje para aislar marcas entre personajes? (TBD Ghidra: qué identifica el juego en `RequestCreateSignParams`)
- ¿Sign area/zone id real usado por el juego para filtrar? (TBD Ghidra: `RequestGetSignListParams` filtra por `PlayRegion`?)

# 05 — Despliegue del servidor en VPS

**Estado:** propuesta

## Objetivo

Sacar `fnserver.py` + `matchbox` de la PC del host y correrlos en una VM
permanente con IP estable, de modo que cualquier jugador pueda conectarse sin
que la PC del host esté encendida.

## El problema crítico: registro de peers y P2P

`fnserver.py` registra cada peer por la **IP de origen de sus paquetes UDP de
control** (`PEERS_NET[sid] = (addr[0], port)`); esa dirección es la que el
lobby entrega a los demás jugadores para el P2P directo.

- **Con servidor en LAN/Tailscale (verificado):** los clientes anuncian sus
  IPs `100.x` — alcanzables directamente, el P2P fluye.
- **Con servidor en VPS pública:** cada cliente registrará su **IP pública
  NAT**, no su IP local. El P2P hogar↔hogar por Internet solo funciona si el
  NAT lo permite (hole-punching): en NAT cónico suele salir si ambos lados
  envían primero; en **NAT simétrico / CGNAT de ISP** (común en Colombia) los
  puertos efímeros difieren por destino y el P2P directo **falla**.

### Opción A — VPS dentro del tailnet (recomendada)

Instalar Tailscale en la propia VPS y unirla al tailnet. Los clientes ponen
`matchbox_ip = 100.x.x.x` (IP Tailscale de la VPS) y todo funciona exactamente
como la sesión verificada: registro con IPs `100.x`, P2P por la malla
WireGuard, cero problemas de NAT. Ventaja extra: los puertos no quedan
expuestos a Internet abierto.

### Opción B — VPS pública sin Tailscale

Abrir los puertos en el firewall de la VM y del proveedor:

- `TCP 10901` — WebSocket FN (login, mensajes, signos, pools)
- `UDP 37015` — matchbox (rendezvous/registro)
- `UDP 37017` — canal de control/lobbies

Clientes: `matchbox_ip = <IP pública VPS>` (y `[fn] host` si se separa).
El login/mensajes/signos funcionarán siempre; **el P2P entre jugadores
dependerá del NAT de cada hogar** — puede funcionar por hole-punch o fallar
en CGNAT. Mitigación futura: modo relay en `matchbox` para el tráfico P2P.

## Lo que corre en la VPS

```bash
python3 -m venv ~/erlmp && ~/erlmp/bin/pip install websockets pynacl
~/erlmp/bin/python -u ~/matchbox/fnserver.py        # TCP 10901 + UDP 37017
~/erlmp/bin/python -u -m matchbox.main              # UDP 37015
```

- Persistencia: `bloodmessages.json` se crea junto a `fnserver.py` — los
  mensajes sobreviven reinicios del proceso y de la VM.
- `BLOODSTAINS`/`GHOSTDATA`/`SIGNS`/`BREAKIN_POOL` son volátiles (memoria).
- Requisitos mínimos triviales: cualquier VM con ~512 MB RAM sobra (el
  servidor solo coordina; el gameplay va P2P).

## Systemd (units propuestas)

```ini
# /etc/systemd/system/erlmp-fn.service
[Unit]
Description=er-local-mp FN server
After=network-online.target

[Service]
WorkingDirectory=/home/erlmp/matchbox
ExecStart=/home/erlmp/venv/bin/python -u fnserver.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Una unit idéntica para `matchbox` (`python -u -m matchbox.main`).

## Configuración del cliente

```ini
[net]
matchbox_ip = 100.x.x.x        # IP Tailscale de la VPS (opción A)
                             # o IP pública de la VPS (opción B)
matchbox_port = 37015
listen_port = 27016            # único por máquina
mode = 0
session = direct

[fn]
port = 10901
```

## Seguridad

- El servidor **no tiene autenticación** — cualquiera con la IP puede hacer
  login FN. Con opción A el tailnet ya es el perímetro. Con opción B,
  restringir el firewall a las IPs de los jugadores conocidos.
- El FN handshake usa claves fijas de investigación (`0x43`/`0x53`) — cifrado
  para cumplir el protocolo, no para confidencialidad.

## Verificación esperada

1. `curl http://<vps>:10901` responde (aunque sea error HTTP — el WS escucha).
2. `fnserver.log` en la VPS muestra `conexion de <ip>` al lanzar el juego.
3. Login FN en el menú (modo online) en ambos clientes.
4. `lcreate`/`ljoin` en el log + P2P establecido → co-op como en la sesión
   Tailscale verificada.

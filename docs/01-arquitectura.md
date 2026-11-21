# 01 — Arquitectura

**Estado:** propuesta

## Decisión

**Modular simple** — módulos de una sola responsabilidad con dependencias
mínimas, sin capas formales ni puertos/adaptadores.

Justificación: no hay infraestructura (ni base de datos, ni colas, ni UI
compleja). Los candidatos descartados:

- *Layered clásica*: añade capas que nadie necesita (no hay "dominio" separable
  del transporte en un componente de ~300 líneas por lado).
- *Hexagonal (ports & adapters)*: el único "puerto" real es la frontera con el
  juego (hooks) — se resuelve con un módulo `hooks` aislado, sin framework.
- *Modular monolito*: suficiente. Si un módulo crece, se subdivide.

Ver `docs/adr/0001-arquitectura-modular.md`.

## Componentes

```
┌──────────────────────────┐        ┌──────────────────────────┐
│  instancia A             │        │  instancia B             │
│ ┌──────────────────────┐ │        │ ┌──────────────────────┐ │
│ │ eldenring.exe        │ │        │ │ eldenring.exe        │ │
│ │  └ mod.dll (inyect.) │ │        │ │  └ mod.dll (inyect.) │ │
│ │     hooks  proto  udp│ │        │ │     hooks  proto  udp│ │
│ └──────────┬───────────┘ │        │ └──────────┬───────────┘ │
└────────────┼─────────────┘        └────────────┼─────────────┘
             │ control: REGISTER/SIGN/JOIN       │
             └──────────────┬───────────────────┘
                            ▼
                    ┌───────────────┐
                    │   matchbox    │  dir de marcas + rendezvous + relay
                    │  (UDP único)  │
                    └───────┬───────┘
             ┌──────────────┴───────────────────┐
             ▼       gameplay P2P (UDP)          ▼
          instancia A  ◄──────────────────────► instancia B
```

## matchbox — módulos

| Módulo | Responsabilidad |
|---|---|
| `proto` | Codificar/decodificar mensajes del protocolo (ver `02-protocolo-matchbox.md`) |
| `state` | Tablas en memoria: peers registrados, marcas activas, sesiones relay |
| `control` | REGISTER/SIGN_UP/SIGN_LIST/JOIN/LEAVE → respuestas |
| `relay` | Reenvío UDP entre peers que no pueden conectar directo |
| `main` | Socket UDP + bucle de despacho; ~todo es un solo proceso |

## mod.dll — módulos

| Módulo | Responsabilidad |
|---|---|
| `config` | Lee `er_local_mp.ini` (matchbox addr, nombre, modo transporte) |
| `hooks` | Detours sobre funciones del juego y del `steam_api64.dll` del emu |
| `signs` | Traduce CreateSign/GetSignList/SummonSign ↔ protocolo matchbox |
| `session` | Fuerza el estado "en sesión" e inyecta el phantom/peer (REA: TBD) |
| `transport` | Socket UDP: desvía `SendP2PPacket`/`ReadP2PPacket`/`IsP2PPacketAvailable` |
| `stub` | No-ops de auth: tickets Steam, regulation hash, EOS/EAC |
| `log` | Log a `er_local_mp.log` junto al DLL |

## Fronteras con el binario (propiedad del módulo `hooks`)

Todo offset, vtable o patrón AOB del `eldenring.exe` objetivo vive
exclusivamente en `mod/hooks/` y se documenta en `analysis/`. El resto del mod
solo ve interfaces C estables que `hooks` expone — si cambia la build del
juego, solo cambia un módulo.

## Topología de red (v1)

- Control mod↔matchbox: **UDP con reintentos** (mensajes pequeños, idempotentes)
- Gameplay peer↔peer: **UDP directo**; si no hay ruta, **relay** por matchbox
- El juego aporta fiabilidad sobre el canal SteamSocket; nuestro UDP puede ser
  "best effort" salvo confirmar lo contrario en el RE de `NWMTSteamSocketManager`

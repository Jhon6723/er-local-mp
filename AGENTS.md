# Reglas de desarrollo — er-local-mp

Mod de multiplayer local/offline para ELDEN RING (build sin anticheat ni Steam real).
Trabajo de ingeniería inversa con fines académicos.

## Spec-Driven Development (SDD)

- **`docs/` es la fuente de verdad.** Toda decisión de diseño, especificación y
  propósito se documenta antes de implementar. El código sigue a la spec, no al
  revés.
- Si una decisión cambia durante la implementación, **primero se actualiza el
  doc**, luego el código. Un doc desactualizado es un bug.
- Numeración: `NN-tema.md` en orden de lectura. Decisiones puntuales y su
  justificación van en `docs/adr/NNNN-decision.md`.
- Estados de spec: `borrador` → `propuesta` → `aprobada` → `implementada`.
  Todo doc lleva su estado en la cabecera.

## Estructura

```
er-local-mp/
├── AGENTS.md              # este archivo
├── docs/                  # propósito, arquitectura, specs, ADRs
├── matchbox/              # servidor de rendezvous/relay (Python)
├── mod/                   # DLL del mod cargada por EldenModLoader (C++)
└── analysis/              # notas de REA/Ghidra, offsets, xrefs (no binarios)
```

## Arquitectura elegida

**Modular simple** (sin capas forzadas, sin puertos/adaptadores formales).
No hay infraestructura persistente ni bases de datos; la complejidad está en el
protocolo y los hooks, no en la separación de responsabilidades. Cada módulo es
un archivo/directorio con una responsabilidad clara y una dependencia mínima
entre módulos. Ver `docs/01-arquitectura.md`.

## Reglas de trabajo

- **No escribir nada en el directorio del juego** (`C:\Games\Elden.Ring...`).
  Todo el desarrollo vive en este proyecto. Solo lectura del juego.
- Idioma: documentación y comentarios en **español**. Código e identificadores
  en inglés (convención del dominio).
- Nada de secrets ni rutas de usuario hardcodeadas en código commiteado; la
  config va en archivos `.ini`/`.toml` de ejemplo.
- Los hallazgos de REA/Ghidra (direcciones, xrefs, pseudo-código relevante) se
  registran en `analysis/` con referencia a la evidencia, no en comentarios
  sueltos.
- Versiones fijadas del binario objetivo: `eldenring.exe` SHA-256
  `f9118fea2cfd8fa3901e8060bfadb1552cb2471771ded8a5b662c4e298ffb328`
  (v1.17.2, image base `0x140000000`). Todo offset/dirección documentada
  se refiere a esa build — la tabla de port desde la build vieja
  (`5d0b85d2…`) y el método para re-derivarlo están en
  `analysis/09-port-1172-offsets.md`. La build vieja ya no existe en la
  máquina; su snapshot funcional quedó en el commit inicial de Git +
  `backups/er_local_mp-5d0b85d2.dll` (fuera del repo).

## Toolchain

- **Compilador del mod:** LLVM-MinGW en `C:\tools\llvm-mingw-20261020-msvcrt-x86_64`
  (clang 23.1.4, target x86_64-w64-windows-gnu). Build: `mod\build.bat` →
  `build\er_local_mp.dll` (enlazado estático, sin deps externas).
- **matchbox:** Python 3.14 (`python -m matchbox.main --port 37015`).
- **REA/Ghidra:** Ghidra 12.1.4 en `C:\tools\ghidra_12.1.4_PUBLIC`,
  JDK 21 en `C:\tools\jdk-21.0.13+9`. Para análisis dirigido existe
  `analysis/rtti_walk.py` (RTTI/vtables sin Ghidra) + capstone en el Python del
  sistema.

## Verificación

- `matchbox`: test funcional con el propio script en modo loopback antes de
  tocar el mod (`python matchbox/test_matchbox.py`).
- `mod`: el criterio mínimo es "el juego no crashea al cargar el DLL"; el
  objetivo es "SummonSign → sesión P2P entre dos instancias en LAN".
  Smoke test sin juego: `LoadLibrary` del DLL → `er_local_mp.log` junto al
  loader muestra init de transporte y errores controlados de matchbox/hooks.
- Cualquier comportamiento observado en el binario (offsets, protocolos)
  queda verificado cuando se reproduce en la build fijada arriba.

## Estado al 2026-11 (ver `docs/04-estado-y-roadmap.md` para el detalle)

**EN CURSO — port a 1.17.2:** el binario nuevo es
`f9118fea…b328`; los offsets del mod ya están portados (ver
`analysis/09-port-1172-offsets.md`) y el DLL compila limpio. Falta la
verificación en runtime (loader + login + co-op).

**VERIFICADO en build vieja `5d0b85d2` (snapshot en Git + backups/):**
dos instancias corrieron co-op real (summon sign → lobby → P2P →
Margit >120 s), mensajes, manchas, fantasmas, signos y evaluación
end-to-end; invasión implementada sin verificar.

**Nuevo — `mode=steam` (híbrido OnlineFix):** `[net] session=steam`
delega interfaces Steam a la emu cargada (sin wrapping, SteamID64 real
como `external_id`); `[net] session=direct` conserva el transporte UDP
propio + lobbies sintéticos. `fnserver.py` sigue siendo necesario en
ambos modos (el protocolo FN no es Steamworks). Diseño en
`analysis/08-seamless-y-onlinefix.md` + `analysis/09-port-1172-offsets.md`.

**Pendiente:** verificación en runtime del port (login, signos, co-op),
restaurar loader + `eldenring_p2.exe` (mutex: segundo descriptor
`CreateMutexW` en `0x4c145ec` / `"Global\SekiroMutex"` UTF-16), verificar
invasión, LAN 2 PCs / `mode=steam` Internet, persistencia de
manchas/fantasmas, 3+ jugadores, empaquetado.

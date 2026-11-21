# Analysis 03 — Extracción dirigida Ghidra + tabla de handlers

**Fecha:** 2026-11-19 · **Build:** `eldenring.exe` `5d0b85d2…`
**Método:** `analyzeHeadless -import -noanalysis` (segundos) + script
`C:\tools\ghidra-scripts\ExtractTargets.java` que desensambla/decompila los
vtables de `analysis/01` + funciones sueltas. **Resultado: 173 funciones
decompiladas en `C:\tools\ghidra-dump.txt`.**

## Por qué dirigido y no análisis completo

El análisis exhaustivo (3 corridas, ~2.5h) nunca completó: la última llegó a
`ApplyDataArchiveAnalyzer` antes de expirar el timeout de REA y el bridge
(entrega resultados por TCP al proceso node muerto) no produjo `session.json`.
La DB de 1.12GB quedó en el temp dir y en `C:\tools\ghidra-snapshot-final\`
pero sin registrar en el `.rep` → no recuperable vía proyecto.

Lección: para este binario (87MB, ~100k funciones), el análisis completo de
Ghidra no es práctico como camino principal. Import sin analizadores (~40s) +
decompile on-demand de funciones ya localizadas vía RTTI = mismo resultado
en minutos.

## Hallazgo principal: tabla de handlers `0x1447ff410`

`FUN_141deff60` (el "result setter" llamado tras cada request) construye en
su primera invocación una **tabla de 81 descriptores** en `0x1447ff410`,
indexada por `type_id` — el mismo enum de `analysis/02`:

- `handlers[0x00]` = `0x141de8080` (CreateSession)
- `handlers[0x07]` = `0x141de7150` (CreateSign)  *(offset 0x410+7*8=0x448)*
- `handlers[0x0D]` = `0x141de85b0` (SummonSign)
- `handlers[0x24]` = `0x141de8b40` (JoinMultiplay)
- ... hasta `handlers[0x50]` (0x1447ff690)

Las entradas mezclan `&UNK_xxx` (objetos descriptor estáticos, probablemente
vtable+params de serialización por tipo) y `FUN_xxx` (funciones). Son los
constructores/procesadores de cada request/response.

**Implicación para el mod**: para fabricar respuestas locales no hay que
reimplementar el protocolo — hay que *invocar el handler correcto* con un
contexto sintético, o reemplazar el descriptor con uno que devuelva éxito.

## Dispatcher `0x141df3a80`

Es un thunk → `FUN_145938d4a` con jumptable en `0x144ddde82` indexada por
`*param_1` (estado del servant). El cuerpo real quedó como
`UNRECOVERED_JUMPTABLE` (demasiadas ramas para el decompilador) — el dispatch
por estado se leerá mejor del disasm o por tracing en vivo (x64dbg).

## Secuencia FNClientImpl (login/handshake)

`FNClientImpl` vtable `0x14307d8c8` (24 slots) — decompilada en el dump;
es el camino Connect→CreateSession→RestoreSession para el stub de login.

## Artefactos

- `C:\tools\ghidra-dump.txt` — 173 funciones decompiladas (4.4k líneas)
- `C:\tools\ghidra-scripts\ExtractTargets.java` — regenerable: editar
  `TABLES`/`SINGLES` y correr headless `-process` (segundos)
- `C:\tools\ghidra-snapshot-final\` — snapshot de la DB de la corrida larga
  (incompleta, sin registrar; solo útil como última opción)

## Pendiente

- Descompilar handlers específicos de `handlers[0x07/0x0A/0x0D]` (CreateSign/
  GetSignList/SummonSign) para saber qué estructura de "éxito" esperan
- Entender el jumptable de `0x145938d4a` (estados del servant)
- Mapear `FNClientImpl` → stub de login
- Probar el DLL en el juego (mods/) — verificación mínima de AGENTS.md

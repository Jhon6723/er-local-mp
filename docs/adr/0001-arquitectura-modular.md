# ADR 0001 — Arquitectura modular simple

**Estado:** aprobada
**Fecha:** 2026-11-19

## Contexto

Dos componentes: `matchbox` (servidor UDP de rendezvous/relay, ~300 líneas) y
`mod` (DLL inyectada en el juego, hooks + socket). Sin persistencia, sin UI, sin
dependencias externas pesadas.

## Decisión

Arquitectura **modular simple**: un módulo por responsabilidad, dependencias
explícitas y mínimas, sin capas ni interfaces formales obligatorias. Excepción
única y deliberada: el módulo `hooks` del mod actúa como única frontera con el
binario del juego (aislamiento informal de puertos).

## Alternativas consideradas

- **Layered**: dos capas útiles (dominio/transporte) no justifican convenciones
  de capa ni DTOs intermedios en 300 líneas.
- **Hexagonal**: los "puertos" serían 2 (juego, socket). Sobreingeniería; el
  módulo `hooks` ya aísla la dependencia volátil.
- **Microservicios / plugins**: un solo proceso por componente basta.

## Consecuencias

- Cambios en la build del juego solo tocan `mod/hooks/` + `analysis/`.
- Si `matchbox` crece (persistencia, auth), se reevalúa en un ADR nuevo.

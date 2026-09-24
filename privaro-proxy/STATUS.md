# STATUS — Privaro (iCommunity Labs)

_Última actualización: 2026-09-24_

---

## Estado actual

- Protección de documentos fotografiados (OCR) en producción y estable: Tesseract disponible, Google Cloud Vision como motor principal (decisión explícita — Tesseract falló repetidamente en pruebas reales), con validación de checksum real de DNI/NIE, y entidades nuevas `license_plate` y `address`.
- `generate-dpo-report` arreglado tras 3 iteraciones reales en producción (getClaims→getUser, period_label/generation_type, `.maybeSingle()` sin scope de org_id) — pendiente de que el usuario confirme que "Generar ahora" funciona sin más errores.
- Correo enviado a Octupus (Michel) proponiendo activar `protect-output` — tráfico de producción real confirmado desde el 18 de septiembre (Octupus + al menos 1 sub-cuenta de cliente, "Ortoprime"), pero solo usan `direction: input`, nunca escanean la respuesta de su propio LLM.
- Conector de Lovable conectado — a partir de ahora los prompts a Lovable se envían directamente desde esta sesión, sin copiar/pegar manual. Proyecto: `938e6682-2a16-4ca7-b87f-913f1bd69b5d`.

## Última sesión

- Auditoría de seguridad completa de la app (5 fases): 11 problemas reales encontrados y corregidos, 4 críticos — el más grave, cualquier usuario autenticado podía auto-otorgarse acceso "platform admin" o suplantar cualquier organización vía `profiles` sin `with_check` en RLS.
- Construida la funcionalidad de protección de documentos en imagen (OCR) de cero: Tier 1 Tesseract → Tier 2 Google Vision, con 6 bugs reales encontrados y arreglados sobre pruebas con DNIs reales (checksum de DNI, segmentación de OCR pegando campos sin separador, reconstrucción de saltos de línea, orden de prioridad `address` vs `full_name`).
- Documentación pública y de partners actualizada (PARTNER_API_REFERENCE.md, Docs.tsx, Changelog.tsx, PiiDetectionApi.tsx) para reflejar todo lo anterior — varios endpoints (`protect-document`, `protect-output`, `/v1/agent/*`) estaban construidos pero sin documentar en ningún sitio.
- Investigación de mercado: Sigma Cognition/AGENDA (competidor débil, anonimización básica pese al marketing), BDO Evidence (no competidor, solopreneur en fase pre-piloto, problema distinto — proveniencia de contenido, no protección de PII), Alinia AI (competidor real y consolidado, con Banco Santander como cliente — no contactar como prospecto), Aelis (partner potencial real vía implantaciones de Sage Copilot).

## Decisiones tomadas

- [2026-08-11] Tier 2 de OCR (Google Cloud Vision) construido como escalada condicional inicialmente, luego cambiado a motor **primario** por decisión explícita del usuario — Tesseract demostró fallos reales repetidos (checksum, segmentación) y el coste de Vision es marginal al volumen actual. Tesseract queda solo como fallback de resiliencia si Vision falla técnicamente.
- [2026-08-11] Matrícula española y dirección postal añadidas como entidades de nivel "identificador directo" (mismo criterio que DNI/IBAN) — solo nombre o fecha de nacimiento aislados NO se consideran identificadores per se.
- [2026-08-12] `TOKEN_PREFIX` estaba duplicado sin importación compartida en 4 archivos distintos (detector.py, proxy.py, document.py, image_document.py) — sincronizados, pero sigue siendo una duplicación frágil pendiente de refactorizar a un solo origen.
- [2026-08-12] Google Cloud Vision configurado vía `GOOGLE_VISION_API_KEY` en Railway (variable de entorno, gestionada por el usuario directamente).
- Confirmado con Michel (Octupus): nunca usarán `/v1/relay/*`, gestionan su propio LLM directamente — la protección de la respuesta de su LLM requiere `protect-output`, activado explícitamente por pipeline.

## Bloqueantes

- Ninguno confirmado activo. Pendiente de verificación por el usuario: que `generate-dpo-report` funcione sin más errores tras el tercer arreglo.

## Próximos pasos

1. Confirmar con el usuario que "Generar ahora" en Informes DPO ya no da error.
2. Seguimiento de la respuesta de Octupus/Michel sobre activar `protect-output`.
3. Reunión pendiente con Ricardo Mora (Aelis) — explorar si implementan Sage Copilot con datos sensibles sin gobernanza, mismo patrón que abrió la puerta con Octupus.
4. Evaluar si se envía la nota técnica al Laboratorio de Privacidad de la AEPD (borrador y diagrama ya preparados, pendiente de decisión final del usuario).
5. `TOKEN_PREFIX` duplicado en 4 archivos — refactorizar a un solo origen compartido cuando haya ocasión (no urgente).

## Contexto importante

- Repos activos: `privaro-proxy` (backend, Railway), `privaro-7938a3bd` (frontend, Supabase Edge Functions + Lovable).
- Patrón de auth interno consolidado: `verify_api_key_or_internal` (secreto compartido `X-Internal-Secret`+`X-Internal-Org-Id`) es el estándar para llamadas servidor-a-servidor; varios routers todavía usaban `verify_api_key_or_dev` y se fueron migrando según se encontraban (agent.py, relay.py ya migrados).
- Miguel (usuario) y Lovable han estado hasciendo cambios en paralelo sobre los mismos archivos varias veces en esta sesión (ej. `generate-dpo-report`, `usage-alerts`) — before touching any Edge Function, hacer `git pull`/`git fetch --unshallow` primero para no pisar trabajo remoto reciente.
- Token de GitHub vigente: el que empieza por `ghp_KQ2oOl...` (el anterior, `ghp_HJizl9...`, quedó invalidado a mitad de sesión).
- iBS (certificación blockchain) corre en Fantom Opera/Gnosis, elegido por volumen alto; distinto del patrón que usan terceros como BDO Evidence (OpenTimestamps sobre Bitcoin, para evidencia forense puntual, no volumen).

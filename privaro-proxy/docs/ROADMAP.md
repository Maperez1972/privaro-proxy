# Privaro — Roadmap de mejoras del proxy/API (partners)

**Última actualización:** 23 de julio de 2026

Origen: pensando en las necesidades reales de Octupus/Robin AI al integrar Privaro en producción — qué podía romperse o quedarse corto en su caso de uso real (chat en tiempo real, volumen variable, reintentos), no una lista de deseos abstracta.

---

## Estado por punto

| # | Punto | Estado | Referencia |
|---|---|---|---|
| 1 | Sin soporte de streaming | ✅ Cerrado | `f5c17c3` — `POST /v1/relay/stream`, toggle `streaming_enabled` |
| 2 | Sin modo degradado ante fallo | ✅ Cerrado | `243b50c` — fail-open con timeout, evento `degraded_bypass` auditado |
| 3 | Sin timeout máximo garantizado | ✅ Cerrado | Mismo commit que el punto 2 (`PROTECT_TIMEOUT_SECONDS`) |
| 4 | Coherencia multi-turno | ✅ Cerrado | `779a518` — dos bugs reales encontrados y corregidos (ver abajo) |
| 5 | Idempotencia en reintentos | ✅ Cerrado | `475dcc1` — cabecera `Idempotency-Key` |
| 6 | Alta de clientes vía API | ✅ Cerrado | `b4cee85` — `POST /v1/partner/sub-accounts`, permiso `partner:write_children` |
| 7 | Detector regex → NER/ML | ✅ Cerrado (hallazgo, no desarrollo) | `09a69ba` — ver nota abajo |
| 8 | Sync de descuento Supabase↔Stripe | ✅ Cerrado (aviso, no automatización completa) | Migración `notify_on_discount_phase_review` |
| 9 | Página de estado pública | 🔲 Prompt de Lovable entregado, pendiente de desplegar | — |
| 10 | Latencia multi-región (LatAm) | ⏸️ Pospuesto — clientes de Octupus son de España, no aplica hoy | — |
| 11 | Contabilidad de consumo por cliente | 🔲 Backend + 3 pantallas entregadas, pendiente de verificación real | Ver sección propia abajo |

---

## Notas relevantes por punto

### 7 — Detector NER (hallazgo, no desarrollo)

El health check (`/health`) llevaba tiempo devolviendo `"detector": "regex-v1"` de forma **hardcodeada**, sin comprobar nada real. Al investigar, se descubrió que **Microsoft Presidio + spaCy (`es_core_news_md`) ya estaba completamente implementado** (`app/services/nlp_engine.py`, con filtros de falsos positivos maduros: listas de términos legales/financieros en mayúsculas, exigencia de ≥2 palabras capitalizadas consecutivas para `full_name`), correctamente instalado en el `Dockerfile`, y **funcionando en producción** — solo que nadie lo sabía porque el reporte de estado mentía.

Confirmado con una prueba real: el texto *"...hablar con Maria Fernandez Lopez sobre..."* (sin ningún patrón regex reconocible) se detectó correctamente como `full_name` con `detector: "presidio"`.

Arreglado: `/health` ahora comprueba `nlp_engine.is_available()` de verdad, devolviendo `"regex-v1+presidio-nlp"` cuando Presidio carga correctamente.

### 8 — Aviso de descuento (no reemplaza el cambio manual)

`apply_discount_reviews()` (pg_cron) dispara un email real (vía `pg_net` → `send-usage-notification`, `type=discount_phase_reviewed`) a `soporte@icommunity.io` en el momento exacto en que un `billing_account` pasa de fase inicial a revisada. **El cambio real del cupón en Stripe (`PARTNER20`→`PARTNER15`) sigue siendo manual** — esto solo garantiza que nadie se olvide.

### 4 — Coherencia multi-turno (dos bugs reales encontrados)

1. `find_existing_token` comparaba por el valor **cifrado** (AES-256-GCM con nonce aleatorio) — el mismo dato en texto plano nunca produce el mismo cifrado dos veces, así que la "reutilización de tokens entre turnos" **nunca había funcionado**, ni siquiera en `/v1/proxy/protect`. Arreglado con un hash SHA-256 determinista (`tokens_vault.original_value_hash`).
2. `audit_logs.conversation_id` y `tokens_vault.conversation_id` tenían una foreign key obligatoria hacia la tabla interna `conversations` (del chat de demo de Privaro) — cualquier partner que mandara su propio id de conversación habría recibido un 500. Eliminadas ambas FKs.

Extendido a `/v1/relay/complete` y `/v1/relay/stream`, que antes no tenían ninguna consistencia de tokens en absoluto.

---

## Punto 11 — Contabilidad de consumo por cliente (detalle)

**Motivación:** `billing_accounts.requests_used` es un contador agregado — un partner con 5 clientes no podía saber cuánto había consumido cada uno individualmente, solo el total conjunto.

**Backend (desplegado y probado con dry-run):**
- Nueva tabla `org_usage_monthly` (org_id, cycle_start, requests_used) — un contador independiente por organización y ciclo de facturación.
- `increment_billing_requests()` ahora incrementa este contador en la misma transacción que el agregado, sin coste adicional de latencia.
- `profiles.is_platform_admin` (boolean) — flag global para ver todas las organizaciones, deliberadamente independiente del sistema de roles por organización (admin/dpo/developer/viewer), ya que ninguno de esos roles cruza organizaciones por diseño.
- Nueva Edge Function `platform-admin-overview` — lista TODAS las organizaciones con su plan y consumo real, gateada por el flag anterior.
- `partner-sub-accounts` (GET) extendida con `requests_used_this_month` por sub-account.
- Política RLS añadida en `org_usage_monthly` (`get_user_org_id(auth.uid())`, mismo patrón que el resto del proyecto) — sin ella, el `GRANT SELECT` a `authenticated` habría sido inerte (RLS estaba activo sin ninguna política, bloqueando todo por defecto).

**Hallazgo real en el camino:** `AdminBilling.tsx` (la pantalla de facturación de cualquier cliente) llevaba tiempo leyendo de `org_settings` — una tabla desconectada del sistema de cuota real desde que se construyó el modelo de partners. Es decir, **todos los clientes veían un número de consumo sin relación con la realidad**. Corregido para leer de `billing_accounts` + `org_usage_monthly`.

**Frontend (desplegado por Lovable, código verificado, pendiente de prueba real en navegador):**
- `AdminBilling.tsx`: plan/consumo desde `billing_accounts`; si la org es `sub_account`, tarjeta adicional "Tu consumo este mes" desde `org_usage_monthly`.
- `PartnerClients.tsx` ("Mis clientes"): columna "Consumo este mes" por cliente.
- `PlatformAdmin.tsx` (`/app/platform-admin`, nueva pantalla): tabla de todas las organizaciones, filtrable/ordenable, solo visible si `is_platform_admin=true`.

**Pendiente:** verificación real en navegador por Miguel Ángel (las tres pantallas).

---

## Filosofía de esta sesión de trabajo

Varios de estos puntos empezaron como "vamos a construir X" y terminaron siendo "X ya existía / estaba roto de una forma distinta a la esperada". El patrón que ha funcionado en todos los casos: **verificar contra el código y los datos reales antes de dar nada por bueno** — con dry-runs SQL antes de desplegar, pruebas end-to-end reales antes de cerrar un punto, y desconfianza sana hacia cualquier descripción de cambio ("hecho") que no se haya verificado directamente contra el repo o la base de datos.

### Aprendizaje añadido — CI del SDK de JS (23 de julio de 2026)

El caso del fallo de CI en Node 18 (`privaro-sdk-js`) es un ejemplo claro de este mismo patrón aplicado a tests: costaron **tres intentos** encontrar la causa real, y los dos primeros fueron razonamientos plausibles pero incompletos:

1. Primer diagnóstico: `ReadableStream` inestable en Node 18 — **correcto como hallazgo, pero no era la causa del fallo real**.
2. Segundo diagnóstico: `globalThis.crypto` no existe en Node 18 sin flag — **correcto, pero el arreglo (`shims: true` en tsup) solo protegía el código YA COMPILADO**, no el código fuente que Jest ejecuta directamente en los tests.
3. Causa real, solo visible con el log completo del job (no con el resumen de GitHub ni con razonamiento por deducción): `import.meta.url` chocaba con la configuración de `ts-jest` del propio proyecto.

**Lo que evitó un cuarto intento a ciegas**: escribir un test que **fuerza explícitamente** la rama de código que llevaba fallando (borrando `globalThis.crypto` temporalmente durante el test), en vez de confiar en que "debería funcionar" porque el razonamiento parecía sólido. Cada test de la suite corría en un entorno (Node 22 local) donde esa rama de fallback nunca se ejercitaba de verdad — así que "todos los tests pasan" no era evidencia real de que el fallback funcionara.

**Regla general para el futuro**: cuando el código tiene una rama de fallback/compatibilidad (para una versión antigua, un entorno degradado, un fallo esperado), **el test debe forzar esa rama activamente**, no limitarse a probar el camino feliz en el entorno de desarrollo actual. Si una rama nunca se ejercita en los tests, "pasa el CI" no es garantía de que funcione en el entorno real donde sí se necesita.

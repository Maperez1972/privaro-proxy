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
| 9 | Página de estado pública | ✅ Cerrado — verificado en producción (`https://privaro.ai/status` responde 200) | — |
| 10 | Latencia multi-región (LatAm) | ⏸️ Pospuesto — clientes de Octupus son de España, no aplica hoy | — |
| 11 | Contabilidad de consumo por cliente | ✅ Cerrado — verificado en navegador, 2 bugs reales encontrados y corregidos en el proceso | Ver sección propia abajo |

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

**✅ Verificado en navegador (24 de julio de 2026), las tres pantallas — y se encontraron dos bugs reales en el proceso:**

1. **Platform Admin**: confirmado con datos reales. De paso, se encontró y borró un registro huérfano de una prueba anterior ("Octopus", sub_account de Partner Demo sin uso real).
2. **Mis clientes**: confirmado — Cliente A mostró "3", Cliente B "2", coincidiendo con tráfico de prueba generado para la ocasión.
3. **Billing (vista de sub_account)**: aquí aparecieron los dos bugs reales:
   - `billing_accounts` tenía RLS activo **sin ninguna política** (igual que `org_usage_monthly` antes) — el GRANT a nivel de tabla no servía de nada sin una policy, así que la tarjeta "Consumo agregado del partner" llevaba mostrando **0/0 para absolutamente cualquier organización**, no solo sub_accounts, desde que se arregló el GRANT original. Arreglada con la misma política (`get_user_org_id(auth.uid())`) usada en `org_usage_monthly`.
   - `AdminBilling.tsx` calculaba el "ciclo actual" con `new Date()` (la fecha de HOY, truncada al mes) en vez de leer `billing.billing_cycle_start` — la tarjeta "Tu consumo este mes" buscaba siempre en el mes calendario en curso, nunca en el ciclo de facturación real de la cuenta. Arreglado por Lovable para derivar `cycleStart` del dato real.

Método de verificación: en vez de crear cuentas de admin nuevas para Cliente A/B (sin herramienta de creación de usuarios disponible), se reasignó temporalmente el usuario de prueba ya existente (`maperez+partnerdemo@icommunity.io`) a la organización de Cliente A vía SQL directo (`profiles.org_id` + `user_roles.org_id`), y se revirtió a Partner Demo al terminar.

---

## Filosofía de esta sesión de trabajo

Varios de estos puntos empezaron como "vamos a construir X" y terminaron siendo "X ya existía / estaba roto de una forma distinta a la esperada". El patrón que ha funcionado en todos los casos: **verificar contra el código y los datos reales antes de dar nada por bueno** — con dry-runs SQL antes de desplegar, pruebas end-to-end reales antes de cerrar un punto, y desconfianza sana hacia cualquier descripción de cambio ("hecho") que no se haya verificado directamente contra el repo o la base de datos.

### Hallazgo de seguridad real — fuga de leads comerciales (24 de julio de 2026)

`demo_requests` (leads del formulario público — nombre, email, empresa, sector, cargo, necesidad expresada) tenía una política RLS que permitía leer **todos los leads** a **cualquier usuario `authenticated` con rol `admin` o `dpo` en cualquier organización**, sin ningún filtro de organización. Es decir: cualquier admin de cualquier cliente o partner (Partner Demo, futuros sub-accounts de Octupus, etc.) podía leer el pipeline comercial completo de iCommunity Labs.

Encontrado y arreglado desde el frontend (Lovable) + backend en la misma sesión:
- **Frontend**: nueva ruta protegida (`PlatformAdminRoute`, redirige si no eres superadmin), enlace del sidebar "Leads" condicionado a `profile.is_platform_admin`, y `AdminLeads.tsx` no consulta la tabla si el usuario no es platform admin — triple capa, verificada directamente contra el código del repo.
- **Backend**: política RLS reemplazada por una restringida a `profiles.is_platform_admin` (vía función `is_platform_admin(uuid)` reutilizable, mismo patrón que `get_user_org_id()`). Verificado con datos reales: `true` para el superadmin, `false` para admins de Octupus/Partner Demo — el hueco real queda cerrado.
- Los inserts desde `send-demo-request` no se ven afectados — confirmado que usa `SUPABASE_SERVICE_ROLE_KEY`, que bypasea RLS.

### Segundo escaneo — 5 hallazgos, 3 falsos positivos + 2 críticos nuevos reales (24 de julio de 2026)

Lovable volvió a reportar 5 críticos, 3 de los cuales resultaron ser **el mismo escaneo desactualizado** (los 3 hallazgos ya cerrados en la ronda anterior: `retention-cleanup`, `chat-completion`, `VITE_PROXY_API_KEY`) — confirmado contra el código real desplegado (versiones 9, 13 y el repo actual respectivamente, todos con el arreglo presente). No se tocó nada de estos tres, ya estaban bien.

Los 2 hallazgos nuevos eran reales y graves:

1. **`send-email-resend` sin verificación de firma**: el Auth Hook de "enviar email" no verificaba en absoluto que la petición viniera de Supabase — cualquiera que conociera la URL podía hacer que Privaro enviara un email con marca oficial a cualquier dirección, con enlaces/códigos elegidos por el atacante (phishing usando el propio dominio de Privaro). Arreglado con el patrón oficial de Supabase (`standardwebhooks`, verificación HMAC de los headers `webhook-id`/`webhook-timestamp`/`webhook-signature`). **Requiere que Miguel configure el secreto `SEND_EMAIL_HOOK_SECRET`** (generado desde Supabase Dashboard → Authentication → Hooks → Send Email) antes de desplegar el código — de lo contrario se cortaría el envío de todos los emails de autenticación. Código listo, pendiente de coordinar el despliegue.

2. **`reveal-token` permitía descifrar PII de cualquier organización**: cualquier admin/dpo (de cualquier organización) podía descifrar el valor real de un token del vault (nombres, DNIs, IBANs) de otra organización con solo conocer su `token_id` — la comprobación de rol no estaba scoped por organización, y la búsqueda del token tampoco verificaba su `org_id`. Arreglado con el mismo patrón usado en el resto de hallazgos de hoy (resolver `org_id` real vía `profiles`, exigir coincidencia antes de descifrar). Desplegado (v20).

### Auditoría de seguridad — 3 hallazgos CRÍTICOS (24 de julio de 2026)

Tras el escaneo anterior (4 warnings), un segundo escaneo de Lovable encontró 3 hallazgos marcados como **crítico**, los tres reales y confirmados contra el código/datos reales antes de arreglar:

1. **`retention-cleanup` sin ninguna autenticación**: `verify_jwt=false` y sin ningún check de secreto en el código — cualquiera con la URL podía disparar el job destructivo (revoca tokens, anonimiza audit_logs, borra detecciones PII/mensajes/informes DPO) para **todas** las organizaciones, repetidamente. Arreglado con el mismo patrón de `X-Internal-Secret` usado en otros sitios; actualizado el cron diario (`pg_cron` + `pg_net`) para enviarlo.

2. **`chat-completion` permitía usar el pipeline de otra organización**: el `pipeline_id` venía del cliente sin verificar que perteneciera a la organización real del usuario — cualquier autenticado que conociera/adivinara el `pipeline_id` de otra organización podía correr chats a través de él, usando la clave LLM real descifrada de esa organización ajena. Arreglado resolviendo el `org_id` real del caller y exigiendo que coincida con el del pipeline (404, no 403, para no confirmar que el ID existe en otro sitio).

3. **API key de producción hardcodeada en el bundle del frontend** (`VITE_PROXY_API_KEY`): el chat principal del dashboard (`useChat.ts`), además de Onboarding y Sandbox, llamaban directamente al proxy desde el navegador con una clave real de producción (`"Lovable Production"`, perteneciente al propio pipeline "Legal Document Reviewer" de iCommunity Labs) embebida en el bundle — extraíble por cualquiera con las devtools, permitiendo consumir la cuota real de iCommunity Labs e inyectar audit_logs indefinidamente. Arreglado de punta a punta:
   - Dos Edge Functions nuevas (`protect-chat-message`, `proxy-bridge`) que verifican el JWT, resuelven el `org_id` y pipeline reales del caller (nunca cayendo a un pipeline fijo de otra organización), y llaman al proxy con el secreto interno compartido.
   - Extendido `/v1/proxy/protect` y `/v1/proxy/detect` (repo `privaro-proxy`) para aceptar este mecanismo como alternativa segura junto al camino normal de key real/dev — sin cambios para tráfico de partners/clientes reales.
   - `useChat.ts` y `proxy-client.ts` ahora llaman a estas Edge Functions en vez de al proxy directamente.
   - **La clave ya expuesta fue revocada en `api_keys`** (`is_active=false`) — seguía siendo válida hasta ese momento independientemente del arreglo de código.
   - De paso, se quitó un fallback relacionado: `useChat.ts` caía al `pipeline_id` fijo de iCommunity Labs para el registro de auditoría de cualquier organización sin pipeline activo propio.

**Pendiente manual**: quitar la variable de entorno `VITE_PROXY_API_KEY` de la configuración de build de Lovable — ya no se lee en ningún sitio del código, pero conviene borrarla para que no pueda reintroducirse por accidente. No pude probar el flujo end-to-end completo yo mismo (`api.privaro.ai` no está en mi lista de dominios permitidos) — pendiente de una prueba real del chat/sandbox/onboarding.

### Auditoría de seguridad — 4 hallazgos de Lovable + 2 adicionales (24 de julio de 2026)

Lovable reportó 4 avisos de seguridad tras un escaneo. Se revisó cada uno contra el código real antes de decidir si merecía arreglo — dos resultaron ser código sin desplegar (sin riesgo activo), uno de impacto real bajo, y uno grave y confirmado:

1. **MCP público sin autenticación** (`mcp` edge function): revisado a fondo — las 11 herramientas expuestas son todas de solo lectura, sin acceso a datos de clientes ni a la base de datos real; el motor de detección PII es una réplica en JS que solo procesa el texto que el propio llamante envía, y el resto es información pública de marketing. **Decisión final de Miguel: dejarlo público, es intencional** — gancho de marketing (endpoint de evaluación del motor PII), no expone nada de tenants. Marcado como ignorado en el scanner de Lovable, decisión documentada. Sugerencia pendiente y opcional para el futuro: rate limiting básico por IP si preocupa el abuso de cómputo, y documentar en las `instructions` del propio MCP que es un endpoint público de evaluación.
2. **Email enumeration en `invite-user`**: ✅ Cerrado — Miguel arregló el código desde Lovable (quitó el `listUsers()`, ahora se apoya en el error genérico nativo de `inviteUserByEmail`). Al revisar antes de desplegar, se encontró y arregló también el mismo patrón de "falta scope de organización en la comprobación de rol admin" que ya había aparecido en `demo_requests`/`generate-dpo-report`/`enforce-mfa` — como era el primer despliegue real de esta función (nunca había estado en producción), se arregló en el mismo movimiento sin riesgo de romper nada existente. Desplegada por primera vez (v1→v2).
3. **Errores internos crudos expuestos** (`err.message` devuelto directamente al cliente): confirmado en 7 funciones (`byok-admin`, `chat-completion`, `enforce-mfa`, `generate-dpo-report`, `protect-document`, `recertify-pending`, `send-email-resend`). Arreglado de forma consistente: se sigue logueando el error completo internamente, pero el cliente recibe siempre un mensaje genérico.
4. **Mutación cross-tenant en `send-welcome-email`**: confirmado y grave — cualquier usuario autenticado (cualquier org, cualquier rol) podía marcar `welcome_email_sent`/`trial_started_at` de una organización ajena, sin ninguna comprobación de propiedad del `org_id`. Arreglado comparando contra `profiles.org_id` real del llamante.

**Hallazgo adicional, no reportado por Lovable**, encontrado al revisar `generate-dpo-report` de cerca por el mismo patrón: la comprobación de rol admin no verificaba que fuera admin **de la organización solicitada**, solo que fuera admin de alguna organización — cualquier admin podía generar y leer el informe DPO de auditoría (metadatos de detección de PII, risk scores, hashes de blockchain) de una organización ajena. Arreglado y verificado contra el único caso de uso real del frontend (`ScheduledReports.tsx`, que siempre pasa `profile.org_id`).

**Detalle menor, no arreglado (nota para el futuro)**: `recertify-pending` autentica comparando un fragmento del propio `SUPABASE_SERVICE_ROLE_KEY` con `.includes()` — funciona pero es un patrón débil; no se tocó para no romper cómo se invoca desde el cron sin confirmarlo antes.

### Aprendizaje añadido — CI del SDK de JS (23 de julio de 2026)

El caso del fallo de CI en Node 18 (`privaro-sdk-js`) es un ejemplo claro de este mismo patrón aplicado a tests: costaron **tres intentos** encontrar la causa real, y los dos primeros fueron razonamientos plausibles pero incompletos:

1. Primer diagnóstico: `ReadableStream` inestable en Node 18 — **correcto como hallazgo, pero no era la causa del fallo real**.
2. Segundo diagnóstico: `globalThis.crypto` no existe en Node 18 sin flag — **correcto, pero el arreglo (`shims: true` en tsup) solo protegía el código YA COMPILADO**, no el código fuente que Jest ejecuta directamente en los tests.
3. Causa real, solo visible con el log completo del job (no con el resumen de GitHub ni con razonamiento por deducción): `import.meta.url` chocaba con la configuración de `ts-jest` del propio proyecto.

**Lo que evitó un cuarto intento a ciegas**: escribir un test que **fuerza explícitamente** la rama de código que llevaba fallando (borrando `globalThis.crypto` temporalmente durante el test), en vez de confiar en que "debería funcionar" porque el razonamiento parecía sólido. Cada test de la suite corría en un entorno (Node 22 local) donde esa rama de fallback nunca se ejercitaba de verdad — así que "todos los tests pasan" no era evidencia real de que el fallback funcionara.

**Regla general para el futuro**: cuando el código tiene una rama de fallback/compatibilidad (para una versión antigua, un entorno degradado, un fallo esperado), **el test debe forzar esa rama activamente**, no limitarse a probar el camino feliz en el entorno de desarrollo actual. Si una rama nunca se ejercita en los tests, "pasa el CI" no es garantía de que funcione en el entorno real donde sí se necesita.

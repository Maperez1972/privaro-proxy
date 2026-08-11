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

### Ronda de pruebas en vivo — 4 bugs reales encontrados y arreglados (24 de julio de 2026)

Tras construir las 4 capacidades nuevas (arriba), se probaron en producción real con datos reales (clave de prueba generada para iCommunity Labs, pipeline "Legal Document Reviewer"). El proceso de prueba en sí sacó a la luz **4 bugs reales**, ninguno de ellos hipotético:

1. **`money`, `field_name_pattern` y detección normal**: confirmados funcionando correctamente a la primera.

2. **Acción "block" ignorada en peticiones parciales**: una regla de política preexistente en el pipeline (bloquear `health_record`, prioridad 1) se evaluaba correctamente por el motor de políticas (visible en los logs: `action=block`), pero el código de tokenización nunca contemplaba el caso "blocked" — caía en un `else` que lo tokenizaba de todas formas. Bug preexistente en `/protect` (no introducido hoy), nunca antes ejercitado porque nunca había habido una regla de bloqueo real configurada en un pipeline con detecciones mixtas. Arreglado: ahora genera `[BLOCKED:TIPO]` sin token, y el guardado en `tokens_vault` lo omite correctamente.

3. **Pérdida real de contenido — el patrón `full_name` se comía la siguiente palabra**: `"cliente Juan García Ruiz tiene un saldo..."` perdía la palabra "tiene" en el texto protegido. Causa raíz: `re.IGNORECASE` aplicado a *todo* el patrón regex (incluida la palabra clave disparadora Y el grupo de captura del nombre) anulaba por completo la exigencia de mayúscula inicial — bajo IGNORECASE, `[A-Z...]` también coincide con minúsculas, así que el patrón podía extender la captura a palabras minúsculas siguientes. Bug preexistente desde que se escribió el patrón, no introducido hoy — solo salió a la luz porque la frase de prueba tenía justo esta estructura. Arreglado limitando `IGNORECASE` a la palabra clave únicamente (`(?i:...)` inline), dejando el grupo del nombre genuinamente sensible a mayúsculas. De paso se arregló también un problema similar (aunque menos grave) en el motor Presidio/NLP, que tampoco recortaba el span tras su propio filtro de validación.

4. **`/detokenize` podía devolver el valor equivocado**: al revertir `[NM-0001]`, devolvió "Ana Pérez" en vez de "Juan García Ruiz". Causa raíz confirmada con datos reales: `token_value` no es único dentro de una organización a lo largo del tiempo — es solo un contador que reinicia en cada llamada a `/protect`. Se encontraron **47 filas** distintas con el literal `[NM-0001]` para la misma organización, acumuladas desde marzo. Arreglado añadiendo `conversation_id` (opcional pero fuertemente recomendado) para desambiguar con precisión, con un fallback de "mejor esfuerzo" (fila más reciente) documentado cuando no se proporciona.

Todos los arreglos verificados con pruebas reales end-to-end tras cada despliegue, no solo compilación. Ninguno de estos 4 bugs se habría encontrado sin probar contra producción real con datos reales — la disciplina de "no dar nada por bueno sin verificarlo" se demostró valiosa una vez más.

**Cierre final del hallazgo #4** (a petición explícita, tras confirmar que el arreglo original — recomendar `conversation_id` — no eliminaba el riesgo del todo): `conversation_id` pasó de "recomendado" a **obligatorio** allí donde genera ambigüedad real — `/protect` cuando `options.reversible=true` (el valor por defecto), y siempre en `/detokenize`/`/protect-structured` (que no tienen modo no-reversible). Se dejó deliberadamente opcional en `/relay/complete`/`/relay/stream`, tras verificar que su guardado en vault ya depende silenciosamente de ese campo hoy (`if conversation_id and enc_key:`) — sin él simplemente no persiste nada, así que no hay riesgo de ambigüedad, solo la limitación conocida de "no será reversible más tarde". Hacerlo obligatorio ahí habría sido un cambio disruptivo sin beneficio de seguridad correspondiente, dado que Octupus está integrando activamente ahora mismo. De paso se corrigió una afirmación incorrecta preexistente en la documentación (decía que el campo era "completamente libre" — en realidad siempre ha tenido que ser un UUID válido para la columna de Postgres).



## Nuevas capacidades a raíz del análisis de Octupus/Robin AI (24 de julio de 2026)

Análisis en profundidad de robin-ia.com (producto, seguridad, FAQ) para identificar mejoras de Privaro relevantes para el caso de uso real de un copiloto de IA dentro de Odoo. Se priorizaron los dos hallazgos con evidencia más sólida (verificados contra el código real del detector, no solo especulación):

1. **Tipo de entidad `money`**: la propia web de seguridad de Robin muestra un ejemplo de tokenización que incluye un importe de facturación junto a PII clásica — su concepto de "sensible" incluye datos comercialmente confidenciales, no solo PII bajo RGPD. Confirmado que el detector no tenía ningún tipo `MONEY`/`AMOUNT`. Añadido, categorizado como `financial` (no `personal`) y con peso bajo en el risk_score para no contaminar las métricas orientadas a RGPD. Patrón probado exhaustivamente contra falsos positivos y contra el propio ejemplo textual de Robin (que inicialmente fallaba por un problema de `\b` con el símbolo `€`, corregido).

2. **`custom_pattern` de `policy_rules`, completado**: existía en el esquema desde hace tiempo sin usarse en ningún sitio del código — infraestructura preparada y olvidada. Ahora se integra como "Tier 1.5" en el detector, permitiendo que cada cliente final de Octupus (un despacho con su propio formato de expediente, una clínica con su propia codificación de historia clínica) extienda la taxonomía sin necesitar ingeniería de Privaro. Requirió reordenar `/protect` y `/detect` para cargar las políticas antes de la detección (antes se cargaban después).

3. **`POST /v1/proxy/detokenize`**: reversión automática en bulk de todos los tokens presentes en un texto, pensado para flujos agénticos con function-calling (el LLM decide escribir un registro real en Odoo a partir de datos que solo vio tokenizados) — a diferencia de `reveal-token`, que es un flujo humano con contraseña, uno a uno. Aplicada desde el diseño la misma disciplina de scope por organización que costó arreglar hoy en `reveal-token` (`get_tokens_by_values` filtra explícitamente por `org_id`).

4. **`POST /v1/proxy/protect-structured`**: protección consciente de campos con nombre (no solo texto libre), con una nueva columna `policy_rules.field_name_pattern` que reutiliza toda la infraestructura de scope/prioridad ya existente. Permite forzar el tipo de entidad de un campo por su nombre (ej. cualquier campo `diagnostico` se trata siempre como dato de salud, independientemente de si el contenido coincide con algún patrón de texto libre) — más preciso que intentar NER médico genérico, que requeriría un diccionario extenso que no existe hoy.

**Estado de verificación**: todo compila limpio (`py_compile` en cada archivo tocado). La lógica central del detector (patrón `money`, `custom_pattern`, selección de reglas por nombre de campo) se probó de forma aislada con casos reales, con resultados correctos. El endpoint `/protect-structured` en sí **no se ha probado con una llamada real end-to-end** — sus dependencias (Supabase REST, servicio de quota) no son mockeables desde este entorno. Pendiente de una prueba real antes de darlo por completamente verificado. Tampoco se ha podido confirmar el despliegue en Railway directamente (`api.privaro.ai` no está en la lista de dominios accesibles desde aquí).

Documentado en `PARTNER_API_REFERENCE.md` (v2) para que Octupus pueda descubrir y usar estas capacidades.

---



## Análisis en profundidad #2 — necesidades reales de Octupus/Robin con Odoo (24 de julio de 2026)

Continuación del análisis inicial (arriba), esta vez centrado en qué módulos concretos de Odoo podría estar usando Robin y qué huecos reales de producto emergen de ahí.

**Cerrado hoy mismo**: `field_name_pattern` (la funcionalidad de protección por nombre de campo, construida en la sesión anterior) no tenía ninguna interfaz de configuración — solo se podía dar de alta por SQL directo, que es como lo probé yo mismo para la demo de `health_record`/`diagnostic`. Construida la pantalla de autoservicio en `Policies.tsx`/`PolicyDialog.tsx`, replicando el patrón ya existente para `custom_pattern`, con la distinción explicada en la propia UI: `custom_pattern` filtra por contenido del mensaje (solo tiene sentido para el tipo "custom"), `field_name_pattern` filtra por el nombre del campo estructurado y funciona con cualquier tipo de entidad — tal como se demostró en la prueba real de hoy (`entity_type: health_record` + `field_name_pattern: diagnostic`, un tipo *ya existente*, no uno personalizado).

**Preguntas enviadas a Octupus** (por email, pendientes de respuesta) para priorizar qué construir después con base en su uso real, no en suposiciones:
1. ¿Robin da acceso a datos de RRHH/nóminas, o el uso es sobre todo cara al cliente?
2. ¿Usan el módulo de Selección/Reclutamiento? (datos de candidatos, retención distinta a la de clientes/empleados)
3. ¿La política de protección debería variar según qué usuario de Odoo pregunta, no solo por organización/pipeline?
4. ¿Tienen flujos donde Robin actúa disparado automáticamente por Odoo (sin humano escribiendo), y cómo gestionan el identificador de sesión en esos casos? — relevante dado que hoy hicimos `conversation_id` obligatorio para peticiones reversibles, un concepto pensado para sesiones humanas.
5. ¿Operan o tienen previsto operar fuera de España? (la detección hoy está orientada a formatos españoles — DNI, teléfono ES)

**Hallazgo arquitectónico propio, no dependiente de la respuesta de Octupus — derecho al olvido / supresión RGPD por persona**: hoy no existe ninguna forma de decir "borra todos los tokens que existen sobre esta persona concreta" en `tokens_vault`. Cada token se vincula a un valor original por el hash de su cadena de texto EXACTA (`original_value_hash`), no por una identidad de persona real — así que si "Juan Pérez" aparece tokenizado en 10 conversaciones distintas con ligeras variaciones de formato ("Juan Pérez", "D. Juan Pérez García", etc.), no hay ningún vínculo entre esas 10 filas que permita purgarlas todas de una vez ante una solicitud de supresión real. Hoy la única purga posible es por organización + antigüedad (`retention-cleanup`, arreglado hoy) o por tipo de entidad — nunca por persona específica. Dado el volumen de PII que procesa un ERP como Odoo (mucho más alto que un chat simple), esto podría convertirse en un problema real de cumplimiento si un cliente de Octupus recibe una solicitud de supresión GDPR sobre un individuo concreto. No es urgente hoy, pero es un rediseño de fondo (requeriría algún tipo de índice/vínculo por persona, no solo por hash de valor exacto) que vale la pena tener en el radar antes de que escale el volumen de uso.



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

## Aviso de consumo — de papel mojado a automático (27 de julio de 2026)

Pregunta real de Miguel al revisar la documentación del template de n8n: si el modelo de cuota es "soft-cap" (nunca bloquea peticiones al superar el plan), ¿cómo se entera él o el cliente de que lo ha superado?

Verificado: el mecanismo de notificación (`usage_threshold` 80% / `usage_overage` 100%, en `quota.py`/`send_usage_notification`) existe en el código desde hace tiempo, pero depende de una fila de configuración manual en `org_notifications` por organización — y **solo 2 organizaciones la tenían configurada** (iCommunity Labs, sin `usage_overage`; y Partner Demo, el sandbox). **Octupus —el único partner real activo— no tenía nada.** Si superaba su plan, nadie se enteraba: ni el cliente, ni Miguel.

Decisión de mantener el soft-cap tal cual (no cambiar a bloqueo duro tipo OpenAI/Anthropic) — coherente con cómo operan otras infraestructuras B2B críticas (Twilio, SendGrid): cortar producción de un partner activo por unas peticiones de más sería más dañino para la relación comercial que el coste de esas peticiones.

Arreglado el problema real (que el aviso nunca llegaba a nadie), no el modelo de cuota:
- Trigger en `user_roles` (no en `organizations`, que no tiene columna de email de admin) que se dispara al asignar el primer rol admin a una organización, creando automáticamente `usage_threshold` + `usage_overage` con destinatarios = [email del admin] + [Miguel, como superadmin, en toda organización sin excepción].
- Backfill ejecutado para todos los admins ya asignados antes de hoy — cubrió Octupus, completó el `usage_overage` que le faltaba a iCommunity Labs, añadió a Miguel a Partner Demo, y de paso configuró automáticamente una organización de prueba (Acme Corp) que ni siquiera se sabía que existía — confirma que el mecanismo cubre cualquier organización, no solo las conocidas explícitamente.



Varios de estos puntos empezaron como "vamos a construir X" y terminaron siendo "X ya existía / estaba roto de una forma distinta a la esperada". El patrón que ha funcionado en todos los casos: **verificar contra el código y los datos reales antes de dar nada por bueno** — con dry-runs SQL antes de desplegar, pruebas end-to-end reales antes de cerrar un punto, y desconfianza sana hacia cualquier descripción de cambio ("hecho") que no se haya verificado directamente contra el repo o la base de datos.

### Regresión crítica del propio arreglo de hoy — fail-open en la protección de PII (24 de julio de 2026)

Al arreglar la clave hardcodeada (`VITE_PROXY_API_KEY`), el nuevo código de `useChat.ts` que llama a `protect-chat-message` **no comprobaba `res.ok`**. Cualquier respuesta de error de la Edge Function (pipeline borrado/inactivo, organización sin pipeline activo, `INTERNAL_NOTIFY_SECRET` no configurado) devuelve un JSON válido `{ error: "..." }` — que no lanza excepción en `fetch`, así que el `catch` nunca se activaba. Resultado: `protectedText` caía al texto **crudo sin proteger**, con `detections: []`, guardado en `conversation_messages` y registrado en `audit_logs` como `event_type: "request_clean"` — un falso negativo de cumplimiento en el propio producto cuyo propósito es demostrar protección de datos. El usuario no veía ningún error; su mensaje aparecía con normalidad.

Encontrado por un escaneo de seguimiento de Lovable, verificado línea por línea contra el código real antes de arreglar. Arreglado diferenciando dos escenarios: un error explícito del servicio de protección (`res.ok` falso) ahora bloquea el envío por completo con un aviso visible al usuario (`ProtectionServiceError`, capturado por separado); un fallo de red genuino (no llega a haber respuesta) sigue degradando al detector local (`mockProxyProtect`), igual que antes. Verificado que `proxy-client.ts` (usado por Onboarding/Sandbox) no tenía este mismo problema — sí comprobaba `res.ok`, y `Sandbox.tsx` además marca explícitamente `isMock: true` cuando cae al detector local, manteniendo la transparencia con el usuario que faltaba en `useChat.ts`.

**Lección**: un arreglo de seguridad (mover la protección al servidor) puede introducir una regresión funcional grave si no se revisa el manejo de errores con el mismo rigor que el propio hallazgo original — sobre todo en un producto cuyo valor central es, precisamente, la protección de datos.

### Hallazgo de seguridad real — fuga de leads comerciales (24 de julio de 2026)

`demo_requests` (leads del formulario público — nombre, email, empresa, sector, cargo, necesidad expresada) tenía una política RLS que permitía leer **todos los leads** a **cualquier usuario `authenticated` con rol `admin` o `dpo` en cualquier organización**, sin ningún filtro de organización. Es decir: cualquier admin de cualquier cliente o partner (Partner Demo, futuros sub-accounts de Octupus, etc.) podía leer el pipeline comercial completo de iCommunity Labs.

Encontrado y arreglado desde el frontend (Lovable) + backend en la misma sesión:
- **Frontend**: nueva ruta protegida (`PlatformAdminRoute`, redirige si no eres superadmin), enlace del sidebar "Leads" condicionado a `profile.is_platform_admin`, y `AdminLeads.tsx` no consulta la tabla si el usuario no es platform admin — triple capa, verificada directamente contra el código del repo.
- **Backend**: política RLS reemplazada por una restringida a `profiles.is_platform_admin` (vía función `is_platform_admin(uuid)` reutilizable, mismo patrón que `get_user_org_id()`). Verificado con datos reales: `true` para el superadmin, `false` para admins de Octupus/Partner Demo — el hueco real queda cerrado.
- Los inserts desde `send-demo-request` no se ven afectados — confirmado que usa `SUPABASE_SERVICE_ROLE_KEY`, que bypasea RLS.

### Tercer escaneo — hallazgo CRÍTICO más grave del día: gestión cruzada del cifrado maestro (24 de julio de 2026)

`byok-admin` reenviaba **toda** petición de gestión de claves de cifrado (BYOK) al proxy usando una **única clave admin global** (`PRIVARO_ADMIN_API_KEY`), sin importar qué organización llamara. Verificado con datos reales: esa clave pertenece a **iCommunity Labs** (`"Admin Key (BYOK)"`, org `d4e09279-...`). Como el proxy scopea cada endpoint de `/v1/admin/keys` por el `org_id` resuelto a partir de la clave usada para autenticar, esto significaba que **cualquier admin/dpo de cualquier organización cliente o partner que abriera la pantalla de gestión BYOK estaba en realidad viendo y gestionando las claves de cifrado de la propia iCommunity Labs** — pudiendo verlas, registrar una nueva y marcarla como default (potencialmente comprometiendo la confidencialidad de datos futuros de la propia plataforma), o desactivar la activa.

Es el hallazgo más grave de todos los de hoy: no es "un cliente ve datos de otro cliente", sino "cualquier cliente puede tomar el control del sistema de cifrado de la propia empresa que opera Privaro".

Arreglado en dos partes:
- **Proxy** (`byok.py`): los 4 endpoints (list/register/deactivate/set-default) extendidos a `verify_api_key_or_internal` (mismo patrón ya usado en `/v1/proxy/protect`/`/detect`). El modo interno ahora también incluye `admin`/`dpo` en sus permisos — seguro porque solo es alcanzable con el secreto compartido conocido exclusivamente por las Edge Functions propias, y cada una ya verifica el rol real del usuario antes de llegar aquí.
- **`byok-admin`**: resuelve el `org_id` real del caller vía `profiles`, escopea la comprobación de rol admin/dpo a esa organización, y autentica al proxy con el secreto interno en vez de la clave admin fija.

### Segundo escaneo — 5 hallazgos, 3 falsos positivos + 2 críticos nuevos reales (24 de julio de 2026)

Lovable volvió a reportar 5 críticos, 3 de los cuales resultaron ser **el mismo escaneo desactualizado** (los 3 hallazgos ya cerrados en la ronda anterior: `retention-cleanup`, `chat-completion`, `VITE_PROXY_API_KEY`) — confirmado contra el código real desplegado (versiones 9, 13 y el repo actual respectivamente, todos con el arreglo presente). No se tocó nada de estos tres, ya estaban bien.

Los 2 hallazgos nuevos eran reales y graves:

1. **`send-email-resend` sin verificación de firma**: el Auth Hook de "enviar email" no verificaba en absoluto que la petición viniera de Supabase — cualquiera que conociera la URL podía hacer que Privaro enviara un email con marca oficial a cualquier dirección, con enlaces/códigos elegidos por el atacante (phishing usando el propio dominio de Privaro). ✅ **Cerrado del todo** — arreglado con el patrón oficial de Supabase (`standardwebhooks`, verificación HMAC de los headers `webhook-id`/`webhook-timestamp`/`webhook-signature`), desplegado tras confirmar que `SEND_EMAIL_HOOK_SECRET` ya estaba configurado, y verificado con una prueba real (email de "olvidé mi contraseña" recibido correctamente) — confirma que la firma se valida bien contra el secreto real que usa Supabase, no solo que el código compila.

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

---

## Revisión proactiva del flujo de creación de sub-cuentas — 27 de julio de 2026

A raíz de que Octupus pidiera activar `partner:write_children` (para crear sub-cuentas por API, una por cada organización de su sistema), revisión completa del endpoint `POST /v1/partner/sub-accounts` antes de que empiecen a usarlo a volumen:

- **Facturación heredada del padre confirmada en código** (`billing_account_id = partner_org["billing_account_id"]`) — las notificaciones de consumo configuradas hoy para Octupus ya cubren automáticamente todas sus futuras sub-cuentas, sin acción adicional.
- **Sin usuario humano creado en este flujo** (solo organización + pipeline + clave) — el trigger de notificaciones de hoy nunca se dispara aquí, pero no es un problema real dado el punto anterior.
- **Hueco real encontrado**: no existe ningún endpoint para configurar el proveedor LLM (OpenAI/Anthropic/etc.) de una sub-cuenta recién creada, ni ningún mecanismo de herencia automática desde el padre (`chat-completion`/`relay` buscan `llm_providers` filtrando estrictamente por el `org_id` del propio pipeline, sin fallback). Esto contradice la propia promesa del comentario del código ("cero pasos manuales en la UI de Privaro") — sigue siendo un hueco real para cualquier partner que use `/v1/relay/complete`/`/relay/stream` (que sí necesita resolver una clave real para llamar al LLM en nombre del cliente).

  **Actualización 2026-07-28 — no bloquea a Octupus específicamente.** Confirmaron que no van a usar el relay en absoluto: su arquitectura permite que el cliente final elija cualquier LLM (no solo los que Privaro sabe llamar de forma nativa), así que montan su propio flujo `protect` → su propia llamada al LLM que sea → `detokenize`. Verificado en código: `/v1/proxy/protect` nunca necesita un proveedor configurado (`get_provider_trust` devuelve `None` sin romper nada, con valores por defecto sensatos vía `if provider_trust else "EU"`), y `llm_provider`/`llm_model` en el body de creación no tienen ninguna restricción de valores en la base de datos — les vale pasar cualquier texto arbitrario (ej. `"generic"`/`"n/a"`), ya que esos campos nunca se leen para resolver una clave real en su flujo. El hueco sigue siendo real para un futuro partner que sí quiera usar el relay — no se ha construido nada para cerrarlo de raíz, solo se confirmó que no afecta a este caso concreto.

Pendiente de la respuesta de Michel a una pregunta clave antes de construir nada: ¿cada cliente final de Octupus tiene su propia clave de proveedor LLM (facturación independiente), o Octupus gestiona una única clave compartida para todos? La respuesta determina si la solución es "heredar automáticamente la configuración del padre" o "añadir un campo al propio POST de creación para pasarla directamente".

---

## Auditoría funcional completa de la app — 2026-08-08

Motivada por: primer cliente real (Octupus) en producción + un cambio de Lovable (`chat-completion`) que resultó ser una vulnerabilidad crítica. Plan de 5 fases ejecutado en su totalidad.

### Fase 1 — Edge Functions (8 problemas reales, 3 críticos)

| Función | Hallazgo | Severidad |
|---|---|---|
| `chat-completion` | Enviaba mensajes reales sin proteger directamente a OpenAI/Anthropic; system prompt afirmaba falsamente que la PII ya estaba tokenizada | 🔴 Crítico |
| `revoke-token` | Cualquier admin/dpo de cualquier organización podía revocar el token de cualquier otra organización (mismo bug que `reveal-token` tenía antes del 24/07, pero nunca se replicó el arreglo aquí) | 🔴 Crítico |
| `proxy-bridge` | Modo `protect` siempre fallaba con 422 (`reversible: true` sin `conversation_id`) | 🟡 Funcional |
| `recertify-pending` | Usaba fragmento del `SERVICE_ROLE_KEY` real como contraseña propia, comparado con `.includes()` | 🟡 Mala práctica |
| `ibs-sync-cron` | Cero autenticación — cualquiera con la URL podía disparar llamadas de pago a la API de iBS repetidamente | 🟡 Denial of wallet |
| `encrypt-provider-key` | Resolvía la organización desde una fila `user_roles` arbitraria en vez de `profiles.org_id` — endurecido preventivamente | 🟢 Robustez |

Arreglo en `privaro-proxy`: `relay.py` ahora acepta el patrón `X-Internal-Secret`+`X-Internal-Org-Id` (antes solo `verify_api_key_or_dev`), necesario para que `chat-completion` pudiera enrutar por el proxy real en vez de llamar a los proveedores directamente. Además, `llm_router.py` tenía 2 bugs reales bloqueando cualquier llamada a modelos `o1/o3/gpt-5`: rechazaban `max_tokens` (necesitan `max_completion_tokens`) y cualquier `temperature` no-default.

### Fase 2 — RLS a nivel de base de datos (2 problemas reales, 1 crítico)

- **`profiles`** (el hallazgo más grave de toda la auditoría): la política de `UPDATE` solo comprobaba `id = auth.uid()`, sin ningún `with_check`. Combinado con permisos de columna reales para `authenticated` sobre `is_platform_admin` y `org_id`, **cualquier usuario autenticado podía auto-otorgarse acceso "platform admin" (ver todas las organizaciones) o cambiar su propio `org_id` para suplantar cualquier otra organización** en prácticamente todas las Edge Functions auditadas en la Fase 1. Arreglado con un trigger que fija ambas columnas a su valor anterior cuando la actualización viene de una sesión de usuario normal (no de `service_role`). Verificado con un ataque simulado real: bloqueado correctamente; las actualizaciones legítimas desde el backend siguen funcionando.
- **`conversations`**: mismo patrón — `UPDATE` solo comprobaba `user_id = auth.uid()`, permitiendo a un usuario cambiar el `org_id` de su propia conversación a cualquier valor. Arreglado con `WITH CHECK` explícito.
- **`retention_runs`**: la política de `SELECT` no filtraba por `org_id` en absoluto (aunque la columna existe) — cualquier admin/dpo podía ver el historial de limpieza de retención de todas las organizaciones. Scopeado correctamente.

### Fase 3 — Endpoints del proxy probados directamente

`/v1/proxy/detect`, `/protect`, `/protect-structured`, `/detokenize`, `/v1/relay/complete` y `GET /v1/partner/sub-accounts` probados con llamadas HTTP reales (no solo revisión de código) contra pipelines reales. Todos funcionan correctamente.

### Fase 4 — Consistencia de facturación (1 problema real)

`increment_billing_requests()` escribía `org_usage_monthly.cycle_start` truncado al primer día del **mes calendario**, mientras que todo el código que lee esa tabla (`partner-sub-accounts`, `usage-alerts`, ambos tocados hoy mismo) compara contra la fecha real de inicio del **ciclo de facturación** (`billing_accounts.billing_cycle_start`), que casi nunca cae el día 1. Las dos convenciones nunca coincidían, así que cualquier lectura de esa tabla devolvía siempre 0 — exactamente el síntoma original que se intentaba arreglar hoy ("la tabla del dashboard ya lo pintaba pero llegaba a 0"). Arreglada la función para escribir con la fecha real del ciclo; migradas las 2 filas del ciclo activo; verificado con una llamada real en producción (30 → 31).

### Fase 5 — Pendiente

Verificación cruzada frontend↔backend para el resto de pantallas de la app (más allá de Chat.tsx, ya cubierto en la Fase 1) — no ejecutada todavía en esta sesión.

---

## Output-direction PII detection — 2026-08-10

Motivado por: revisión estratégica de posicionamiento frente al estándar AIUC-1 (certificación de agentes de IA). Al mapear los 51 controles de AIUC-1 contra Privaro, quedó claro que el motor de detección solo se invocaba sobre el INPUT (prompt → LLM), nunca sobre el OUTPUT (respuesta del LLM → usuario/agente). Confirmado con datos reales de producción antes de tocar código: `conversation_messages` tenía 1.175 detecciones de PII en 76 mensajes `role=user` y **0 en 78 mensajes `role=assistant`**; `pipelines.total_leaked` estaba en 0 en absolutamente todos los pipelines, incluidos los de cientos de requests.

### Cambios

- **Migración `output_direction_policies`**: añade `direction` (`input`/`output`/`both`) a `policy_rules`, `audit_logs` y `pii_detections`. Todas las filas existentes se retro-rellenan explícitamente a `'input'` — cero cambio de comportamiento para clientes existentes.
- **Migración `output_scanning_rollout_flag`**: añade `pipelines.output_scanning_enabled` (default `false`) y `pipelines.output_scanning_mode` (`shadow`/`enforce`, default `shadow`). El escaneo de output es estrictamente opt-in por pipeline — desplegar este código no cambia nada hasta que un cliente lo activa explícitamente. `shadow` detecta y audita sin modificar la respuesta (periodo de validación seguro antes de pasar a `enforce`).
- **`policy_engine.py`**: `_matches_context` ahora filtra por `direction` — una regla `input` (o sin `direction`, tratada como `input`) nunca se aplica a un contexto `output`, y viceversa; `direction='both'` aplica a ambos. Verificado con `test_output_direction.py` (sin dependencias externas — no requiere Supabase ni presidio).
- **`relay.py`**: nueva `_scan_output_for_pii()`, invocada en `/v1/relay/complete` sobre la respuesta CRUDA del LLM, ANTES de la de-tokenización de los placeholders `[XX-0001]` del propio caller (esos nunca matchean un patrón de PII, así que esto solo detecta fugas NUEVAS — RAG, resultados de tool-calls, contaminación cross-tenant, memorización del modelo — nunca los datos que el propio caller ya había autorizado en turnos anteriores de la misma conversación). Genera un `audit_log` separado (`direction='output'`, `pipeline_stage='relay_output'`) para no tocar la forma del audit_log principal que ya leen dashboards/informes DPO existentes.
- **`proxy.py`**: nuevo endpoint `POST /v1/proxy/protect-output`, para clientes que usan `/protect` de forma standalone (llaman a su propio LLM fuera de Privaro) y quieren escanear la respuesta antes de devolverla a su usuario final. Falla con 403 explícito si el pipeline no tiene `output_scanning_enabled` — mejor eso que dar una falsa sensación de protección.
- **Fix de raíz, encontrado durante esta revisión**: `_apply_tokenization` (proxy.py) y `_protect_messages` (relay.py) descartaban en silencio cualquier detección sin `start`/`end` fiable (`continue` sin cambiar el estado) — la detección quedaba SIN enmascarar en el texto real, y nada lo registraba. Es la razón exacta por la que `pipelines.total_leaked` llevaba en 0 en toda la producción: ningún código asignaba nunca `action = "leaked"`. Corregido en ambos sitios.

### Pendiente (no construido en esta sesión — backlog explícito)

- Escaneo de output en `/v1/relay/stream` (SSE) — requiere lógica de buffering adicional (un chunk puede cortar una entidad detectada a la mitad); el escaneo no-streaming (`/complete`, `/protect-output`) ya cubre el caso más común.
- `agent_steps` con `role='assistant'`/`step_type='response'` — hoy solo existen filas `user`/`prompt`; extender el router de agentes para registrar (y escanear) los pasos de respuesta y resultados de tool-calls es la vía real para cerrar la fuga vía RAG/tool-calling en flujos agénticos multi-paso.
- SDKs (`privaro-sdk-python`, `privaro-sdk-js`): añadir un método `protect_output()`/`protectOutput()` equivalente, hoy solo cubren el flujo de input.
- UI de dashboard (repo `privaro-7938a3bd`): toggle de `output_scanning_enabled`/`mode` por pipeline, selector de `direction` en el editor de policy rules, vista de "Output Incidents", y actualización de `generate-dpo-report` para reflejar cobertura de output.

---

## Escaneo de output en streaming — 2026-08-10 (misma tarde)

Motivado por: prueba real de iCommunity Labs activando `output_scanning_enabled` en el pipeline "Medical Document Reviewer" — el toggle se guardó correctamente, pero al revisar `audit_logs` no apareció ningún evento `direction='output'`. Causa encontrada: el chat real de la app llama a `chat-completion` → **`/v1/relay/stream`**, no a `/v1/relay/complete` — y el escaneo de output de esta misma tarde solo estaba conectado a `/complete`. El toggle era un no-op silencioso en la única ruta que importaba de verdad.

### Por qué streaming es fundamentalmente distinto

En `/complete` se puede escanear la respuesta ANTES de devolverla — hay margen para enmascarar. En streaming, cada chunk ya se ha entregado al cliente en tiempo real; para cuando se puede analizar la respuesta completa, el usuario ya la ha visto. No existe un modo "enforce" real en streaming sin retener toda la respuesta hasta escanearla (lo cual anula el propósito de usar streaming).

### Diseño

- `_audit_streamed_output()` en `relay.py`, invocada tras `data: [DONE]`, sobre el texto RAW (antes de detokenizar) acumulado durante el stream.
- Es **solo auditoría**, nunca modifica lo ya enviado.
- El `output_scanning_mode` del pipeline determina cómo se ETIQUETA la detección, no si se enmascara:
  - `shadow`: se guarda la acción que resolvería la policy (informativo — el cliente ya sabía que esto es solo observación).
  - `enforce`: cualquier detección cuya acción resuelta no sea un no-op se reetiqueta como **`leaked`** — la política pedía bloquear/enmascarar y el canal no pudo cumplirlo. Esto alimenta correctamente `pipelines.total_leaked` y `stats.leaked`, dando al DPO una señal honesta de que este canal concreto no puede hacer cumplir sus políticas de output.
- Verificado con `test_output_direction.py` (2 casos nuevos: shadow mantiene la acción resuelta, enforce reetiqueta a `leaked`).

### Pendiente

- Si un cliente necesita **enforcement real** en streaming, la única solución honesta es desactivar streaming en ese pipeline (`organizations.streaming_enabled`, ya existe) y usar `/complete`, o aceptar latencia añadida con un buffer de N segundos antes de empezar a emitir — no construido, requiere decisión de producto.

---

## Protección de imagen-documento — Tier 1 OCR con Tesseract (2026-08-11)

Nuevo endpoint `POST /v1/proxy/protect-image-document` para documentos fotografiados/escaneados (DNI, contratos, capturas de pantalla): OCR con Tesseract (spa+eng, cajas de palabra + confianza), reconstrucción de texto completo, el mismo motor de detección/políticas que `/protect` y `/protect-document` sin ningún cambio, mapeo de cada detección a las cajas de píxeles que cubre, y redacción de esas regiones con rectángulos negros sobre la imagen.

Decisión de negocio deliberada: **solo Tier 1 (Tesseract), sin fallback a OCR en la nube todavía** — con un solo cliente en producción y sin datos reales sobre cómo se comporta Tesseract con fotos reales (vs. documentos escaneados limpios), construir una escalada de pago a un OCR en la nube ahora sería adivinar el balance de coste sin datos. La respuesta del endpoint incluye un bloque `ocr_quality` explícito (confianza media/mínima, % de palabras de baja confianza) precisamente para que el uso real informe si Tier 2 merece la pena construirse, y en su caso, a partir de qué umbral de confianza activarlo.

**2 bugs reales encontrados durante la verificación end-to-end** (no solo revisión de código — desplegado, probado con una petición real, y depurado con logs reales de Railway ante un 500):
- `find_existing_token()` se llamaba con el parámetro `encrypted_value` (que nunca existió con ese nombre real, y que además nunca podría haber funcionado — AES-256-GCM usa un nonce aleatorio, así que el mismo texto nunca produce el mismo cifrado dos veces). Copiado literalmente del patrón ya existente en `document.py`, que tenía el mismo bug latente sin detonar en producción hasta ahora. `proxy.py` y `relay.py` ya se habían arreglado correctamente el 23/07; `document.py` nunca recibió ese mismo arreglo.
- Consecuencia del mismo bug: `original_value_hash` tampoco se guardaba nunca al insertar el token, así que aunque se hubiera corregido solo el nombre del parámetro, la reutilización de tokens dentro de una misma conversación en `/protect-document` nunca habría funcionado en silencio — arreglado en ambos archivos.

Dockerfile: añadidos `tesseract-ocr` + `tesseract-ocr-spa` (el paquete de español es imprescindible — sin él, la precisión en documentos españoles, el caso de uso completo de esta función, se vería muy afectada). `requirements.txt`: `pytesseract` + `Pillow`.

Verificado con una imagen sintética de prueba (nombre, DNI, teléfono, email, dirección) tanto en lógica aislada como en producción real tras el despliegue: reconstrucción de texto con offsets correctos, mapeo de detección→píxeles correcto (un nombre de 3 palabras mapeó a exactamente 3 cajas), y la imagen redactada resultante confirmada visualmente — los 4 campos sensibles correctamente tapados, sin desplazamiento ni solapamiento con las etiquetas.

---

## Tier 2 (OCR en la nube) — exploración para decidir más adelante, 2026-08-11

Motivado por una prueba real con un DNI fotografiado desde el móvil (no una imagen sintética): Tesseract confundió el carácter final del número de DNI, leyendo "4" donde había una "A" — un error de sustitución de caracteres visualmente similares, no un carácter ausente. El propio texto extraído (`542676064` en vez de `54267606A`) confirma que Tesseract puede estar **"confiadamente equivocado"**: no es que fallara en leer nada, es que leyó mal un carácter concreto con aparente normalidad.

### Dos arreglos ya hechos hoy mismo, independientes de la decisión de Tier 2

1. **Checksum del DNI/NIE** (algoritmo módulo 23 real, RD 1553/2005): eleva la confianza a 0.99 cuando la letra cuadra, mantiene la detección a 0.95 cuando no cuadra (más probable un error de OCR/tecleo que una coincidencia aleatoria). Verificado con el ejemplo oficial (12345678 → Z) y recalculado a mano para un NIE. **No habría resuelto el caso concreto de la prueba** — cuando falta o se sustituye el carácter en el texto extraído, ningún regex puede recuperarlo. Confirmado explícitamente para no generar falsas expectativas.
2. **Nuevo tipo de entidad `license_plate`**: formato español actual (4 dígitos + 3 consonantes, sin vocales/Ñ/Q, vigente desde 2000). Identificador directo (como DNI/IBAN) — permite localizar al propietario/conductor vía DGT, por eso se pixela siempre en fotos/dashcams/prensa. De paso, sincronizado `TOKEN_PREFIX` en los 4 archivos donde estaba duplicado sin importación compartida (`detector.py`, `proxy.py`, `document.py`, `image_document.py`) — `document.py`/`image_document.py` ya estaban desincronizados antes de hoy (les faltaba `money`/`passport`, no solo `license_plate`).

### La decisión pendiente — Tier 2

**Opciones de proveedor evaluadas:**

| | Google Cloud Vision / AWS Textract | BlinkID (Microblink), self-hosted |
|---|---|---|
| Coste | ~$1,50/1.000 imágenes, 1.000 gratis/mes — prácticamente gratis al volumen actual | Sin precio público, venta enterprise/contrato |
| Integración | API REST self-service, sin contrato | Proceso de venta más lento |
| Especialización en documentos de identidad | OCR genérico, mejor que Tesseract en fotos reales, sin corrección específica de campos | Corrección inteligente de caracteres específica para IDs — exactamente la clase de error (A↔4) encontrado hoy. 2.500+ tipos de documento, 140+ países, ISO 27001/27701 |
| **Dónde viven los datos** | La imagen completa sale hacia Google/AWS **sin proteger**, antes de que Privaro pueda tokenizar nada | Se auto-hospeda — los datos nunca salen de la infraestructura de Privaro |

**Tensión conceptual identificada, no solo de coste**: usar un OCR en la nube genérico (Google/AWS) significa mandar el documento de identidad completo, sin ninguna protección, a un tercero antes de poder tokenizar nada — exactamente el tipo de salto de confianza que Privaro existe para evitar con los LLMs. Para clientes de banca/seguros/legal, esto podría ser una objeción real de venta ("¿mandáis mi DNI a Google?"). BlinkID (self-hosted) resuelve esto de raíz, a cambio de mayor coste y un proceso de integración/venta más lento.

**Recomendación cuando se decida construir**: empezar con Google Cloud Vision (barato, rápido, ya mejora la extracción con fotos reales) para validar con volumen bajo; evaluar migrar a algo self-hosted como BlinkID si el volumen de documentos de identidad crece y la privacidad del propio proceso de OCR se convierte en argumento de venta (probable, dados los sectores objetivo).

**Estrategia de activación — más precisa que "confianza baja genérica"**: dado que Tesseract puede estar confiadamente equivocado (el caso de hoy no habría bajado ninguna métrica de confianza agregada), NO basar la escalada solo en `ocr_quality.avg_confidence`. Mejor: escalar específicamente cuando se detecta un patrón "casi-DNI" (8-9 dígitos consecutivos en contexto de documento de identidad) pero el checksum no valida, o cuando no se detecta ningún DNI en absoluto en una imagen que aparenta serlo — esto ataca directamente el campo de mayor valor en vez de disparar por una métrica que puede no reflejar el error real.

**Estado**: sin construir, documentado para decidir cuándo abordarlo.

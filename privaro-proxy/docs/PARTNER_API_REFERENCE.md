# Privaro — Referencia de API para partners

**Versión:** v1
**Última actualización:** 24 de julio de 2026
**Ámbito:** Referencia técnica completa de todos los endpoints disponibles para partners. Complementa a la Guía de integración rápida (Quickstart) — ese documento cubre el "cómo empezar"; este cubre cada campo, cada endpoint y cada comportamiento con precisión.

**URL base:** `https://api.privaro.ai`
**Autenticación:** cabecera `X-Privaro-Key: prvr_xxxxxxxxxxxx` en todos los endpoints salvo que se indique lo contrario.

---

## 1. Concepto clave — tokenización y destokenización automáticas

Antes de entrar en cada endpoint, esto es lo más importante para quien construye un chat:

**Privaro tokeniza el dato personal del *input* antes de que llegue al LLM, y lo vuelve a convertir a su valor original en la *respuesta* del LLM, automáticamente, antes de devolvérosla a vosotros.** No hace falta que gestionéis ningún mapa de tokens, ni que llaméis a ningún endpoint de "destokenizar" — ya viene resuelto.

Ejemplo: si el usuario escribe *"Soy Juan Pérez, ¿podéis confirmarme mi cita?"*, Privaro envía al LLM *"Soy [NM-0001], ¿podéis confirmarme mi cita?"*. Si el LLM responde *"Claro, [NM-0001], su cita es el..."*, Privaro os devuelve *"Claro, Juan Pérez, su cita es el..."* — nunca veis el token en la respuesta final.

Esto se controla con el campo `detokenise_response` (ver más abajo), **activado por defecto** en `/v1/relay/complete` y `/v1/relay/stream`.

---

## 2. POST /v1/proxy/protect

Protege un prompt de texto (sin llamar al LLM — la llamada al proveedor la hacéis vosotros).

```
POST /v1/proxy/protect
Headers:
  X-Privaro-Key: prvr_xxxxx
  Content-Type: application/json
  Idempotency-Key: <opcional>
Body:
{
  "pipeline_id": "string",
  "prompt": "string (1-50000 caracteres)",
  "options": {
    "mode": "tokenise" | "anonymise" | "block",   // default: "tokenise"
    "include_detections": true,                    // default: true
    "reversible": true,                             // default: true
    "agent_mode": false                             // default: false — activa políticas más estrictas
  },
  "conversation_id": "UUID — obligatorio si reversible=true (el valor por defecto); opcional si reversible=false"
}
```

**Respuesta (200):**
```json
{
  "request_id": "req_xxxxxxxx",
  "protected_prompt": "texto con los datos personales enmascarados",
  "detections": [
    { "type": "email", "severity": "high", "action": "tokenised", "token": "[EM-0001]", "start": 12, "end": 30, "confidence": 0.99, "detector": "regex" }
  ],
  "stats": { "total_detected": 1, "total_masked": 1, "leaked": 0, "coverage_pct": 100.0, "processing_ms": 45, "by_type": {...}, "risk_score": 0.3 },
  "audit_log_id": "uuid",
  "gdpr_compliant": true,
  "degraded_mode": false,
  "degraded_reason": null
}
```

**`degraded_mode: true`** significa que el detector falló o tardó demasiado (timeout de 2s) y `protected_prompt` es el prompt **original, sin proteger** (fail-open — nunca bloqueamos vuestro tráfico). Queda igualmente registrado como evento de auditoría de severidad crítica. Si veis esto de forma repetida, avisadnos.

`detector` puede ser `"regex"`, `"presidio"` (motor NER) o `"custom_pattern"` (regla de detección personalizada configurada para vuestro pipeline — contactad con nosotros para dar de alta patrones específicos de vuestro dominio, ej. formato de número de expediente).

Tipos de entidad soportados: `dni`, `iban`, `credit_card`, `email`, `phone`, `health_record`, `ip_address`, `date_of_birth`, `full_name`, y `money` (importes/cifras de negocio, ej. `45.200 €` — categorizado como dato "financial" confidencial, no como dato personal RGPD).

---

## 3. POST /v1/proxy/detect

Idéntico a `/protect` en el request, pero **solo analiza, no enmascara ni persiste nada**. Útil para previsualizar qué detectaría Privaro sin generar rastro.

```
POST /v1/proxy/detect
Body: { "pipeline_id": "string", "prompt": "string" }
```

**Respuesta (200):**
```json
{ "request_id": "req_xxxxxxxx", "detections": [...], "stats": {...} }
```

(Mismo formato de `detections`/`stats` que `/protect`, sin `protected_prompt` ni `audit_log_id`.)

---

## 4. POST /v1/relay/complete

Ciclo completo: protege los mensajes, llama él mismo al LLM (con vuestra clave configurada en LLM Providers), destokeniza la respuesta, devuelve todo de una vez (sin streaming).

```
POST /v1/relay/complete
Headers: X-Privaro-Key, Idempotency-Key (opcional)
Body:
{
  "pipeline_id": "string",
  "messages": [ { "role": "user" | "assistant" | "system", "content": "string" } ],  // 1-50 mensajes
  "provider": "string opcional — sobreescribe el proveedor del pipeline",
  "model": "string opcional — sobreescribe el modelo del pipeline",
  "options": {
    "mode": "tokenise",              // default
    "detokenise_response": true,      // default — ver sección 1
    "include_detections": true,       // default
    "max_tokens": 2048,                // default
    "temperature": 0.7,                // default
    "system_prompt": "string opcional"
  },
  "conversation_id": "UUID opcional — pero sin él los tokens no se guardan en absoluto, ver aviso abajo"
}
```

**Respuesta (200):**
```json
{
  "request_id": "relay_xxxxxxxx",
  "provider": "openai",
  "model": "gpt-4o",
  "protected_messages": [...],
  "pii_detected": 1,
  "pii_masked": 1,
  "risk_score": 0.3,
  "gdpr_compliant": true,
  "response": "texto de la respuesta, ya destokenizado",
  "response_raw": "texto tal cual lo devolvió el LLM, con tokens sin resolver (solo si detokenise_response=true y hubo algún reemplazo — para debugging)",
  "audit_log_id": "uuid",
  "tokens_replaced": 1,
  "usage": { "input_tokens": 120, "output_tokens": 45 },
  "processing_ms": 850
}
```

**Error si el proveedor falla** (502 u otro código del proveedor):
```json
{ "error": "llm_provider_error", "message": "...", "provider": "openai", "hint": "Configure your LLM provider API key at /app/admin/providers" }
```

---

## 5. POST /v1/relay/stream — el endpoint para vuestro chat

Igual que `/relay/complete`, pero devuelve la respuesta **en streaming real**, según el modelo la va generando.

```
POST /v1/relay/stream
Headers: X-Privaro-Key
Body: idéntico a /v1/relay/complete
```

**Respuesta:** `Content-Type: text/event-stream`, formato Server-Sent Events:

```
data: {"delta": "Claro, "}
data: {"delta": "Juan Pérez"}
data: {"delta": ", su cita es el..."}
data: [DONE]
```

Concatenad los `delta` según llegan. **La destokenización ya viene aplicada en cada `delta`** cuando `detokenise_response: true` (default) — internamente, Privaro usa un pequeño buffer de seguridad para no cortar nunca un token a la mitad entre dos trozos del stream, así que lo que recibís ya es texto limpio, listo para mostrar.

Si el descifrado/proveedor falla a mitad del stream, recibiréis:
```
data: {"error": "mensaje de error", "provider": "openai"}
data: [DONE]
```

**Proveedores soportados en streaming hoy:** OpenAI, Azure OpenAI, Anthropic. Otros proveedores (Mistral, Gemini) devuelven un error explícito indicando que no hay streaming disponible todavía — usad `/v1/relay/complete` para esos casos.

**Activado/desactivado por organización:** hay un interruptor `streaming_enabled` (activado por defecto) en vuestro panel, Billing → Security Configuration. Si alguna vez veis un 403 con `"error": "streaming_disabled"`, es que se desactivó ahí.

---

## 6. `conversation_id` — coherencia entre turnos, y cuándo es obligatorio

Si mandáis vuestro propio identificador de conversación/sesión (el que uséis en Robin) en el campo `conversation_id`, **el mismo dato personal recibe siempre el mismo token dentro de esa conversación**. Si "Juan Pérez" sale como `[NM-0001]` en el turno 1, sigue siendo `[NM-0001]` en el turno 5 — nunca un token nuevo para el mismo valor.

**Debe ser un UUID válido** (ej. `550e8400-e29b-41d4-a716-446655440000`) — se guarda en una columna `uuid` de nuestra base de datos. No necesita registrarse ni existir en ningún sitio dentro de Privaro de antemano, pero si Robin usa internamente otro formato de ID de conversación (numérico, con guiones, etc.), generad un UUID propio para asociarlo — un valor que no sea UUID se rechaza con un 422 claro.

**¿Cuándo es obligatorio, no solo recomendado?** El literal de un token (ej. `[NM-0001]`) nunca es único dentro de vuestra organización a lo largo del tiempo — sin un identificador que agrupe qué tokens pertenecen a qué interacción concreta, revertirlos más tarde es ambiguo (confirmado con datos reales: 47 filas históricas compartiendo un mismo literal para una sola organización). Por eso:

| Endpoint | ¿`conversation_id` obligatorio? |
|---|---|
| `/protect` (y `/detect`, aunque no persiste nada) | **Sí, si `options.reversible=true`** (el valor por defecto). Si mandáis `reversible=false`, no se persiste ningún token y `conversation_id` es opcional. |
| `/protect-structured` | **Sí, siempre** — no existe un modo no-reversible para este endpoint. |
| `/detokenize` | **Sí, siempre** — el propio propósito del endpoint es la reversión precisa; sin él no hay forma segura de saber a qué token os referís. |
| `/relay/complete`, `/relay/stream` | Opcional — pero si no lo mandáis, los tokens generados **no se guardan en la base de datos en absoluto** (solo se destokenizan en la propia respuesta de esa llamada gracias a `detokenise_response`). Si necesitáis poder revertir esos tokens más adelante (ej. `/detokenize` en un flujo agéntico posterior), tenéis que mandar `conversation_id` aquí también. |

---

## 7. `Idempotency-Key` — reintentos seguros

Cabecera opcional en `/v1/proxy/protect`, `/v1/proxy/detect` y `/v1/relay/complete` (no disponible en `/v1/relay/stream`). Si repetís la misma petición con la misma clave, Privaro os devuelve exactamente la misma respuesta ya calculada, sin volver a contar contra vuestra cuota ni repetir la llamada al LLM. Generad un identificador único por cada intento lógico vuestro (no por cada HTTP request individual) y reenviadlo tal cual en el reintento. Válido 24 horas.

---

## 8. API de partner — vuestros propios clientes

Estos endpoints requieren que vuestra key tenga los permisos `partner:read_children` (lectura) o `partner:write_children` (creación) — pedidnos que os los activemos si no los tenéis.

### GET /v1/partner/sub-accounts
Lista todos vuestros clientes finales.
```json
{ "sub_accounts": [ { "id": "uuid", "name": "...", "created_at": "..." } ], "count": 3 }
```

### POST /v1/partner/sub-accounts
Crea un cliente final programáticamente (alternativa a hacerlo desde "Mis clientes" en el panel).
```
Body: { "name": "string", "sector": "string", "llm_provider": "string", "llm_model": "string" }
```
**Respuesta (201):**
```json
{ "org_id": "uuid", "pipeline_id": "uuid", "api_key": "prvr_xxxxx", "warning": "This key is shown only once..." }
```
⚠️ La clave se muestra **una única vez**. Guardadla en ese momento.

### GET /v1/partner/sub-accounts/{org_id}/dpo-report/latest
Último informe de compliance de un cliente concreto, con un enlace de descarga firmado (válido 1h).

### GET /v1/partner/sub-accounts/{org_id}/audit-summary?days=30
Resumen ligero: eventos, fugas, eventos de alto riesgo en los últimos N días (máximo 90) para un cliente concreto. Pensado para un widget pequeño en vuestro propio panel, no para volcar el log completo.

---

## 9. POST /v1/proxy/detokenize — reversión automática en bulk

Pensado para flujos agénticos con function-calling: si vuestro LLM decide, a partir de datos que solo vio tokenizados, escribir un registro real en vuestro sistema (crear un albarán, validar una venta), necesitáis los valores reales de vuelta — de golpe, sin intervención humana. Este endpoint encuentra **todos** los tokens Privaro (`[XX-0001]`) presentes en un texto y los revierte en una sola llamada.

No es lo mismo que un flujo de "revelar un valor" pensado para un humano con contraseña — aquí os autenticáis con vuestra propia API key, igual que en `/protect`/`/detect`, y solo se revierten tokens que pertenezcan a vuestra organización.

```
POST /v1/proxy/detokenize
Headers: X-Privaro-Key: prvr_xxxxx
Body:
{
  "pipeline_id": "string",
  "text": "string (1-100000 caracteres) — puede contener 0 o más tokens",
  "conversation_id": "UUID — OBLIGATORIO, ver aviso abajo"
}
```

**⚠️ `conversation_id` es obligatorio en este endpoint.** El literal de un token (ej. `[NM-0001]`) **no es único** dentro de vuestra organización a lo largo del tiempo — es solo un contador que empieza de nuevo en cada llamada a `/protect`. Sin `conversation_id`, no hay garantía de que `[NM-0001]` se resuelva al valor de la petición que os interesa — confirmado con datos reales: una sola organización puede acumular decenas de filas históricas compartiendo el mismo literal. Pasad el mismo `conversation_id` (UUID) que usasteis en el `/protect` o `/protect-structured` original que generó esos tokens.

**Respuesta (200):**
```json
{
  "request_id": "req_xxxxxxxx",
  "detokenized_text": "texto con los valores reales restituidos",
  "tokens_reversed": 3,
  "tokens_not_found": []
}
```

`tokens_not_found` lista cualquier token con formato válido presente en el texto pero que no se encontró para vuestra organización (por ejemplo, si el LLM alucinó un token, o si ya expiró) — se dejan sin modificar en `detokenized_text`.

---

## 10. POST /v1/proxy/protect-structured — protección consciente de campos

`/protect` opera sobre un único prompt de texto libre. Si vuestros datos vienen como **campos con nombre** (los resultados de una consulta a vuestro ERP, por ejemplo), este endpoint os permite indicar qué tipo de dato es cada campo por su **nombre**, no solo por su contenido — útil para casos donde el nombre del campo es señal más fiable que el contenido (por ejemplo, un campo `diagnostico` es dato de salud independientemente de qué enfermedad concreta mencione).

```
POST /v1/proxy/protect-structured
Headers: X-Privaro-Key: prvr_xxxxx
Body:
{
  "pipeline_id": "string",
  "fields": {
    "nombre_campo_1": "valor 1",
    "nombre_campo_2": "valor 2"
  },
  "conversation_id": "UUID — OBLIGATORIO"
}
```

`conversation_id` es obligatorio aquí — este endpoint no tiene un modo "no reversible", así que siempre puede persistir tokens, y sin un identificador de conversación no hay forma segura de revertirlos después (ver sección 6).

**Respuesta (200):**
```json
{
  "request_id": "req_xxxxxxxx",
  "protected_fields": { "nombre_campo_1": "...", "nombre_campo_2": "..." },
  "detections_by_field": { "nombre_campo_1": [...], "nombre_campo_2": [...] },
  "stats": {...},
  "audit_log_id": "uuid"
}
```

Para forzar el tipo de un campo por su nombre (en vez de depender solo del contenido), contactad con nosotros para configurar una regla `field_name_pattern` en vuestro pipeline — por ejemplo, cualquier campo que coincida con `diagnostic|patholog` se trata siempre como dato de salud, cualquier campo que coincida con `importe|facturac` se trata siempre como cifra de negocio confidencial. Los campos sin regla configurada pasan por la detección de contenido habitual (incluye ahora también importes monetarios en texto libre — ver sección de tipos de entidad).

---

## 11. Errores comunes

| Código | Significado |
|---|---|
| 401 `missing_api_key` / `invalid_api_key` | Falta la cabecera `X-Privaro-Key` o la clave no es válida/está revocada |
| 403 `pipeline_org_mismatch` | El `pipeline_id` no pertenece a la organización de esa clave |
| 403 `partner_permission_required` / `partner_write_permission_required` | Vuestra clave no tiene el permiso necesario para ese endpoint |
| 404 `pipeline_not_found` | El `pipeline_id` no existe |
| 404 `sub_account_not_found` | El `org_id` no existe o no es hijo de vuestra organización |
| 502 `llm_provider_error` | El proveedor del LLM devolvió un error (clave inválida, cuota agotada, etc. — el campo `message` trae el detalle) |

---

## Historial de cambios

| Versión | Fecha | Cambios |
|---|---|---|
| v4 | 2026-07-24 | `conversation_id` ahora es **obligatorio** en `/detokenize` y `/protect-structured` (antes solo recomendado), y en `/protect` cuando `options.reversible=true` (el valor por defecto) — cierra de raíz la ambigüedad del literal de token, no solo la mitiga. `/relay/*` se deja opcional deliberadamente (ver sección 6). |
| v3 | 2026-07-24 | `/v1/proxy/detokenize` ahora acepta `conversation_id` (muy recomendado) tras un fallo real detectado en pruebas en vivo — `token_value` no es único dentro de una organización a lo largo del tiempo. |
| v2 | 2026-07-24 | Añadido `/v1/proxy/detokenize` (reversión en bulk para flujos agénticos), `/v1/proxy/protect-structured` (protección por campo con nombre, pensado para copilotos de ERP), y nuevo tipo de entidad `money` — a raíz del análisis de Robin AI/Octupus como copiloto de Odoo. |
| v1 | 2026-07-24 | Primera versión — referencia completa de todos los endpoints, en respuesta a una pregunta real de integración (destokenización en streaming). |

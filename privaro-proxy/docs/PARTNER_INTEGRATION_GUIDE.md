# Privaro — Guía de integración para partners

**Versión:** v3
**Última actualización:** 2026-07-23
**Ámbito:** Partners tipo "agregador" (ISV que embebe Privaro en su propio producto y reparte el consumo entre sus clientes finales). Ejemplo de referencia: Octupus Technologies / Robin AI.

> Este documento se actualiza automáticamente cada vez que un cambio de backend afecta al flujo de integración de partners. Ver el historial de cambios al final.

---

## 1. Principio del modelo

Un partner (p. ej. Octupus) integra Privaro una vez y lo reparte entre N clientes finales. Dos cosas se agregan hacia el partner, y una cosa nunca se agrega:

| Se agrega al partner | Nunca se agrega — se queda aislado por cliente |
|---|---|
| Cuota de peticiones/mes (`billing_accounts`) | Audit log (`audit_logs`) |
| Factura y descuento de partner | PII detections, tokens_vault |
| | DPO Report, evidencia blockchain (iBS) |

Cada cliente final de Octupus sigue siendo su propio responsable de tratamiento ante su AEPD — necesita su propia evidencia, aunque la factura y la cuota las lleve Octupus.

---

## 2. Conceptos y terminología

- **Partner org** (`org_type = 'partner'`): la organización del partner en Privaro (p. ej. Octopus). No tiene `parent_org_id`. Tiene su propia `billing_account`.
- **Sub-account org** (`org_type = 'sub_account'`): un cliente final del partner. Tiene `parent_org_id` apuntando al partner. **No tiene `billing_account` propia** — apunta a la del partner (`billing_account_id` compartido).
- **Billing account** (`billing_accounts`): dueña del plan, tier, descuento y contador de peticiones. Una por partner (compartida por todos sus sub-accounts) o una por cliente directo.
- **Partner API key**: una única clave (`X-Privaro-Key`) con el permiso `partner:read_children`, propiedad del partner, que puede leer (nunca escribir) datos de sus sub-accounts.
- **Sub-account API key**: una clave por cliente final, con permisos normales (`proxy:write`, `proxy:read`), usada para las llamadas reales de protección de datos (`/v1/proxy/protect`, `/v1/proxy/detect`).

---

## 3. Paso a paso — alta de un partner nuevo

### 3.1 Alta del partner (lo hace el equipo de Privaro)

1. Crear la organización del partner: `org_type = 'partner'`, `parent_org_id = NULL`.
2. Crear su `billing_account`: plan, `requests_limit` (tier negociado), `initial_discount_pct`, `reviewed_discount_pct`, `discount_review_at` (fecha del escalón, normalmente +6 meses desde el despliegue).
3. Vincular `organizations.billing_account_id` del partner a esa `billing_account`.
4. Generar la **partner API key** con permiso `partner:read_children`, y entregársela al partner por canal seguro (nunca por email en texto plano).

*(Hoy este alta se hace manualmente vía Supabase. No hay todavía una pantalla de self-serve para esto — ver Sección 6, pendiente.)*

### 3.2 Activación del pago (Stripe)

Antes de que el partner pueda dar de alta clientes, su suscripción tiene que estar activa:

1. Privaro genera un **link de pago de Stripe** para el tier acordado, con un **código promocional de un solo uso** que aplica el descuento de la fase inicial (20%).
2. El partner abre el link, introduce método de pago, y **debe teclear el código promocional en el campo de descuento del checkout** — el descuento no se aplica solo, hay que indicárselo explícitamente al partner en el email de activación.
3. Al completar el pago queda activa la suscripción recurrente mensual en Stripe, vinculada al `stripe_customer_id` guardado en la `billing_account` del partner.

**Notas importantes de esta fase (aprendidas al hacerlo por primera vez):**
- El código promocional **no puede estar restringido a un `customer` concreto** si se usa desde un Payment Link genérico — Stripe rechaza el código como "no válido" porque el checkout todavía no ha identificado al comprador en ese punto del flujo. Usa códigos sin restricción de cliente, protegidos solo por `max_redemptions: 1`.
- Si el comprador está fuera de la Eurozona, Stripe puede ofrecerle pagar en su moneda local además de EUR ("Adaptive Pricing", configuración de cuenta, no del link). Si se quiere forzar solo EUR, hay que desactivarlo en el Dashboard de Stripe → Settings → Payments.
- El escalón de descuento a los 6 meses (20% → 15%) **no está automatizado en Stripe todavía** — hay que entrar manualmente a la suscripción en el Dashboard y sustituir el cupón `PARTNER20` por `PARTNER15` en la fecha `discount_review_at` de la `billing_account`.

### 3.3 Alta de cada cliente final (sub-account) — autoservicio

A diferencia del alta del partner (que hace el equipo de Privaro), **cada cliente final lo da de alta el propio partner**, sin intervención de Privaro:

1. El partner entra a su panel de Privaro (con el usuario admin que se le ha invitado) y va a la sección **"Mis clientes"**.
2. Pulsa "Añadir cliente" y rellena: nombre, sector, proveedor de LLM y modelo.
3. Al confirmar, Privaro crea automáticamente la organización (`org_type = 'sub_account'`, `parent_org_id` = el partner, `billing_account_id` = la misma del partner) y genera una API key propia para ese cliente.
4. La API key se muestra **una única vez** en pantalla — el partner tiene que guardarla en ese momento, Privaro no puede volver a mostrarla.

Por debajo, esto llama a la Edge Function `partner-sub-accounts` (`GET`/`POST`), autenticada con la sesión del usuario del partner (no con `X-Privaro-Key`). No requiere ninguna acción manual de Privaro salvo que el partner tenga dudas.

### 3.4 Integración técnica — llamadas de protección (por cada cliente final)

El partner llama al proxy usando la API key del sub-account correspondiente:

```
POST https://<proxy-url>/v1/proxy/protect
Headers: X-Privaro-Key: prvr_xxxxx   (key del sub-account, no la del partner)
Body: { "pipeline_id": "...", "prompt": "..." }
```

Cada llamada cuenta contra la cuota del partner (agregada), pero genera audit log, PII detections y certificación blockchain aislados en el `org_id` del sub-account.

`/v1/proxy/detect` funciona igual, en modo solo-análisis (sin persistir).

### 3.5 Integración técnica — panel de compliance embebido (opcional pero recomendado)

Para que el partner muestre el estado de compliance de cada cliente final **dentro de su propio producto**, sin que el cliente final necesite loguearse en Privaro:

```
GET /v1/partner/sub-accounts                                    (lista de clientes del partner)
GET /v1/partner/sub-accounts/{org_id}/dpo-report/latest         (último informe DPO + link firmado, 1h)
GET /v1/partner/sub-accounts/{org_id}/audit-summary?days=30     (resumen para un widget)
```

Todas usan la **partner API key** (no la del sub-account) en `X-Privaro-Key`. Devuelven 404 si el `org_id` solicitado no es un sub-account de ese partner — el aislamiento se verifica en cada llamada, no solo al crear la key.

### 3.6 Webhook automático — nuevo informe DPO disponible

Cuando se genera un DPO Report para uno de tus clientes finales, Privaro dispara un webhook hacia ti (si tienes uno configurado) en vez de obligarte a hacer polling:

```
Evento: dpo_report.generated
Firma:  header X-Privaro-Signature: sha256=<hmac-sha256 del body con tu secret>
Body:   { "event": "dpo_report.generated", "org_id": "...", "org_name": "...",
          "report_id": "...", "period_label": "...", "event_count": N,
          "certified_count": N, "high_risk_count": N, "generated_at": "..." }
```

Configúralo dándonos una URL de destino y un secreto — lo damos de alta en tu organización de partner. Es *best-effort*: si tu endpoint falla o no responde, la generación del informe no se ve afectada; simplemente no llega el aviso (usa el polling de 3.4 como respaldo).

### 3.7 Notificaciones de consumo (80% y 100% del tier)

Si lo activas, te avisamos automáticamente por email o webhook cuando el consumo agregado de tu cuenta llega al 80% de tu tier (aviso) y al 100% (ya en overage). Cada aviso se dispara **una sola vez por ciclo de facturación** — no te vamos a machacar con el mismo email en cada petición una vez pasado el umbral. Pídenos que te lo activemos indicando destinatarios y canal (email o webhook).

---

## 4. Modelo de facturación (resumen operativo)

- El partner paga una cuota fija mensual (prepago) basada en el tier de peticiones/mes agregadas de todos sus sub-accounts — no revenue share, salvo acuerdo específico.
- La suscripción se gestiona en Stripe (link de pago + código promocional para el descuento inicial — ver Sección 3.2).
- Descuento de partner: fase inicial (mayor descuento, primeros 6 meses) → fase de revisión (descuento suelo). En Supabase el cambio de fase es automático (`pg_cron`); **en Stripe el cambio de cupón es manual todavía** — hay que sincronizar ambos en la fecha `discount_review_at`.
- Cuota: **soft-cap**. Nunca se bloquea el tráfico al superar el límite; el exceso se cuenta aparte (`overage_requests_used`) y se factura según `overage_rate_per_1000` (a definir por partner).
- Reset de cuota: automático cada mes (`pg_cron`), sin intervención manual.
- El partner decide libremente cómo repercute el coste a sus clientes finales — Privaro no impone su modelo de precios hacia el usuario final.

*(Términos legales y económicos exactos: ver el Acuerdo Marco de Partnership firmado con cada partner, no este documento.)*

---

## 5. Checklist de arranque técnico

- [ ] Partner org creada con su `billing_account` y tier acordado
- [ ] Suscripción de Stripe activada por el partner (link de pago + código promocional canjeado correctamente)
- [ ] Usuario(s) admin del partner invitados y vinculados a su organización
- [ ] Partner API key generada y entregada de forma segura (para el panel de compliance embebido, Sección 3.5)
- [ ] Al menos un cliente final dado de alta desde "Mis clientes" por el propio partner
- [ ] Llamada de prueba a `/v1/proxy/protect` con la key de ese cliente — confirmar que el contador de la `billing_account` del partner sube
- [ ] Llamada de prueba a `/v1/partner/sub-accounts/{org_id}/audit-summary` con la partner key — confirmar respuesta 200
- [ ] Confirmar `discount_review_at` configurado correctamente según lo firmado en el contrato, y anotado también para el cambio manual de cupón en Stripe

---

## 6. Pendiente / roadmap conocido (no bloqueante para arrancar)

- Sin autoservicio para el alta del partner en sí (org + billing_account + primer usuario admin) — decisión deliberada, se hace manualmente tras confirmar el pago. El alta de clientes finales SÍ es autoservicio (Sección 3.3).
- El webhook `dpo_report.generated` y las notificaciones de consumo (80%/100%) requieren que Privaro configure manualmente tus credenciales/destinatarios — no hay autoservicio todavía.
- Overage: la tarifa (`overage_rate_per_1000`) no está fijada por defecto — se define por partner.
- El escalón de descuento 20%→15% no está sincronizado automáticamente entre Supabase y Stripe — hay que cambiar el cupón a mano en la fecha de revisión (ver Sección 3.2).

---

## Historial de cambios

| Versión | Fecha | Cambios |
|---|---|---|
| v1 | 2026-07-02 | Primera versión. Modelo partner/sub_account, `billing_accounts` agregada, soft-cap, API de partner de solo lectura (`/v1/partner/*`), reset mensual y escalón de descuento automáticos. |
| v2 | 2026-07-02 | Corregido: codificación UTF-8 en respuestas JSON (afectaba a nombres con tildes/guiones en clientes como PowerShell). Corregido: `get_latest_dpo_report` buscaba `status='completed'`, el valor real es `'ready'` — el endpoint de informe DPO nunca habría devuelto nada. Añadido: notificaciones automáticas de consumo al 80%/100% del tier (Sección 3.6). Añadido: webhook `dpo_report.generated` hacia el partner cuando se genera un informe de un cliente final (Sección 3.5). |
| v3 | 2026-07-23 | Corregido: nombre del partner de referencia (Octopus → Octupus). Añadido: Sección 3.2, activación de pago vía Stripe (link de pago + código promocional), con las dos lecciones aprendidas al hacerlo por primera vez (el código no puede ir restringido a un customer en un Payment Link genérico; Adaptive Pricing puede ofrecer monedas no deseadas si no se desactiva). Actualizado: la Sección 3.3 (antes 3.2) ya no es un alta manual de clientes finales por parte de Privaro — ahora es autoservicio real del partner desde "Mis clientes", probado end-to-end. Actualizado el checklist de arranque y el roadmap pendiente en consecuencia. |


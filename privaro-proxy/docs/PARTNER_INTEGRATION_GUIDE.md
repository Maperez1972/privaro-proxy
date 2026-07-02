# Privaro — Guía de integración para partners

**Versión:** v1
**Última actualización:** 2026-07-02
**Ámbito:** Partners tipo "agregador" (ISV que embebe Privaro en su propio producto y reparte el consumo entre sus clientes finales). Ejemplo de referencia: Octopus Technologies / Robin AI.

> Este documento se actualiza automáticamente cada vez que un cambio de backend afecta al flujo de integración de partners. Ver el historial de cambios al final.

---

## 1. Principio del modelo

Un partner (p. ej. Octopus) integra Privaro una vez y lo reparte entre N clientes finales. Dos cosas se agregan hacia el partner, y una cosa nunca se agrega:

| Se agrega al partner | Nunca se agrega — se queda aislado por cliente |
|---|---|
| Cuota de peticiones/mes (`billing_accounts`) | Audit log (`audit_logs`) |
| Factura y descuento de partner | PII detections, tokens_vault |
| | DPO Report, evidencia blockchain (iBS) |

Cada cliente final de Octopus sigue siendo su propio responsable de tratamiento ante su AEPD — necesita su propia evidencia, aunque la factura y la cuota las lleve Octopus.

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

### 3.2 Alta de cada cliente final (sub-account)

Por cada cliente final que el partner incorpora:

1. Crear la organización del cliente: `org_type = 'sub_account'`, `parent_org_id = <id del partner>`.
2. **Importante:** `billing_account_id` de este sub-account debe apuntar a la **misma** `billing_account` del partner — no se crea una nueva.
3. Generar una **API key normal** para este sub-account (permisos `proxy:write`, `proxy:read`), que el partner usará en sus llamadas al proxy en nombre de ese cliente.
4. Configurar al menos un `pipeline` para el sub-account (LLM provider, sector) — necesario para que `/v1/proxy/protect` funcione.

### 3.3 Integración técnica — llamadas de protección (por cada cliente final)

El partner llama al proxy usando la API key del sub-account correspondiente:

```
POST https://<proxy-url>/v1/proxy/protect
Headers: X-Privaro-Key: prvr_xxxxx   (key del sub-account, no la del partner)
Body: { "pipeline_id": "...", "prompt": "..." }
```

Cada llamada cuenta contra la cuota del partner (agregada), pero genera audit log, PII detections y certificación blockchain aislados en el `org_id` del sub-account.

`/v1/proxy/detect` funciona igual, en modo solo-análisis (sin persistir).

### 3.4 Integración técnica — panel de compliance embebido (opcional pero recomendado)

Para que el partner muestre el estado de compliance de cada cliente final **dentro de su propio producto**, sin que el cliente final necesite loguearse en Privaro:

```
GET /v1/partner/sub-accounts                                    (lista de clientes del partner)
GET /v1/partner/sub-accounts/{org_id}/dpo-report/latest         (último informe DPO + link firmado, 1h)
GET /v1/partner/sub-accounts/{org_id}/audit-summary?days=30     (resumen para un widget)
```

Todas usan la **partner API key** (no la del sub-account) en `X-Privaro-Key`. Devuelven 404 si el `org_id` solicitado no es un sub-account de ese partner — el aislamiento se verifica en cada llamada, no solo al crear la key.

---

## 4. Modelo de facturación (resumen operativo)

- El partner paga una cuota fija mensual (prepago) basada en el tier de peticiones/mes agregadas de todos sus sub-accounts — no revenue share, salvo acuerdo específico.
- Descuento de partner: fase inicial (mayor descuento, primeros 6 meses) → fase de revisión (descuento suelo, automático, sin intervención manual — `pg_cron` cambia `discount_phase` en la fecha `discount_review_at`).
- Cuota: **soft-cap**. Nunca se bloquea el tráfico al superar el límite; el exceso se cuenta aparte (`overage_requests_used`) y se factura según `overage_rate_per_1000` (a definir por partner).
- Reset de cuota: automático cada mes (`pg_cron`), sin intervención manual.
- El partner decide libremente cómo repercute el coste a sus clientes finales — Privaro no impone su modelo de precios hacia el usuario final.

*(Términos legales y económicos exactos: ver el Acuerdo Marco de Partnership firmado con cada partner, no este documento.)*

---

## 5. Checklist de arranque técnico

- [ ] Partner org creada con su `billing_account` y tier acordado
- [ ] Partner API key generada y entregada de forma segura
- [ ] Al menos un sub-account de prueba creado y apuntando a la `billing_account` del partner
- [ ] Llamada de prueba a `/v1/proxy/protect` con la key del sub-account — confirmar que el contador de la `billing_account` del partner sube
- [ ] Llamada de prueba a `/v1/partner/sub-accounts/{org_id}/audit-summary` con la partner key — confirmar respuesta 200
- [ ] Confirmar `discount_review_at` configurado correctamente según lo firmado en el contrato

---

## 6. Pendiente / roadmap conocido (no bloqueante para arrancar)

- Sin pantalla self-serve de alta de partners/sub-accounts — hoy es manual vía Supabase.
- Sin notificación automática al 80%/100% de cuota todavía (la cuota sí se cuenta correctamente; falta el aviso).
- Sin webhook `dpo_report.generated` disparado automáticamente hacia el partner todavía — el partner debe hacer polling a `/dpo-report/latest`.
- Overage: la tarifa (`overage_rate_per_1000`) no está fijada por defecto — se define por partner.

---

## Historial de cambios

| Versión | Fecha | Cambios |
|---|---|---|
| v1 | 2026-07-02 | Primera versión. Modelo partner/sub_account, `billing_accounts` agregada, soft-cap, API de partner de solo lectura (`/v1/partner/*`), reset mensual y escalón de descuento automáticos. |

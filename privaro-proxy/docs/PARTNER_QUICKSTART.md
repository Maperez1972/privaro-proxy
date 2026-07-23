# Privaro — Guía de integración rápida para partners

**Versión:** v2
**Última actualización:** 23 de julio de 2026

Esta guía cubre únicamente los pasos que tu equipo tiene que ejecutar para integrar Privaro en vuestro producto. No incluye nada de cómo funciona Privaro por dentro — solo lo que necesitáis vosotros.

---

## 1. Qué es Privaro para vuestros clientes finales

Privaro se sitúa entre vuestro producto y el modelo de lenguaje (OpenAI, Azure OpenAI, Anthropic, etc.). Antes de que un prompt salga hacia el modelo, Privaro detecta y enmascara datos personales, y genera un log auditable de cada interacción. Vuestros clientes finales obtienen evidencia de compliance (GDPR, AI Act) sin que tengáis que construir esa capa vosotros.

Todos vuestros clientes finales comparten una única cuota mensual contratada por vosotros — no facturáis nada por separado con Privaro por cada cliente.

---

## 2. Activar vuestra suscripción

1. Recibiréis un enlace de pago y un código promocional por email.
2. Abrid el enlace, introducid vuestro método de pago, y **escribid el código promocional en el campo de descuento del checkout** — sin él, no se aplica la condición acordada.
3. Al completar el pago, la suscripción queda activa de inmediato.

---

## 3. Acceder a vuestro panel

1. Recibiréis una invitación por email para cada persona que vaya a administrar la cuenta.
2. Abrid el enlace de invitación y fijad vuestra contraseña.
3. Una vez dentro, veréis:
   - Vuestro consumo actual (peticiones usadas / límite del plan).
   - La sección **"Mis clientes"**, donde dais de alta a cada cliente final.

---

## 4. Dar de alta a vuestros clientes finales

Por cada cliente final que queráis proteger con Privaro:

1. Entrad en "Mis clientes" → **"Añadir cliente"**.
2. Rellenad: nombre del cliente, sector, proveedor de LLM (OpenAI, Azure OpenAI, Anthropic, etc.) y modelo concreto.
3. Al confirmar, se genera una **API key** exclusiva para ese cliente.

> ⚠️ **La API key se muestra una única vez.** Copiadla y guardadla en vuestro gestor de secretos en ese mismo momento — no podemos volver a mostrárosla. Si la perdéis, hay que dar de alta el cliente de nuevo.

**¿Queréis automatizarlo desde vuestro propio backend?** En vez de dar de alta cada cliente a mano en el panel, podéis llamar directamente a:

```
POST https://<URL-DEL-PROXY-PRIVARO>/v1/partner/sub-accounts
Headers: X-Privaro-Key: <vuestra clave de partner, con permiso adicional 'partner:write_children'>
Body: { "name": "...", "sector": "...", "llm_provider": "...", "llm_model": "..." }
```

Mismo resultado que hacerlo desde "Mis clientes" (misma API key generada, mismo aviso de que solo se muestra una vez), pero disparable automáticamente el momento en que uno de vuestros clientes se da de alta con vosotros. Pedidnos que activemos el permiso `partner:write_children` en vuestra clave de partner si queréis usar esta vía — por defecto la clave de partner es solo de lectura.

---

## 5. Integración técnica — proteger un prompt

Por cada llamada que vuestro producto haga a un LLM en nombre de un cliente final, pasadla primero por Privaro usando la API key de ese cliente concreto (no una API key genérica vuestra):

```
POST https://api.privaro.ai/v1/proxy/protect
Headers:
  X-Privaro-Key: <API key del cliente final>
  Content-Type: application/json
Body:
{
  "pipeline_id": "<id del pipeline de ese cliente>",
  "prompt": "<el prompt que ibais a enviar al LLM>"
}
```

**Respuesta:**

```json
{
  "protected_prompt": "El texto del prompt con los datos personales enmascarados",
  "detections": [ { "type": "email", "action": "tokenised", "token": "[EM-0001]" } ],
  "gdpr_compliant": true
}
```

Enviad `protected_prompt` (no el original) al proveedor del LLM. El `pipeline_id` de cada cliente os lo proporciona Privaro al darlo de alta.

### Modo solo-análisis (sin bloquear ni persistir)

Si solo queréis detectar datos personales sin generar registro permanente, usad el mismo formato contra:

```
POST https://api.privaro.ai/v1/proxy/detect
```

### Importante sobre límites de uso

Privaro **nunca bloquea vuestro tráfico**. Si superáis el volumen contratado, las llamadas se siguen sirviendo con normalidad — el exceso se factura aparte, no se corta el servicio.

### Streaming — si vuestro chat muestra la respuesta palabra a palabra

Si vuestro producto usa streaming (lo habitual en un chat), usad esta vía en vez de `/v1/proxy/protect` — protege el prompt, llama al LLM configurado en vuestro pipeline (con la clave que hayáis dado de alta en LLM Providers), y os devuelve la respuesta en streaming real:

```
POST https://api.privaro.ai/v1/relay/stream
Headers:
  X-Privaro-Key: <API key del cliente final>
  Content-Type: application/json
Body:
{
  "pipeline_id": "<id del pipeline de ese cliente>",
  "messages": [{ "role": "user", "content": "<mensaje del usuario>" }]
}
```

Respuesta en Server-Sent Events, según el modelo va generando texto:

```
data: {"delta": "Hola"}
data: {"delta": ", "}
data: {"delta": "¿en qué puedo ayudarte?"}
data: [DONE]
```

Concatenad los `delta` según llegan para mostrar el efecto de streaming en vuestra interfaz. Soportado hoy para OpenAI/Azure y Anthropic — para otros proveedores, usad `/v1/proxy/protect` + vuestra propia llamada al LLM mientras tanto.

Este comportamiento está activado por defecto en vuestra organización; si alguna vez preferís desactivarlo, hay un interruptor en Billing → Security Configuration del panel.

---

## 6. Panel de compliance embebido en vuestro producto (opcional, recomendado)

Para mostrar el estado de compliance de cada cliente final **dentro de vuestro propio producto**, sin que tengan que entrar a Privaro directamente, usad vuestra clave de partner (distinta de las claves de cada cliente):

```
GET https://api.privaro.ai/v1/partner/sub-accounts
GET https://api.privaro.ai/v1/partner/sub-accounts/{id}/dpo-report/latest
GET https://api.privaro.ai/v1/partner/sub-accounts/{id}/audit-summary?days=30
```

Headers: `X-Privaro-Key: <vuestra clave de partner>`

El primer endpoint lista vuestros clientes. El segundo devuelve el último informe de protección de datos (con un enlace de descarga temporal). El tercero da un resumen de actividad de los últimos N días — ideal para un pequeño widget de estado.

---

## 7. Webhook — aviso automático de nuevo informe (opcional)

Si preferís que os avisemos en vez de consultar activamente, dadnos una URL y un secreto, y os notificaremos cada vez que se genere un nuevo informe para uno de vuestros clientes:

```
Evento: dpo_report.generated
Header:  X-Privaro-Signature: sha256=<firma HMAC-SHA256 del cuerpo con vuestro secreto>
Body:    { "event": "dpo_report.generated", "org_id": "...", "report_id": "...",
           "period_label": "...", "event_count": N, "generated_at": "..." }
```

Verificad la firma antes de confiar en el contenido del webhook.

---

## 8. Checklist de arranque

- [ ] Suscripción activada (código promocional canjeado correctamente)
- [ ] Al menos un usuario admin ha entrado al panel
- [ ] Primer cliente final dado de alta desde "Mis clientes"
- [ ] API key del primer cliente guardada de forma segura
- [ ] Primera llamada de prueba a `/v1/proxy/protect` completada con éxito
- [ ] (Opcional) Clave de partner configurada para el panel embebido
- [ ] (Opcional) Webhook de informes configurado

---

## Soporte

Cualquier duda durante la integración, escribidnos a **soporte@icommunity.io** o contactad directamente con vuestro interlocutor en iCommunity Labs.

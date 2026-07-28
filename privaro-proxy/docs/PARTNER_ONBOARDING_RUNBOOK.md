# Runbook interno — Alta de un partner nuevo

**Uso:** solo para el equipo de Privaro (Miguel / Claude). No es el documento
para partners — ese es `PARTNER_INTEGRATION_GUIDE.md`. Este es el "cómo lo
doy de alta yo", pensado para copiar-pegar-confirmar cuando llegue un
partner nuevo (p. ej. Octopus) tras firmar y pagar.

Probado end-to-end con "Partner Demo" el 2026-07-02 (ver Sección 5 de este
documento para el historial).

---

## 0. Cuestionario previo — todo esto se pregunta ANTES de tocar nada técnico

**Por qué existe esta sección así de larga:** Octupus fue nuestro primer
partner real, y fuimos aprendiendo sus necesidades sobre la marcha, por
email, una a una, durante días (permisos de partner pedidos por separado,
pregunta del modelo de proveedor LLM descubierta tarde, etc.). Cada
pregunta de abajo nace de algo concreto que tuvimos que resolver a
posteriori con Octupus. La idea es que el **siguiente** partner se
configure de una sola sesión, sin ninguna vuelta atrás.

### Básico (ya existía)

- [ ] Nombre del partner
- [ ] Tier de peticiones/mes acordado (ver `2. Tabla Tiers` del Excel de pricing)
- [ ] % descuento fase inicial y fase de revisión (normalmente 20% → 15%)
- [ ] Fecha del escalón de descuento (normalmente despliegue + 6 meses)
- [ ] Email del primer usuario admin del partner (quien va a gestionar sus clientes)
- [ ] Confirmación de que el pago/contrato ya está cerrado — este alta da acceso real

### Modelo de proveedor LLM — determina si hace falta construir algo antes de escalar

- [ ] **¿Cada cliente final del partner tiene su propia clave de LLM (OpenAI/Anthropic/etc.), o el partner gestiona una única clave compartida para todos?**
      *Por qué importa:* si crean sub-cuentas por API (ver siguiente bloque), hoy no hay forma de configurar el proveedor LLM en esa misma llamada — hay que entrar al dashboard a mano para cada una. Si el modelo es "clave compartida", hay que construir un mecanismo de herencia automática del proveedor del padre ANTES de que empiecen a escalar, no después. (Pendiente de resolver con Octupus — primer caso real que hizo saltar esta pregunta, 2026-07-27.)

### Uso de la API de partner (sub-cuentas)

- [ ] **¿Van a gestionar sus clientes finales por API (no solo desde "Mis clientes" en el dashboard)?**
      *Si la respuesta es "no lo sabemos todavía" o "probablemente sí": dale igualmente ambos permisos desde el alta (ver paso 3.5) — no cuesta nada tenerlos activados aunque no los usen desde el primer día, y evita la vuelta atrás que tuvimos con Octupus.*
- [ ] ~~¿Cuántas organizaciones/clientes finales esperan dar de alta, aproximadamente?~~ — **no preguntar esto de antemano.** Si el partner va a crear sus sub-cuentas por su propia API (que es lo normal — protección de datos de sus propios clientes, no van a querer pasárnoslos a nosotros), el volumen es asunto suyo, no algo que necesitemos saber para configurar nada. Solo entra en juego si ELLOS mismos plantean un problema de volumen/límite — en ese momento sí se investiga si hace falta algo (rate limit, creación en bloque, etc.), no antes. (Aprendido con Octupus, 2026-07-27 — la pregunta original asumía que nosotros probaríamos el volumen por ellos, cuando en realidad lo harán ellos mismos con su propia integración.)

### Encaje con su vertical/producto (relevante si el partner construye un copiloto de IA sobre un ERP/CRM, como Octupus/Robin AI sobre Odoo — pero aplica a cualquier "AI Partner" vertical)

- [ ] **¿Su producto toca datos de RRHH/nóminas de sus propios clientes (salarios, datos bancarios de nómina)?** — categoría de dato distinta a la de clientes finales, con implicaciones de confidencialidad propias.
- [ ] **¿Usan algún módulo de Selección/Reclutamiento (datos de candidatos)?** — plazos de retención distintos a los de clientes/empleados en muchas legislaciones.
- [ ] **¿La protección debería variar según qué usuario final pregunta (no solo por organización/pipeline)?** — hoy el motor de políticas de Privaro no distingue por usuario final, solo por organización.
- [ ] **¿Tienen flujos donde su producto llama a Privaro sin que haya un humano escribiendo (acciones automáticas/programadas)?** Si es así: **¿qué usan como identificador único de esos flujos?** — relevante porque `conversation_id` es obligatorio en varias llamadas reversibles, y ese campo asume una sesión con identidad propia; para flujos de sistema, hay que generar un UUID por ejecución, no reutilizar uno fijo.
- [ ] **¿Necesitan poder marcar campos concretos de su estructura de datos como sensibles por su NOMBRE** (ej. un campo `diagnostico` siempre es dato de salud, sin importar el contenido)? — esto ya existe (`field_name_pattern`, con pantalla propia en Privaro → Políticas), pero hay que decirles que existe, no esperar a que lo pidan.
- [ ] **¿Operan o tienen previsto operar fuera de España?** — la detección de Privaro hoy está orientada a formatos españoles (DNI, teléfono ES). Si hay demanda internacional real, es una conversación de producto a tener pronto, no una sorpresa después.

### Notificaciones y webhooks (lo automático ya no hace falta preguntarlo)

- [ ] ~~¿Quieren activar notificaciones de consumo 80%/100%?~~ — **ya no hace falta preguntarlo**, se activa solo en el paso 3 (ver Sección 6, "Ya resuelto"). Sí puedes preguntar si quieren AÑADIR más destinatarios además del admin + Miguel.
- [ ] **¿Quieren el webhook `dpo_report.generated`** para recibir el aviso en su propio sistema cuando se genera un informe DPO de un cliente suyo? Si sí: pídeles la URL ahora, no cuando lo necesiten.

---


---

## 1. Crear la organización partner + su cuenta de facturación

Ejecutar contra el proyecto Supabase `Privaro` (`evtfdgjliyhpubbrxzuq`). Sustituye los valores entre `[CORCHETES]`.

```sql
DO $$
DECLARE
  v_partner_org_id uuid;
  v_billing_id uuid;
BEGIN
  -- 1. Organización partner
  INSERT INTO organizations (name, slug, org_type, parent_org_id, plan)
  VALUES (
    '[NOMBRE DEL PARTNER]',                    -- ej. 'Octopus Technologies'
    '[slug-en-minusculas-sin-espacios]',       -- ej. 'octopus-technologies'
    'partner', NULL, 'pro'
  )
  RETURNING id INTO v_partner_org_id;

  -- 2. Su cuenta de facturación
  INSERT INTO billing_accounts (
    owner_org_id, plan, requests_limit, requests_used, overage_requests_used,
    overage_rate_per_1000, billing_cycle_start, discount_phase,
    initial_discount_pct, reviewed_discount_pct, discount_review_at
  )
  VALUES (
    v_partner_org_id,
    'pro',
    [TIER ACORDADO, ej. 500000],
    0, 0,
    [TARIFA OVERAGE €/1000, ej. 0.81 — pendiente de definir por defecto, confirmar caso a caso],
    CURRENT_DATE,                              -- arranca hoy; no poner fecha pasada salvo pruebas
    'initial',
    [DESCUENTO INICIAL, ej. 0.20],
    [DESCUENTO REVISION, ej. 0.15],
    CURRENT_DATE + INTERVAL '6 months'          -- fecha del escalón de descuento
  )
  RETURNING id INTO v_billing_id;

  UPDATE organizations SET billing_account_id = v_billing_id WHERE id = v_partner_org_id;

  RAISE NOTICE 'partner_org_id=%, billing_id=%', v_partner_org_id, v_billing_id;
END $$;
```

**Después de ejecutar**, recupera los IDs generados (los necesitas para el paso 3):

```sql
select o.id as partner_org_id, o.name, ba.id as billing_id, ba.requests_limit, ba.discount_review_at
from organizations o join billing_accounts ba on ba.id = o.billing_account_id
where o.slug = '[el mismo slug que usaste arriba]';
```

---

## 2. Invitar al primer usuario admin del partner

No se hace por SQL directo — usa el panel de Supabase para no tocar el esquema interno de Auth:

1. Supabase Dashboard → proyecto `Privaro` → **Authentication → Users → Add user → Send invitation**.
2. Introduce el email del contacto del partner (ej. `sergio@octopus.tech`). Esto le manda un magic link para que fije su contraseña.
3. Copia el **User UID** que aparece en la lista de usuarios tras la invitación — lo necesitas para el paso siguiente.

> ℹ️ **Nota histórica (ya no es necesario actuar, resuelto en el código):**
> Hay un trigger que asigna automáticamente a cada usuario nuevo `org_id = iCommunity Labs, role = 'developer'` al crearse. Esto rompía `partner-sub-accounts` (v1/v2) porque hacía `.maybeSingle()` sobre `user_roles` filtrando solo por `user_id`, y con dos filas la llamada fallaba. **Desde v3 (2026-07-03), la función busca explícitamente la fila cuya organización sea `org_type='partner'` entre TODAS las del usuario**, así que ya no hace falta borrar la fila automática a mano. Se deja documentado por si el síntoma reaparece en otro punto de la app que sí asuma una sola fila por usuario.
>
> ⚠️ **Esto sigue siendo válido:** `user_roles` tiene `UNIQUE(user_id, role)` — un mismo usuario no puede tener el rol `admin` dos veces, en ninguna org. Si vas a reutilizar tu propio email para pruebas internas y ya eres admin de otra org (ej. iCommunity Labs), usa un alias (`tunombre+partnerdemo@icommunity.io`) — si no, el INSERT del paso 3 falla por conflicto de constraint.

---

## 3. Vincular ese usuario a la organización partner con rol admin

```sql
-- Sustituye [USER_ID] por el UID copiado en el paso 2,
-- y [PARTNER_ORG_ID] por el id devuelto en el paso 1.

UPDATE profiles SET org_id = '[PARTNER_ORG_ID]' WHERE id = '[USER_ID]';

INSERT INTO user_roles (user_id, org_id, role)
VALUES ('[USER_ID]', '[PARTNER_ORG_ID]', 'admin')
ON CONFLICT (user_id, org_id) DO UPDATE SET role = EXCLUDED.role;
```

*Verificado contra el esquema real: `user_roles` tiene `UNIQUE (user_id, org_id)` y también `UNIQUE (user_id, role)` — un mismo usuario no puede tener el mismo rol duplicado ni pertenecer dos veces a la misma org. Si el usuario ya tuviera una fila con otro `org_id` (no debería pasar en un alta nueva), bórrala antes de insertar.*

---

## 3.5. Crear la clave de API de partner (SIEMPRE, no opcional)

**Actualizado 2026-07-27** tras un caso real: Octupus tuvo que pedir por email, uno a uno y con días de diferencia, `partner:write_children` y luego `partner:read_children` — algo completamente previsible, ya que **todo partner real va a querer gestionar sus propias sub-cuentas por API**, no solo desde el dashboard. Este paso ya no es opcional ni "a posteriori" — se hace en el alta, siempre, con ambos permisos desde el primer día.

```sql
-- Sustituye [PARTNER_ORG_ID] por el id del paso 1. Genera un hash real
-- (no el valor crudo) — mismo patrón validado hoy para Octupus/Robin AI.
with new_key as (
  select 'prvr_' || encode(gen_random_bytes(20), 'hex') as raw_key
)
insert into api_keys (org_id, name, key_hash, key_prefix, is_active, permissions, display_permissions)
select
  '[PARTNER_ORG_ID]',
  '[NOMBRE DEL PARTNER] — Partner API',
  encode(digest(raw_key, 'sha256'), 'hex'),
  left(raw_key, 12),
  true,
  array['proxy:read', 'proxy:write', 'partner:read_children', 'partner:write_children'],
  array['detect', 'protect', 'partner_read', 'partner_write']
from new_key
returning (select raw_key from new_key) as raw_key_para_el_partner, key_prefix, id;
```

**Entrégale al partner el `raw_key_para_el_partner`** — se muestra una única vez, guárdalo bien en ese momento (no queda recuperable después). Incluye `proxy:read`/`proxy:write` también, por si el partner quiere hacer llamadas directas de prueba con su propio pipeline además de gestionar sub-cuentas.

---



```sql
select
  o.name, o.org_type, o.slug,
  ba.plan, ba.requests_limit, ba.discount_phase, ba.discount_review_at,
  ur.role, p.org_id as profile_org_id
from organizations o
join billing_accounts ba on ba.id = o.billing_account_id
join user_roles ur on ur.org_id = o.id
join profiles p on p.id = ur.user_id
where o.id = '[PARTNER_ORG_ID]';
```

Confirma que sale exactamente 1 fila, con `org_type='partner'`, el tier y descuento correctos, `role='admin'`, y que `profile_org_id` coincide con `PARTNER_ORG_ID`.

---

## 5. Qué decirle al partner

Una vez verificado:

1. Pásale la **Guía de integración para partners** (`Privaro_Guia_Integracion_Partners_v1.docx` o la versión más reciente).
2. Dile que entre con el email invitado en [URL de la app] y fije su contraseña desde el magic link.
3. Una vez dentro, verá la sección **"Mis clientes"** — desde ahí da de alta a sus propios clientes finales de forma autónoma (nombre, sector, proveedor LLM, modelo) y obtiene la API key de cada uno al momento.
4. Recuérdale que la API key se muestra **una sola vez** — que la guarde bien en cuanto la vea.

---

## 6. Cosas que NO hace este runbook (todavía)

- No crea el webhook `dpo_report.generated` del partner — si lo quiere, pídele URL + genera un secreto y da de alta una fila en `org_webhooks` con `events = ARRAY['dpo_report.generated']`. Esto sí depende genuinamente de cada partner (necesitas su URL real), así que sigue siendo manual y caso por caso.
- **El cambio de cupón de Stripe en la fecha de revisión sigue siendo manual** (aunque desde 2026-07-23 recibes un email automático a soporte@icommunity.io en el momento exacto en que `discount_phase` pasa a `reviewed` — ver `apply_discount_reviews()`. El aviso es automático; el cambio real de `PARTNER20` a `PARTNER15` en el Dashboard de Stripe, no.

**Ya resuelto, no hace falta hacer nada manual para esto:**
- ~~No genera la partner API key~~ — desde el 2026-07-27, es el paso 3.5 de este mismo runbook, siempre, con ambos permisos por defecto.
- ~~No activa notificaciones de consumo 80%/100%~~ — desde el 2026-07-27, un trigger en `user_roles` las crea automáticamente en el momento del paso 3 (cuando se inserta el admin con `role='admin'`), con ese admin + Miguel como destinatarios. Verificado con datos reales el mismo día (Octupus, iCommunity Labs, Partner Demo, y una organización de prueba que ni siquiera sabíamos que existía — el trigger cubrió las cuatro sin distinción).

---

## Historial de uso de este runbook

| Fecha | Partner | Resultado |
|---|---|---|
| 2026-07-27 | Ampliación de la Sección 0 a cuestionario completo | A petición explícita de Miguel: "somos el primer partner con quien estamos aprendiendo, pero hay que automatizarlo al máximo para los siguientes". Cada pregunta nueva nace de algo real descubierto tarde con Octupus (permisos pedidos uno a uno, modelo de proveedor LLM sin resolver, necesidades de su vertical Odoo sin preguntar de antemano). Objetivo: que el próximo partner se configure en una sola sesión. |
| 2026-07-27 | Octupus Technologies — caso real que motivó esta actualización | Su clave inicial se creó sin ningún permiso `partner:*` (solo `proxy:read`/`proxy:write`), porque el runbook de entonces no contemplaba la clave de partner como paso estándar. Michel tuvo que pedir `partner:write_children` y `partner:read_children` por email, uno detrás de otro. Añadido el paso 3.5 (siempre, ambos permisos por defecto) para que esto no vuelva a pasar con el siguiente partner. De paso, corregida la Sección 6: las notificaciones de consumo que decía como pendientes de activar a mano ya se resuelven solas desde el trigger de `user_roles` de ese mismo día. |
| 2026-07-02 | Partner Demo (ficticio, pruebas) | Validado end-to-end: agregación de cuota, soft-cap, reset, aislamiento — ver conversación de referencia. Dos bugs reales encontrados y corregidos en el proceso (columna ambigua en RPC, codificación UTF-8). |
| 2026-07-03 | Partner Demo — alta de usuario admin (`maperez+partnerdemo@icommunity.io`) | Encontrado y documentado: trigger de auto-asignación (`developer` @ iCommunity Labs) en usuarios nuevos, que rompía `partner-sub-accounts` por `.maybeSingle()` con filas duplicadas. Corregido en el runbook (ver aviso en Sección 2). |
| 2026-07-03 | Prueba end-to-end de la pantalla "Mis clientes" | **Bug de infraestructura, no de esta función en concreto**: la tabla `billing_accounts` (creada por migración SQL manual) nunca recibió los privilegios `SELECT/INSERT/UPDATE/DELETE` para `service_role`/`authenticated` — solo `REFERENCES/TRIGGER/TRUNCATE`. Cualquier tabla creada así en el futuro tendría el mismo problema silencioso (las pruebas vía `execute_sql` no lo detectan porque ese canal usa un rol con privilegios de administrador, no `service_role`). Corregido con `GRANT` explícito + `ALTER DEFAULT PRIVILEGES` para que no vuelva a pasar. **Lección: cualquier tabla nueva creada por migración debe verificarse contra `information_schema.role_table_grants` antes de darla por lista para producción, no solo probarse por SQL directo.** También corregidos en el camino: `auth.getClaims()` no disponible en esta función (cambiado a `auth.getUser()`), y el `join` embebido de PostgREST devolviendo array en vez de objeto. |

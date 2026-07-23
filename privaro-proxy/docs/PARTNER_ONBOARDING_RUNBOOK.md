# Runbook interno — Alta de un partner nuevo

**Uso:** solo para el equipo de Privaro (Miguel / Claude). No es el documento
para partners — ese es `PARTNER_INTEGRATION_GUIDE.md`. Este es el "cómo lo
doy de alta yo", pensado para copiar-pegar-confirmar cuando llegue un
partner nuevo (p. ej. Octopus) tras firmar y pagar.

Probado end-to-end con "Partner Demo" el 2026-07-02 (ver Sección 5 de este
documento para el historial).

---

## 0. Antes de arrancar — datos que necesitas tener ya decididos

- [ ] Nombre del partner
- [ ] Tier de peticiones/mes acordado (ver `2. Tabla Tiers` del Excel de pricing)
- [ ] % descuento fase inicial y fase de revisión (normalmente 20% → 15%)
- [ ] Fecha del escalón de descuento (normalmente despliegue + 6 meses)
- [ ] Email del primer usuario admin del partner (quien va a gestionar sus clientes)
- [ ] Confirmación de que el pago/contrato ya está cerrado — este alta da acceso real

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

## 4. Verificación antes de avisar al partner

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

- No crea el webhook `dpo_report.generated` del partner — si lo quiere, pídele URL + genera un secreto y da de alta una fila en `org_webhooks` con `events = ARRAY['dpo_report.generated']`.
- No activa notificaciones de consumo 80%/100% — si las quiere, inserta filas en `org_notifications` (`type='usage_threshold'` y `type='usage_overage'`) con sus destinatarios.
- No genera la partner API key de solo-lectura (`/v1/partner/*`, para que el partner embeba compliance en su propio producto) — eso es aparte del acceso de dashboard; créala igual que se hizo para Partner Demo si el partner la va a usar.
- **El cambio de cupón de Stripe en la fecha de revisión sigue siendo manual** (aunque desde 2026-07-23 recibes un email automático a soporte@icommunity.io en el momento exacto en que `discount_phase` pasa a `reviewed` — ver `apply_discount_reviews()`. El aviso es automático; el cambio real de `PARTNER20` a `PARTNER15` en el Dashboard de Stripe, no.

---

## Historial de uso de este runbook

| Fecha | Partner | Resultado |
|---|---|---|
| 2026-07-02 | Partner Demo (ficticio, pruebas) | Validado end-to-end: agregación de cuota, soft-cap, reset, aislamiento — ver conversación de referencia. Dos bugs reales encontrados y corregidos en el proceso (columna ambigua en RPC, codificación UTF-8). |
| 2026-07-03 | Partner Demo — alta de usuario admin (`maperez+partnerdemo@icommunity.io`) | Encontrado y documentado: trigger de auto-asignación (`developer` @ iCommunity Labs) en usuarios nuevos, que rompía `partner-sub-accounts` por `.maybeSingle()` con filas duplicadas. Corregido en el runbook (ver aviso en Sección 2). |
| 2026-07-03 | Prueba end-to-end de la pantalla "Mis clientes" | **Bug de infraestructura, no de esta función en concreto**: la tabla `billing_accounts` (creada por migración SQL manual) nunca recibió los privilegios `SELECT/INSERT/UPDATE/DELETE` para `service_role`/`authenticated` — solo `REFERENCES/TRIGGER/TRUNCATE`. Cualquier tabla creada así en el futuro tendría el mismo problema silencioso (las pruebas vía `execute_sql` no lo detectan porque ese canal usa un rol con privilegios de administrador, no `service_role`). Corregido con `GRANT` explícito + `ALTER DEFAULT PRIVILEGES` para que no vuelva a pasar. **Lección: cualquier tabla nueva creada por migración debe verificarse contra `information_schema.role_table_grants` antes de darla por lista para producción, no solo probarse por SQL directo.** También corregidos en el camino: `auth.getClaims()` no disponible en esta función (cambiado a `auth.getUser()`), y el `join` embebido de PostgREST devolviendo array en vez de objeto. |

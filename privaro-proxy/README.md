# Privaro Proxy API — Guía de Despliegue Railway

## Estructura del proyecto

```
privaro-proxy/
├── app/
│   ├── main.py              # FastAPI app + CORS + lifespan
│   ├── config.py            # Variables de entorno (pydantic-settings)
│   ├── routers/
│   │   ├── health.py        # GET / y GET /health
│   │   └── proxy.py         # POST /v1/proxy/detect y /protect
│   ├── services/
│   │   ├── detector.py      # Motor PII (regex) — Phase 2: Presidio
│   │   ├── supabase.py      # Cliente Supabase service_role
│   │   └── auth.py          # Validación API Keys
│   └── models/
│       └── schemas.py       # Pydantic models
├── Dockerfile
├── railway.toml
├── requirements.txt
├── supabase_rpc.sql          # ← ejecutar en Supabase PRIMERO
└── .env.example
```

---

## PASO 0 — Supabase: ejecutar la función RPC

Antes de desplegar, ejecuta `supabase_rpc.sql` en el SQL Editor de Supabase.
Esto crea la función `increment_pipeline_stats` que el proxy usa para actualizar
los contadores de cada pipeline de forma atómica.

---

## PASO 1 — GitHub: crear el repositorio

```bash
# En tu máquina local
git init privaro-proxy
cd privaro-proxy
# Copia todos los archivos aquí
git add .
git commit -m "feat: privaro proxy api v0.1 mvp"
git remote add origin https://github.com/TU_USUARIO/privaro-proxy.git
git push -u origin main
```

---

## PASO 2 — Railway: crear el proyecto

1. Ve a **railway.app** → Log in con GitHub
2. Click **"New Project"** → **"Deploy from GitHub repo"**
3. Selecciona el repo `privaro-proxy`
4. Railway detecta el `Dockerfile` automáticamente → click **Deploy**

El primer deploy fallará porque faltan las variables de entorno. Es normal.

---

## PASO 3 — Railway: configurar variables de entorno

En tu proyecto Railway → **Settings** → **Variables** → añadir:

| Variable | Valor | Dónde obtenerlo |
|---|---|---|
| `ENVIRONMENT` | `production` | — |
| `SUPABASE_URL` | `https://stoucpzrbasxhbdhmblm.supabase.co` | Supabase → Settings → API |
| `SUPABASE_SERVICE_KEY` | `eyJ...` (service_role) | Supabase → Settings → API → service_role |
| `ENCRYPTION_KEY` | *(genera abajo)* | Terminal local |
| `PRIVARO_DEV_KEY` | *(dejar vacío en prod)* | — |

**Generar ENCRYPTION_KEY:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Después de añadir las variables → Railway redeploya automáticamente.

---

## PASO 4 — Railway: configurar dominio personalizado

1. Railway → tu proyecto → **Settings** → **Networking** → **Custom Domain**
2. Añadir: `proxy.privaro.io`
3. Copiar el CNAME que Railway te da
4. En tu DNS (Cloudflare/Namecheap/etc): añadir registro CNAME apuntando al valor de Railway
5. Esperar propagación (1-5 min con Cloudflare)

Si no tienes dominio todavía, Railway te asigna uno automático tipo:
`privaro-proxy-production.up.railway.app` — úsalo mientras tanto.

---

## PASO 5 — Verificar que funciona

```bash
# Health check
curl https://proxy.privaro.io/health

# Test del detector (con tu dev key del .env)
curl -X GET https://proxy.privaro.io/v1/proxy/test \
  -H "X-Privaro-Key: prvr_dev_localtest_only"

# Detect (sin guardar en DB)
curl -X POST https://proxy.privaro.io/v1/proxy/detect \
  -H "Content-Type: application/json" \
  -H "X-Privaro-Key: prvr_dev_localtest_only" \
  -d '{
    "pipeline_id": "TU_PIPELINE_UUID",
    "prompt": "Paciente: María García, DNI 34521789X, email: maria@test.es"
  }'

# Protect (guarda audit_log en Supabase)
curl -X POST https://proxy.privaro.io/v1/proxy/protect \
  -H "Content-Type: application/json" \
  -H "X-Privaro-Key: prvr_dev_localtest_only" \
  -d '{
    "pipeline_id": "TU_PIPELINE_UUID",
    "prompt": "Cliente: Juan López, IBAN ES91 2100 0418 4502 0005 1332",
    "options": {"mode": "tokenise", "include_detections": true}
  }'
```

Respuesta esperada de `/protect`:
```json
{
  "request_id": "req_a7f3b2c1",
  "protected_prompt": "Cliente: Juan López, IBAN [BK-0001]",
  "detections": [
    {"type": "iban", "severity": "critical", "action": "tokenised", "token": "[BK-0001]"}
  ],
  "stats": {"total_detected": 1, "total_masked": 1, "leaked": 0, "coverage_pct": 100.0},
  "audit_log_id": "uuid...",
  "gdpr_compliant": true
}
```

---

## PASO 6 — Conectar Lovable

En tu proyecto Lovable → **Settings** → **Environment Variables**:

```
VITE_PROXY_URL=https://proxy.privaro.io/v1
```

El Sandbox de Lovable ya tiene el switch condicional — al detectar esta variable
cambia de los mocks a la API real automáticamente.

---

## PASO 7 — Crear una API Key real en Supabase

En el Sandbox de Lovable ya funciona con la DEV_KEY. Para el piloto con un
cliente real, crea una API Key desde el Panel Admin → /app/admin/api-keys.

Formato de clave generada: `prvr_xxxxxxxxxxxx`
La clave completa se muestra **una sola vez** al crear. El hash SHA-256 se guarda en DB.

---

## Próximos pasos (roadmap)

| Fase | Qué añadir | Impacto |
|---|---|---|
| **Phase 2** | Presidio + spaCy es_core_news_lg | Detección semántica real (nombres sin keywords) |
| **Phase 3** | Tokens Vault con AES-256 real | Reversibilidad segura de tokens |
| **Phase 4** | `/proxy/restore` endpoint | DPO puede de-tokenizar |
| **Phase 5** | iBS webhook + `/webhooks/ibs` | Certificación blockchain Polygon |
| **Phase 6** | `/proxy/forward` | Proxy completo: proteger → LLM → restaurar |

---

## Nota sobre la alerta del linter de Supabase

**"Leaked password protection is disabled"**

Activar en: Supabase Dashboard → **Authentication** → **Settings** → **Password** →
activar **"Enable 'Have I Been Pwned' integration"**

No afecta al Proxy API — es una configuración de Supabase Auth para el login de usuarios.

# Privaro — Manual de uso y configuración para administradores

**Versión:** v1
**Última actualización:** 23 de julio de 2026
**Ámbito:** este manual cubre la aplicación completa de Privaro (`privaro.ai/app/...`) — acceso, todas las pantallas, y configuración de cuenta. Es válido tanto para organizaciones clientes directas como para partners.

> Este documento se actualiza automáticamente cada vez que un cambio de frontend afecta a una pantalla o flujo descrito aquí. Ver el historial de cambios al final.

---

## 1. Acceso a la aplicación

### 1.1 Registro e inicio de sesión

La aplicación tiene tres modos en la pantalla de acceso (`/auth`):

- **Iniciar sesión**: email + contraseña.
- **Crear cuenta**: email, contraseña, nombre completo y nombre de la organización. Al crear una cuenta nueva se crea también la organización.
- **Recuperar contraseña**: envía un enlace de restablecimiento al email.

Si te invitan a una organización ya existente (caso más habitual para partners y equipos), recibirás un email de invitación con un enlace mágico — no pasas por el formulario de "Crear cuenta", simplemente fijas tu contraseña desde ese enlace.

### 1.2 Verificación en dos pasos (MFA)

Privaro soporta autenticación de doble factor:

- **Activarla**: desde el flujo de configuración de MFA, se genera un código y hay que introducir un código de verificación de 6 dígitos para confirmarlo.
- **Al iniciar sesión** con MFA activado, tras el email/contraseña se pide el código de verificación de 6 dígitos antes de dar acceso.

### 1.3 Primera vez — asistente de configuración (Onboarding)

La primera vez que un usuario admin entra, aparece un asistente de 4 pasos:

1. **Bienvenida** — introducción rápida.
2. **Políticas** — aplicar un preset de reglas de protección de datos ya preparado (ver Sección 5, Policy Presets) o configurarlas después manualmente.
3. **Pipeline** — crear el primer pipeline (conexión a un proveedor de LLM).
4. **Integración** — instrucciones técnicas para empezar a llamar a la API.

Este asistente se puede volver a lanzar en cualquier momento desde **Settings → Onboarding Wizard → Reset** (solo visible para admins).

---

## 2. Estructura general de la interfaz

El menú lateral tiene tres bloques, según tu rol:

| Bloque | Quién lo ve | Contenido |
|---|---|---|
| Principal | Todos los roles | Conversations, Dashboard, AI Pipelines, PII Sandbox, Policy Engine, Agent Runs, Settings |
| Partner (si aplica) | Solo si tu organización es de tipo partner | Mis clientes |
| Admin | Admin y DPO (sección ampliada) / solo Admin (resto) | Leads, Audit Logs, Encryption Keys — y además, solo Admin: LLM Providers, Users, Tokens Vault, Policy Presets, API Keys, Billing, Admin Settings |

El bloque "Admin" se puede colapsar/expandir haciendo clic en su cabecera.

---

## 3. Pantallas principales (todos los roles)

### 3.1 Conversations

Un chat interactivo real para probar Privaro en conversación, no solo con un prompt suelto. Incluye:

- Lista de conversaciones, con carpetas, archivado, fijado y renombrado.
- Selector de pipeline (para elegir contra qué proveedor/modelo de LLM se prueba).
- Adjuntar archivos o pegar texto largo directamente en el chat.

Es el sitio más rápido para ver el efecto de Privaro en vivo sin tener que integrar nada todavía.

### 3.2 Dashboard

Resumen de actividad con 8 indicadores:

| Indicador | Qué mide |
|---|---|
| Total Requests | Peticiones API procesadas en todos los pipelines activos |
| PII Detected | Entidades de datos personales detectadas |
| Coverage | % de datos personales detectados que se protegieron con éxito |
| Incidents | Datos personales que llegaron a filtrarse al proveedor del LLM |
| Avg Latency | Latencia media de procesamiento |
| Blockchain Certified | % de logs de auditoría certificados en la blockchain de iBS |
| Avg Risk | Puntuación de riesgo media |
| High Risk | Eventos con riesgo ≥ 70% |

### 3.3 AI Pipelines

Un pipeline es la conexión entre tu caso de uso y un proveedor de LLM. Al crear uno se define:

- **Nombre** del pipeline.
- **Sector**: legal, healthcare, fintech o general.
- **Proveedor de LLM**: OpenAI, Anthropic, Google, Azure, DeepSeek o Custom.
- **Modelo** (depende del proveedor elegido) — por ejemplo, para Anthropic: `claude-opus-4-5`, `claude-sonnet-4-5`, `claude-haiku-4-5-20251001`.
- **Endpoint URL** (opcional, para proveedores personalizados).

Si un proveedor no tiene API key configurada, aparece deshabilitado en el selector. La interfaz avisa automáticamente si el proveedor elegido tiene un nivel de riesgo alto (no verificado para GDPR) o procesa datos fuera de la UE.

### 3.4 PII Sandbox

Entorno de pruebas para pegar un texto y ver, sin usarlo en producción, qué detecta Privaro y cómo lo protegería.

### 3.5 Policy Engine

Aquí se definen las reglas de qué hacer con cada tipo de dato personal detectado. Cada regla tiene:

| Campo | Valores posibles |
|---|---|
| **Entity Type** | full_name, email, phone, dni, ssn, iban, credit_card, address, medical_record, diagnosis, ip_address, custom |
| **Category** | personal, financial, special, business |
| **Action** | tokenise, pseudonymise, anonymise, block |
| **Regulation Reference** | referencia normativa asociada (texto libre) |
| **Priority** | prioridad de aplicación de la regla |
| **Custom Pattern** | expresión regular, si Entity Type = custom |

Las reglas se pueden aplicar a un pipeline concreto o a todos ("All Pipelines"). También se pueden aplicar **presets** ya preparados (paquetes de reglas por sector) con un clic, en vez de crear cada regla a mano.

### 3.6 Agent Runs

Historial de sesiones de agentes de IA, con las métricas de gobernanza de datos personales de cada sesión.

### 3.7 Settings

Configuración personal y de la organización, dividida en:

- **Profile**: tus datos personales de usuario.
- **Language**: español o inglés.
- **Organization**: nombre, slug, plan y región de datos de tu organización (solo lectura para la mayoría de roles).
- **Roles & Permissions**: qué rol(es) tienes tú en esta organización.
- **Change Password**: cambiar tu contraseña.
- **Onboarding Wizard** (solo admin): relanzar el asistente de configuración inicial.

---

## 4. Pantallas de Admin y DPO

Visibles para los roles **admin** y **dpo**:

### 4.1 Leads

Gestión de solicitudes recibidas desde la web pública (evaluaciones de riesgo de IA y solicitudes de beta). Relevante principalmente para el equipo de Privaro, no para el uso operativo diario de un cliente o partner.

### 4.2 Audit Logs

El registro auditable completo: cada evento de detección/protección de datos personales, con filtros por severidad, estado de certificación blockchain y nivel de riesgo, y opción de **exportar a CSV**.

### 4.3 Encryption Keys

Gestión de claves de cifrado para el Tokens Vault (ver 5.4). Soporta **BYOK** ("Bring Your Own Key"): puedes usar tu propia clave de cifrado — Privaro nunca almacena el material de esa clave.

---

## 5. Pantallas solo para Admin

Visibles únicamente para el rol **admin**:

### 5.1 LLM Providers

Gestión de los proveedores de LLM disponibles para tu organización: activar/desactivar cada uno, ver su nivel de riesgo, y añadir un proveedor personalizado con su propia API key.

### 5.2 Users

Gestión de usuarios de tu organización: invitar nuevos usuarios, y asignar uno de estos 4 roles:

| Rol | Qué ve |
|---|---|
| **admin** | Todo — incluyendo el bloque Admin completo |
| **dpo** | Todo excepto la parte exclusiva de admin (ve Leads, Audit Logs, Encryption Keys) |
| **developer** | Solo el bloque principal (sin sección Admin) |
| **viewer** | Solo el bloque principal, en modo lectura |

### 5.3 Policy Presets

Aquí se crean y mantienen los paquetes de reglas predefinidas que aparecen como "presets" en el Policy Engine (Sección 3.5) — nombre, sector al que aplica, icono, color, y el conjunto de reglas que incluye cada uno.

### 5.4 Tokens Vault

Gestión de los tokens reversibles generados al proteger datos personales, en dos pestañas:

- **Active Tokens**: tokens actualmente en la bóveda.
- **Tokens Log**: histórico de accesos a esos tokens.

### 5.5 API Keys

Generación de claves de API (`X-Privaro-Key`) para llamar al proxy. Cada clave se puede configurar con dos permisos independientes:

- **detect** → permiso `proxy:read` (solo analizar, sin persistir).
- **protect** → permiso `proxy:write` (proteger y registrar).

### 5.6 Billing

Plan actual, consumo, y **Security Configuration**:

| Opción | Qué hace |
|---|---|
| Enforce GDPR Providers | Solo permite usar proveedores de LLM verificados como conformes con GDPR |
| Sandbox Enabled | Permite o bloquea el uso del PII Sandbox (Sección 3.4) |

### 5.7 Admin Settings

Dos bloques:

- **Datos de la organización**: nombre, slug, email del DPO, región de datos.
- **Notificaciones**: activar/desactivar cada tipo de aviso —

| Notificación | Qué la dispara |
|---|---|
| Critical Incidents | Incidentes críticos |
| PII Leaks Detected | Fuga de datos personales detectada |
| Blockchain Certification Failed | Fallo al certificar en blockchain |
| Usage Threshold Exceeded | Umbral de consumo superado |
| Certificate Expiry | Vencimiento de certificado |

---

## 6. Sección Partner (si tu organización es un partner)

Si tu organización está configurada como partner, verás un bloque adicional **"Mis clientes"** para dar de alta y gestionar tus propios clientes finales de forma autónoma.

Esta sección tiene su propia guía específica, orientada a la integración técnica: **Privaro — Guía de integración rápida para partners**. Consulta ese documento para el detalle de API, webhooks y activación de pago.

---

## 7. Resumen — qué rol necesitas para cada cosa

| Necesitas... | Rol mínimo |
|---|---|
| Usar el chat, ver el dashboard, crear pipelines, probar el sandbox, gestionar políticas | developer |
| Ver el registro de auditoría y exportarlo | dpo |
| Gestionar claves de cifrado | dpo |
| Invitar usuarios y asignar roles | admin |
| Gestionar proveedores de LLM, presets de políticas, tokens vault, API keys, facturación y configuración de la organización | admin |
| Dar de alta clientes finales (si eres partner) | admin |

---

## Historial de cambios

| Versión | Fecha | Cambios |
|---|---|---|
| v1 | 2026-07-23 | Primera versión. Documentadas todas las pantallas de la aplicación a partir de revisión directa del código: acceso y MFA, onboarding, las 7 pantallas del bloque principal, las 3 de Admin/DPO, las 7 exclusivas de Admin, y la sección Partner. |

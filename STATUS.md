# STATUS — Privaro

_Última actualización: 2026-09-23_

---

## Estado actual

No queda trabajo técnico en curso. Todo lo abordado en la última sesión se completó, se desplegó y se verificó en producción real (no solo en código) antes de cerrar. Lo único pendiente son seguimientos comerciales que dependen de respuesta externa (ver "Contexto importante").

## Última sesión

Sesión larga y multi-frente. En orden aproximado:

- Auditoría de documentación en los 10 repos `privaro-*`: arreglados 4 repos de ejemplo (LangChain, CrewAI, OpenAI Agents, n8n) que tenían bugs reales de código, no solo de texto; reescrito `privaro-agents` desde un borrador sin terminar.
- Trabajo comercial: one-pager para TSS/Constellation, presentación en Gamma para una reunión con NTT DATA, análisis de una respuesta técnica de un contacto de LinkedIn (Eleva AI), correo de seguimiento a Acurio tras una reunión técnica sobre tokenización vs. hash+caché.
- Redespliegue de 4 Edge Functions de Supabase (`send-demo-request`, `send-techbrief-request`, `usage-alerts`, `send-email-resend`), con un bug real de bundler encontrado y corregido de camino.
- **Auditoría completa de cómo se comunica RAG en la web**, que llevó a:
  - Un bug crítico de producción: `protect-document` con subida de fichero (PDF/DOCX/XLSX/CSV/EML) colisionaba de ruta con la versión de texto/JSON y quedaba inalcanzable — arreglado, separado a `/protect-document/upload`, verificado con una subida de fichero real.
  - Página dedicada `/rag-pii-protection`, entrada de menú, mención en home, enlace en el footer, actualización de `/docs` (referencia de API completada) y de la página de precios (RAG como *feature* del plan Business).
  - Dos bugs de seguimiento autoinfligidos, encontrados y corregidos: `nav.partners` sin traducir en inglés (se borró sin querer al añadir otra clave), y una descripción de endpoint que mi propio fix de rutas había dejado desactualizada.
- **Facturación de RAG ajustada al coste real**: hasta ahora, un documento de 2.000.000 de caracteres consumía la misma "1 petición" que un mensaje de chat de 50 caracteres. Ahora Ingest pondera por tamaño (1 unidad cada 2.000 caracteres) y Retrieval Guard por número de fragmentos del lote. De paso, se encontró que la subida de fichero no llamaba a control de cuota *en absoluto* — arreglado también. Función SQL (`increment_billing_requests`) probada en vivo contra una cuenta real antes de darla por buena, incluyendo el caso límite de un salto que cruza el límite del plan de golpe.
- Investigado el aviso de Supabase sobre el fin de los *grants* automáticos de la Data API (30 oct 2026): confirmado que no afecta a nada existente, y establecida la práctica a seguir de aquí en adelante (ver Decisiones tomadas).

## Decisiones tomadas

- [2026-09-23] Toda tabla nueva de Supabase debe incluir `GRANT` explícito en la misma migración/`execute_sql` — `service_role` para tablas internas del backend (el proxy nunca se autentica como otro rol), y además `authenticated` (apoyado en RLS) para tablas que el dashboard del frontend consulta directamente.
- [2026-09-23] Facturación de Ingest ponderada por caracteres (1 unidad / 2.000 caracteres, mínimo 1) y de Retrieval Guard por número de fragmentos del lote, en vez de un valor plano de 1 por petición.
- [2026-09-20] `protect-document` con subida de fichero movido a su propia ruta (`/protect-document/upload`) tras confirmar que colisionaba con el endpoint de texto y quedaba inalcanzable.
- [2026-09-20] RAG (Privaro Ingest + Retrieval Guard) se comunica como *feature* del plan Business en adelante — sin crear un mecanismo de módulo/precio aparte, por ser el cambio de menor riesgo dado que no había ninguna infraestructura de precios por módulo ya construida.

## Bloqueantes

Ninguno técnico.

## Próximos pasos

1. Seguimiento comercial: esperar respuesta de Íñigo Erana (Acurio) al correo enviado.
2. Reunión pendiente con Agustina Rocca (NTT DATA) — presentación en Gamma ya lista y revisada.
3. Valorar si perseguir programas de partners ISV (marketplace de Snowflake, programas de Azure/AWS) como vía de distribución — surgió del análisis de riesgo de comoditización tras la reunión con Acurio.
4. Deuda técnica anotada, no urgente: `document.py` resuelve la clave de cifrado leyendo `settings.ENCRYPTION_KEY` directamente en vez de pasar por el patrón BYOK-aware (`get_org_default_key_id` + `resolve_encryption_key`) que usa el resto del sistema.
5. Deuda técnica anotada, no urgente: `TOKEN_PREFIX` y la lógica de tokenización están duplicadas en varios routers (`proxy.py`, `document.py`, `agent.py`) en vez de tener una única fuente compartida.

## Contexto importante

- El backend (`privaro-proxy`) accede a Supabase exclusivamente vía la Data API (PostgREST, `/rest/v1`) con la clave `service_role` — nunca hay conexión directa a Postgres. El frontend (`privaro-7938a3bd`) sí hace consultas directas a Supabase con el rol `authenticated` en 9 ficheros, para el dashboard.
- Railway (backend) tiene redeploy automático en cada push a `main`. `privaro-7938a3bd` (frontend, gestionado con Lovable) se publica de forma manual — cualquier cambio de frontend necesita que el usuario lo publique explícitamente antes de estar en vivo.
- Organización de prueba interna para verificación en producción: iCommunity Labs (org `d4e09279-eb50-4c38-a8ba-de3c548d6292`, billing account `784a16ce-2b66-4d40-b0d5-1f3475a44e21`, plan free, límite 500). Pipeline de prueba: `eb48edec-2ed6-4241-aa17-af8cd394a804` (Medical Document Reviewer). Clave de API de prueba: `prvr_6c84adecd74bd1df466f14fc83d8d004a4d43573`.
- No existe `CLAUDE.md` en este repo. Podría ser útil crear uno con las convenciones de arquitectura del proyecto, pero no se ha creado sin indicación explícita del usuario.

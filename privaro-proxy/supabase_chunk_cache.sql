-- ============================================================
-- Supabase SQL — caché de protección de chunks (Privaro Retrieval Guard,
-- Fase 2 del plan de RAG)
-- Ejecutar en SQL Editor ANTES de desplegar esta versión del Proxy API
-- ============================================================
--
-- Por qué existe: a diferencia de la ingesta (coste único por
-- documento), este endpoint está en el camino crítico de CADA pregunta
-- de un usuario en un sistema RAG. Si el mismo chunk (o uno con
-- contenido idéntico, reindexado con otro id) se recupera repetidas
-- veces, no tiene sentido volver a ejecutar Tier 1 + Tier 2 cada vez —
-- la clave de caché es el HASH DEL CONTENIDO, no el chunk_id que
-- proporciona el cliente (que puede cambiar entre reindexaciones del
-- mismo texto).

CREATE TABLE IF NOT EXISTS public.chunk_protection_cache (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            uuid NOT NULL,
  content_hash      text NOT NULL,  -- sha256 hex del texto original del chunk
  protected_text    text NOT NULL,
  detections_count  integer NOT NULL DEFAULT 0,
  created_at        timestamptz NOT NULL DEFAULT now(),
  last_used_at      timestamptz NOT NULL DEFAULT now()
);

-- Aislamiento por organización explícito en el índice de búsqueda -- un
-- hash de contenido idéntico entre dos orgs distintas NUNCA debe
-- compartir caché, aunque la probabilidad de colisión real sea
-- despreciable. Mejor no depender de eso.
CREATE UNIQUE INDEX IF NOT EXISTS idx_chunk_cache_org_hash
  ON public.chunk_protection_cache (org_id, content_hash);

-- Limpieza de entradas antiguas sin usar -- una tarea programada (cron
-- de Supabase, o el propio worker en un futuro) puede borrar filas con
-- last_used_at antiguo para no crecer sin límite.
CREATE INDEX IF NOT EXISTS idx_chunk_cache_last_used
  ON public.chunk_protection_cache (last_used_at);

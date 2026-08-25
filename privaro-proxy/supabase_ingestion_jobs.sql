-- ============================================================
-- Supabase SQL — tabla de jobs de ingesta asíncrona (Privaro Ingest,
-- Fase 1 del plan de RAG)
-- Ejecutar en SQL Editor ANTES de desplegar esta versión del Proxy API
-- ============================================================
--
-- Por qué existe: la Fase 0 del plan de RAG midió con datos reales que
-- Presidio (Tier 2 NLP) puede tardar >30s en documentos de cientos de
-- KB, y que el propio motor de compresión (Kompress) puede tumbar el
-- proceso completo por encima de ~30K caracteres (sin resolver aún —
-- por eso Context Optimization NO se activa en /protect-document).
-- Un documento de ingesta grande no puede procesarse de forma síncrona
-- dentro de una única petición HTTP sin arriesgar timeouts en cascada.
--
-- Diseño deliberado: el worker que consume esta tabla debe correr como
-- un PROCESO SEPARADO de la API que sirve tráfico de chat en vivo — si
-- Kompress se reactiva aquí en el futuro y vuelve a crashear, no debe
-- poder tumbar la API de producción.

CREATE TABLE IF NOT EXISTS public.ingestion_jobs (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                uuid NOT NULL,
  pipeline_id           uuid NOT NULL,
  document_id_external  text,
  status                text NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
  document              text NOT NULL,
  options               jsonb NOT NULL DEFAULT '{}'::jsonb,
  char_count            integer NOT NULL,
  result                jsonb,
  error                 text,
  created_at            timestamptz NOT NULL DEFAULT now(),
  started_at            timestamptz,
  completed_at          timestamptz
);

-- El worker hace polling filtrando por status — este índice parcial
-- mantiene esa consulta barata sin importar cuántos jobs históricos
-- (completed/failed) se acumulen con el tiempo.
CREATE INDEX IF NOT EXISTS idx_ingestion_jobs_pending
  ON public.ingestion_jobs (created_at)
  WHERE status IN ('pending', 'processing');

CREATE INDEX IF NOT EXISTS idx_ingestion_jobs_org
  ON public.ingestion_jobs (org_id);

-- Reclama atómicamente el job pendiente más antiguo para procesarlo.
-- FOR UPDATE SKIP LOCKED es lo que hace esto seguro si en algún momento
-- corre más de una instancia del worker a la vez -- cada una se queda
-- con un job distinto en vez de pelearse por el mismo o procesarlo dos
-- veces.
CREATE OR REPLACE FUNCTION public.claim_next_ingestion_job()
RETURNS SETOF public.ingestion_jobs
LANGUAGE plpgsql
AS $$
DECLARE
  claimed_id uuid;
BEGIN
  SELECT id INTO claimed_id
  FROM public.ingestion_jobs
  WHERE status = 'pending'
  ORDER BY created_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1;

  IF claimed_id IS NULL THEN
    RETURN;
  END IF;

  RETURN QUERY
  UPDATE public.ingestion_jobs
  SET status = 'processing', started_at = now()
  WHERE id = claimed_id
  RETURNING *;
END;
$$;

-- RLS: el proxy accede con la service_role key (bypassa RLS, igual que
-- el resto de tablas de este proyecto — ver la nota en app/services/supabase.py),
-- pero se activa RLS igualmente por si en el futuro se expone consulta
-- directa desde el dashboard con el token del usuario final.
ALTER TABLE public.ingestion_jobs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "org members can view their own ingestion jobs"
  ON public.ingestion_jobs FOR SELECT
  USING (org_id IN (
    SELECT org_id FROM public.profiles WHERE id = auth.uid()
  ));

-- ============================================================
-- Supabase SQL — función RPC para incrementar contadores del pipeline
-- Ejecutar en SQL Editor ANTES de desplegar el Proxy API
-- ============================================================

-- Función de incremento atómico (evita race conditions)
CREATE OR REPLACE FUNCTION public.increment_pipeline_stats(
  p_pipeline_id   uuid,
  p_requests      bigint DEFAULT 1,
  p_detected      bigint DEFAULT 0,
  p_masked        bigint DEFAULT 0,
  p_leaked        bigint DEFAULT 0,
  p_latency_ms    integer DEFAULT 0
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  UPDATE public.pipelines
  SET
    total_requests      = total_requests + p_requests,
    total_pii_detected  = total_pii_detected + p_detected,
    total_pii_masked    = total_pii_masked + p_masked,
    total_leaked        = total_leaked + p_leaked,
    avg_latency_ms      = CASE
      WHEN total_requests = 0 THEN p_latency_ms
      ELSE ((avg_latency_ms * total_requests) + p_latency_ms) / (total_requests + 1)
    END
  WHERE id = p_pipeline_id;
END;
$$;

-- Grant execution to service_role (called by Proxy API)
GRANT EXECUTE ON FUNCTION public.increment_pipeline_stats TO service_role;

-- ============================================================
-- También necesitas la función update_updated_at si no existe ya:
-- ============================================================
CREATE OR REPLACE FUNCTION public.update_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

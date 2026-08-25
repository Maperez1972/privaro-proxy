"""
Ingestion worker — Privaro Ingest, Fase 1 del plan de RAG.

Proceso DELIBERADAMENTE SEPARADO de la API que sirve tráfico de chat en
vivo (app/main.py). Consume la tabla `ingestion_jobs` (ver
supabase_ingestion_jobs.sql) y procesa documentos grandes que
/v1/proxy/protect-document decide no procesar de forma síncrona.

Por qué un proceso separado, no un hilo de fondo dentro de la propia
API: la Fase 0 del plan de RAG encontró que Kompress puede crashear el
proceso ENTERO (SIGABRT nativo de ONNX Runtime, no una excepción de
Python capturable) en documentos por encima de ~30K caracteres. Aunque
/protect-document no llama a Context Optimization todavía (bloqueado
hasta resolver ese hallazgo), el worker de ingesta es exactamente el
sitio donde alguien reactivaría eso en el futuro sobre documentos
grandes — mantenerlo en un proceso aparte significa que, si eso pasa,
se lleva por delante el worker, no la API que atiende a Robin/Octupus
en ese mismo instante.

Despliegue: pensado para correr como un SERVICIO SEPARADO en Railway
(o el orquestador que sea), con su propio comando de arranque:

    python -m app.worker.ingestion_worker

No comparte proceso con `uvicorn app.main:app`.
"""
import asyncio
import time
import traceback

from app.services import detector, supabase as db
from app.services.chunker import chunk_protected_document
from app.services import policy_engine as pe

# Reutiliza exactamente la misma lógica de tokenización que /protect y
# /protect-document, para no duplicar (y arriesgar divergir de) las
# reglas de reemplazo de texto -- ver la nota de deuda técnica ya
# existente sobre PREFIX_MAP duplicado en detector.py/proxy.py/
# relay.py/agent.py; esto habría sido una cuarta copia si no se
# reutilizara así.
from app.routers.proxy import _apply_tokenization, _build_vault_rows
from app.services.key_manager import resolve_encryption_key

POLL_INTERVAL_SECONDS = 3.0
IDLE_LOG_EVERY_N_POLLS = 20  # evita llenar los logs cuando no hay trabajo


async def _process_job(job: dict) -> None:
    job_id = job["id"]
    org_id = job["org_id"]
    pipeline_id = job["pipeline_id"]
    document = job["document"]
    options = job.get("options") or {}
    chunk_size = options.get("chunk_size", 512)
    use_nlp = options.get("use_nlp", True)
    reversible = options.get("reversible", True)

    t0 = time.monotonic()
    try:
        pipeline = await db.get_pipeline(pipeline_id)
        if not pipeline:
            await db.fail_ingestion_job(job_id, "pipeline_not_found")
            return

        policies = await db.get_policy_rules(org_id, pipeline_id=pipeline_id) or []
        custom_pattern_rules = [r for r in policies if r.get("custom_pattern")]

        loop = asyncio.get_event_loop()
        detections = await loop.run_in_executor(
            None, detector.detect, document, use_nlp, custom_pattern_rules,
        )

        policy_context = {
            "provider": "", "user_role": "developer", "data_region": "EU",
            "agent_mode": False, "pipeline_sector": pipeline.get("sector", "general"),
            "default_action": options.get("mode", "tokenise"),
        }
        if policies and detections:
            detections = pe.apply_policies(detections, policies, policy_context)
        else:
            for d in detections:
                d.action = "tokenised"

        counters: dict = {}
        protected_document = _apply_tokenization(document, detections, counters)

        raw_chunks = chunk_protected_document(protected_document, chunk_size=chunk_size)
        chunks = [
            {"index": c.index, "text": c.text, "char_start": c.char_start, "char_end": c.char_end}
            for c in raw_chunks
        ]

        if reversible:
            enc_key, enc_key_id = await resolve_encryption_key(org_id)
            vault_rows = await _build_vault_rows(
                document, detections, org_id, pipeline_id, None, enc_key, enc_key_id,
            )
            if vault_rows:
                await db.insert_tokens_batch(vault_rows)

        result = {
            "protected_document": protected_document,
            "chunks": chunks,
            "detections": [d.model_dump() for d in detections],
            "stats": {
                "total_detected": len(detections),
                "total_masked": sum(1 for d in detections if d.action in ("tokenised", "anonymised")),
                "char_count": len(document),
                "chunk_count": len(chunks),
                "processing_ms": int((time.monotonic() - t0) * 1000),
            },
        }
        await db.complete_ingestion_job(job_id, result)
        print(f"[IngestionWorker] job {job_id} completed ({len(document)} chars, {len(chunks)} chunks, "
              f"{int((time.monotonic() - t0) * 1000)}ms)")

    except Exception as e:
        print(f"[IngestionWorker] job {job_id} failed: {e}")
        traceback.print_exc()
        await db.fail_ingestion_job(job_id, str(e))


async def run_forever() -> None:
    print("[IngestionWorker] starting — polling ingestion_jobs every "
          f"{POLL_INTERVAL_SECONDS}s")
    idle_polls = 0
    while True:
        job = await db.claim_next_pending_ingestion_job()
        if job is None:
            idle_polls += 1
            if idle_polls % IDLE_LOG_EVERY_N_POLLS == 0:
                print(f"[IngestionWorker] idle ({idle_polls} polls, no pending jobs)")
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
            continue

        idle_polls = 0
        await _process_job(job)


if __name__ == "__main__":
    asyncio.run(run_forever())

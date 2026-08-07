"""Health check endpoints."""
from fastapi import APIRouter
from app.models.schemas import HealthResponse
from app.config import settings
from app.services.nlp_engine import is_available as nlp_is_available
from app.services.context_optimizer import kompress_ready

router = APIRouter()


def _detector_label() -> str:
    # Was hardcoded as "regex-v1" regardless of whether Presidio/spaCy
    # actually loaded — found 2026-07-23 while investigating roadmap item
    # #7. The health check had been silently lying about detector
    # capability since NLP (Tier 2) was added; this reflects the real,
    # live state instead.
    return "regex-v1+presidio-nlp" if nlp_is_available() else "regex-v1"


def _build_health_response() -> HealthResponse:
    # Added 2026-07-30 — real finding: NLP degradation was only visible by
    # parsing the `detector` string, with `status` always "ok" regardless.
    # A monitoring probe watching for `status != "ok"` (the common,
    # low-effort way to wire an uptime check) would NEVER catch a Tier-2
    # NLP outage — Tier-1-only regex has real, documented detection gaps
    # (see fix/tier1-detection-gaps), so silently running without NLP is a
    # compliance-relevant degradation, not just a performance one. `status`
    # now reflects that explicitly, and `nlp_active` is exposed as a plain
    # boolean for anything that wants to check it directly instead of
    # string-matching `detector`.
    active = nlp_is_available()

    # Added 2026-08-07 — real production incident: requirements.txt was
    # missing the [proxy] extra Kompress needs (onnxruntime/transformers).
    # The app started fine, /health said status=ok the whole time, and the
    # only way to see Kompress had failed to load was grepping container
    # logs for "background model download failed". If warmup was
    # requested (CONTEXT_OPTIMIZATION_WARMUP=true) but the model still
    # isn't ready, that's a real degradation — surfaced the same way the
    # NLP one is, instead of requiring log access to notice.
    kompress_ok = kompress_ready()
    warmup_expected = settings.CONTEXT_OPTIMIZATION_WARMUP
    degraded = (not active) or (warmup_expected and not kompress_ok)

    return HealthResponse(
        status="ok" if not degraded else "degraded",
        version="0.1.0",
        environment=settings.ENVIRONMENT,
        detector=_detector_label(),
        supabase="connected" if settings.SUPABASE_URL else "not configured",
        nlp_active=active,
        kompress_ready=kompress_ok,
    )


@router.get("/", response_model=HealthResponse)
async def root():
    return _build_health_response()


@router.get("/health", response_model=HealthResponse)
async def health():
    return _build_health_response()

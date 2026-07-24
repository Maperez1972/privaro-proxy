"""Health check endpoints."""
from fastapi import APIRouter
from app.models.schemas import HealthResponse
from app.config import settings
from app.services.nlp_engine import is_available as nlp_is_available

router = APIRouter()


def _detector_label() -> str:
    # Was hardcoded as "regex-v1" regardless of whether Presidio/spaCy
    # actually loaded — found 2026-07-23 while investigating roadmap item
    # #7. The health check had been silently lying about detector
    # capability since NLP (Tier 2) was added; this reflects the real,
    # live state instead.
    return "regex-v1+presidio-nlp" if nlp_is_available() else "regex-v1"


@router.get("/", response_model=HealthResponse)
async def root():
    return HealthResponse(
        status="ok",
        version="0.1.0",
        environment=settings.ENVIRONMENT,
        detector=_detector_label(),
        supabase="connected" if settings.SUPABASE_URL else "not configured",
    )


@router.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(
        status="ok",
        version="0.1.0",
        environment=settings.ENVIRONMENT,
        detector=_detector_label(),
        supabase="connected" if settings.SUPABASE_URL else "not configured",
    )

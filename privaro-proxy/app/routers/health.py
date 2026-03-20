"""Health check endpoints."""
from fastapi import APIRouter
from app.models.schemas import HealthResponse
from app.config import settings

router = APIRouter()


@router.get("/", response_model=HealthResponse)
async def root():
    return HealthResponse(
        status="ok",
        version="0.1.0",
        environment=settings.ENVIRONMENT,
        detector="regex-v1",
        supabase="connected" if settings.SUPABASE_URL else "not configured",
    )


@router.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(
        status="ok",
        version="0.1.0",
        environment=settings.ENVIRONMENT,
        detector="regex-v1",
        supabase="connected" if settings.SUPABASE_URL else "not configured",
    )

@router.get("/ibs-test")
async def ibs_test():
    from app.services import ibs
    from app.config import settings
    return {
        "ibs_api_key_set": bool(settings.IBS_API_KEY),
        "ibs_api_key_prefix": settings.IBS_API_KEY[:10] + "..." if settings.IBS_API_KEY else "EMPTY",
        "ibs_base": settings.IBS_API_BASE,
        "headers_preview": ibs._get_ibs_headers().get("Authorization", "")[:20] + "...",
    }

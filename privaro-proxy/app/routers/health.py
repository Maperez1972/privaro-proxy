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


@router.get("/health/ibs-test")
async def ibs_test():
    """Diagnóstico: verifica que IBS_API_KEY llega al contenedor."""
    key = settings.IBS_API_KEY or ""
    return {
        "ibs_api_key_set": bool(key),
        "ibs_api_key_length": len(key),
        "ibs_api_key_prefix": key[:12] + "..." if key else "EMPTY",
        "ibs_base": settings.IBS_API_BASE,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/health/ibs-certify-test")
async def ibs_certify_test():
    """Test directo usando ibs._post_evidence — incluye signatures:[]"""
    from app.services import ibs
    # Usa directamente la función del módulo ibs — mismo código que certify_audit_log
    evidence_id = await ibs._post_evidence(
        title="privaro_health_test_001",
        payload_hash=ibs._build_hash({"test": True, "source": "health-check"}),
    )
    return {
        "success": evidence_id is not None,
        "evidence_id": evidence_id,
        "ibs_key_prefix": settings.IBS_API_KEY[:12] + "..." if settings.IBS_API_KEY else "EMPTY",
    }

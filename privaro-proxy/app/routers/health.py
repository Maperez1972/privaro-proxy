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
    """Test directo de POST /evidences — certifica un evento de prueba."""
    import hashlib, base64, json
    import httpx
    from app.services import ibs

    key = settings.IBS_API_KEY or ""
    if not key:
        return {"error": "IBS_API_KEY not set"}

    # Build a test payload hash
    payload = {"test": True, "source": "privaro-health-check"}
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sha512 = hashlib.sha512(payload_json.encode()).digest()
    payload_hash = base64.b64encode(sha512).decode()

    ibs_body = {
        "payload": {
            "title": "privaro_health_test",
            "files": [{"name": "test.json", "file": payload_hash}],
        }
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                f"{settings.IBS_API_BASE}/evidences",
                headers=ibs._get_ibs_headers(),
                json=ibs_body,
            )
            return {
                "status": r.status_code,
                "response": r.text[:500],
                "headers_auth_prefix": ibs._get_ibs_headers()["Authorization"][:20] + "...",
            }
    except Exception as e:
        return {"error": str(e)}

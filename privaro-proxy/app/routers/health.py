"""Health check endpoints."""
from fastapi import APIRouter
from app.models.schemas import HealthResponse
from app.config import settings

router = APIRouter()

@router.get("/", response_model=HealthResponse)
async def root():
    return HealthResponse(status="ok", version="0.1.0", environment=settings.ENVIRONMENT,
        detector="regex-v1", supabase="connected" if settings.SUPABASE_URL else "not configured")

@router.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", version="0.1.0", environment=settings.ENVIRONMENT,
        detector="regex-v1", supabase="connected" if settings.SUPABASE_URL else "not configured")

@router.get("/health/ibs-test")
async def ibs_test():
    key = settings.IBS_API_KEY or ""
    return {"ibs_api_key_set": bool(key), "ibs_api_key_length": len(key),
            "ibs_api_key_prefix": key[:12] + "..." if key else "EMPTY",
            "ibs_base": settings.IBS_API_BASE, "environment": settings.ENVIRONMENT}

@router.get("/health/ibs-source")
async def ibs_source():
    try:
        with open("/app/app/services/ibs.py", "r") as f:
            content = f.read()
        lines = content.split("\n")
        return {"has_signatures_field": '"signatures"' in content, "lines_33_45": "\n".join(lines[30:45])}
    except Exception as e:
        return {"error": str(e)}

@router.get("/health/ibs-v1")
async def ibs_v1():
    """Test signatures: [] vacio"""
    import hashlib, base64, json, httpx
    key = settings.IBS_API_KEY or ""
    payload_hash = base64.b64encode(hashlib.sha512(b"test").digest()).decode()
    body = json.dumps({"payload": {"title": "privaro_test_v1", "files": [{"name": "t.json", "file": payload_hash}]}, "signatures": []})
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(f"{settings.IBS_API_BASE}/evidences",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            content=body.encode())
    return {"variant": "signatures:[]", "status": r.status_code, "response": r.text[:300]}

@router.get("/health/ibs-v2")
async def ibs_v2():
    """Test sin campo signatures"""
    import hashlib, base64, json, httpx
    key = settings.IBS_API_KEY or ""
    payload_hash = base64.b64encode(hashlib.sha512(b"test").digest()).decode()
    body = json.dumps({"payload": {"title": "privaro_test_v2", "files": [{"name": "t.json", "file": payload_hash}]}})
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(f"{settings.IBS_API_BASE}/evidences",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            content=body.encode())
    return {"variant": "no_signatures", "status": r.status_code, "response": r.text[:300]}

@router.get("/health/ibs-v3")
async def ibs_v3():
    """Test signatures dentro de payload"""
    import hashlib, base64, json, httpx
    key = settings.IBS_API_KEY or ""
    payload_hash = base64.b64encode(hashlib.sha512(b"test").digest()).decode()
    body = json.dumps({"payload": {"title": "privaro_test_v3", "files": [{"name": "t.json", "file": payload_hash}], "signatures": []}})
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(f"{settings.IBS_API_BASE}/evidences",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            content=body.encode())
    return {"variant": "signatures_inside_payload", "status": r.status_code, "response": r.text[:300]}

@router.get("/health/ibs-v4")
async def ibs_v4():
    """Test multipart/form-data"""
    import hashlib, base64, json, httpx
    key = settings.IBS_API_KEY or ""
    payload_hash = base64.b64encode(hashlib.sha512(b"test").digest()).decode()
    payload_obj = {"title": "privaro_test_v4", "files": [{"name": "t.json", "file": payload_hash}]}
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(f"{settings.IBS_API_BASE}/evidences",
            headers={"Authorization": f"Bearer {key}"},
            data={"payload": json.dumps(payload_obj), "signatures": "[]"})
    return {"variant": "multipart_form", "status": r.status_code, "response": r.text[:300]}

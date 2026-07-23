"""
Privaro Proxy API — v0.3.0
Privacy Infrastructure for Enterprise AI · iCommunity Labs
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.routers import proxy, health, webhooks, agent, document, relay
from app.config import settings
from app.services import ibs


class UTF8JSONResponse(JSONResponse):
    """
    Explicit charset=utf-8 in Content-Type. Without this, some HTTP clients
    (notably Windows PowerShell's Invoke-WebRequest) default to Latin-1 when
    decoding the response body, mangling non-ASCII characters like em-dashes
    or accented names (e.g. "Cliente A" showing as "Clientea Â").
    """
    media_type = "application/json; charset=utf-8"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    print(f"🚀 Privaro Proxy API starting — env: {settings.ENVIRONMENT}")
    if settings.IBS_API_KEY:
        try:
            registered = await ibs.register_webhook()
            print(f"[iBS] Webhook: {'✅ registered' if registered else '⚠️ failed (non-critical)'}")
        except Exception as e:
            print(f"[iBS] Webhook error (non-critical): {e}")
    else:
        print("[iBS] IBS_API_KEY not set — blockchain disabled")
    yield
    print("🛑 Privaro Proxy API shutting down")


app = FastAPI(
    title="Privaro Proxy API",
    description="Privacy Infrastructure for Enterprise AI — iCommunity Labs",
    version="0.3.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url=None,
    default_response_class=UTF8JSONResponse,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Routers
app.include_router(health.router, tags=["Health"])
app.include_router(proxy.router, prefix="/v1/proxy", tags=["Privacy Proxy"])
app.include_router(webhooks.router, prefix="/v1/webhooks", tags=["Webhooks"])
app.include_router(agent.router, tags=["Agent API"])
app.include_router(relay.router, tags=["relay"])
app.include_router(document.router, prefix="/v1/proxy", tags=["Document"])

# Phase 13 — BYOK / Key Management
from app.routers import byok
app.include_router(byok.router, tags=["BYOK"])

# Phase 14 — Partner API (sub-account aggregation, no separate end-user login)
from app.routers import partner
app.include_router(partner.router, prefix="/v1/partner", tags=["Partner API"])

# Internal — server-to-server only (never called from a browser)
from app.routers import internal
app.include_router(internal.router, tags=["Internal"])


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return UTF8JSONResponse(
        status_code=500,
        content={"error": "internal_error", "detail": "An unexpected error occurred"},
    )

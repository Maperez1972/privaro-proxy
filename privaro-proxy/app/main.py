"""
Privaro Proxy API — v0.1.0 (MVP)
Privacy Infrastructure for Enterprise AI · iCommunity Labs
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.routers import proxy, health, webhooks, agent
from app.config import settings
from app.services import ibs


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


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "detail": "An unexpected error occurred"},
    )

"""
Configuration — reads from environment variables.
All secrets are injected by Railway in production, .env file in development.
"""
from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    # ── Environment ────────────────────────────────────────────────
    ENVIRONMENT: str = "development"

    # ── Supabase ───────────────────────────────────────────────────
    SUPABASE_URL: str
    SUPABASE_SERVICE_KEY: str          # service_role key — bypasses RLS for server writes

    # ── Encryption ────────────────────────────────────────────────
    ENCRYPTION_KEY: str = "0" * 64    # required in production — generate with secrets.token_hex(32)

    # ── iBS (Blockchain Evidence) ──────────────────────────────────
    IBS_API_KEY: str = ""
    IBS_WEBHOOK_SECRET: str = ""
    IBS_API_BASE: str = "https://api.icommunitylabs.com/v2"

    # ── Development only (never set in production) ─────────────────
    PRIVARO_DEV_KEY: Optional[str] = None
    DEV_ORG_ID: Optional[str] = None

    # ── CORS ───────────────────────────────────────────────────────
    CORS_ORIGINS: List[str] = [
        "https://privaro.lovable.app",
        "https://app.privaro.io",
        "http://localhost:5173",
        "http://localhost:3000",
    ]

    # ── Rate limiting ──────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",  # ignora variables del .env no declaradas aquí
    }


settings = Settings()
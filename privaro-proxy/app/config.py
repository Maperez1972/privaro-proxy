"""
Configuration — reads from environment variables.
All secrets are injected by Railway in production, .env file in development.

NOTE: LLM provider API keys (Anthropic, OpenAI, etc.) are NOT stored here.
They are customer-owned, stored encrypted in Supabase (llm_providers table),
and decrypted in-memory at request time by the LLM router.
"""
from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    # ── Environment ────────────────────────────────────────────────
    ENVIRONMENT: str = "development"

    # ── Supabase ───────────────────────────────────────────────────
    SUPABASE_URL: str
    SUPABASE_SERVICE_KEY: str

    # ── Encryption ────────────────────────────────────────────────
    # Used to decrypt customer LLM API keys stored in llm_providers table
    # and to encrypt/decrypt PII tokens in the vault.
    ENCRYPTION_KEY: str = "0" * 64

    # ── iBS (Blockchain Evidence) ──────────────────────────────────
    IBS_API_KEY: str = ""
    IBS_WEBHOOK_SECRET: str = ""
    IBS_API_BASE: str = "https://api.icommunitylabs.com/v2"

    # ── Development only ───────────────────────────────────────────
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
        "extra": "ignore",
    }


settings = Settings()

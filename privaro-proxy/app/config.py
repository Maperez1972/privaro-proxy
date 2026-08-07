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

    # ── Context Optimization ────────────────────────────────────────
    # If True, the prose-compression model (Kompress) is force-loaded at
    # startup (blocking, off the event loop) so no request has to eat the
    # cold-start download. If False (default), the model loads lazily on
    # first use of optimize_context=True, and early requests during that
    # window simply skip prose compression (fail-open — see
    # context_optimizer.py). Enable this in production once
    # optimize_context is actually exposed to customers.
    CONTEXT_OPTIMIZATION_WARMUP: bool = False
    # Added 2026-08-07 — real production finding: compress_protected_messages()
    # runs a real transformer model (Kompress) on CPU, and on a large
    # document (~14K chars) took 30s+ end to end. Bounds worst-case latency
    # so one oversized request can't hang a request indefinitely; see
    # compress_with_timeout() in context_optimizer.py, which fails open
    # (skips compression, keeps the already-tokenised text) on timeout.
    CONTEXT_OPTIMIZATION_TIMEOUT_SECONDS: float = 20.0

    # ── Development only ───────────────────────────────────────────
    PRIVARO_DEV_KEY: Optional[str] = None
    DEV_ORG_ID: Optional[str] = None

    # ── Usage notifications (added 2026-07) ─────────────────────────
    # Shared secret between this service and the send-usage-notification
    # Supabase Edge Function — server-to-server only, not user-facing.
    INTERNAL_NOTIFY_SECRET: Optional[str] = None

    # ── CORS ───────────────────────────────────────────────────────
    # Fixed 2026-07-23: "app.privaro.io" was never a real domain -- the
    # app lives under privaro.ai itself (e.g. privaro.ai/app/...), not a
    # separate subdomain, and never on a .io TLD. Confirmed against the
    # frontend repo's own schema.org metadata (index.html), which only
    # ever declares https://privaro.ai. This list is currently unused in
    # practice since main.py sets allow_origins=["*"], but keeping it
    # correct so it's safe to tighten CORS later without re-auditing.
    CORS_ORIGINS: List[str] = [
        "https://privaro.ai",
        "https://www.privaro.ai",
        "https://privaro.lovable.app",
        "http://localhost:5173",
        "http://localhost:3000",
    ]

    # ── Resilience / graceful degradation (added 2026-07) ───────────────────
    # Max time budget for the detection + policy engine step in /protect and
    # /detect. If exceeded, fails open (see proxy.py) rather than blocking
    # the caller's traffic indefinitely — Privaro sits in Robin/Octupus's
    # critical path, so an internal slowdown must never become their outage.
    PROTECT_TIMEOUT_SECONDS: float = 2.0

    # ── Rate limiting ──────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


settings = Settings()

"""
LLM Router — Multi-provider relay for Privaro proxy.

Supports: Anthropic Claude, OpenAI (GPT-4), Mistral, Google Gemini.

IMPORTANT: API keys are customer-owned and stored encrypted in Supabase
(llm_providers.api_key_encrypted). Privaro never stores them in plaintext.
The ENCRYPTION_KEY env var (Railway) is Privaro's key to decrypt them at runtime.

Flow:
    1. Client calls /v1/relay/complete with pipeline_id
    2. Relay reads pipeline.llm_provider → looks up llm_providers table
    3. Decrypts customer API key with ENCRYPTION_KEY (AES-256-GCM)
    4. Routes to provider with decrypted key
    5. Key is never logged or persisted beyond the request
"""
from __future__ import annotations
import json
import os
import base64
from typing import Any, Dict, List, Optional
import httpx

from app.config import settings

# ── Provider constants ────────────────────────────────────────────────────────
PROVIDERS = {
    "anthropic": {
        "name": "Anthropic Claude",
        "default_model": "claude-sonnet-4-20250514",
        "models": ["claude-opus-4-0", "claude-sonnet-4-20250514", "claude-haiku-4-5"],
    },
    "openai": {
        "name": "OpenAI",
        "default_model": "gpt-4o",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
    },
    "mistral": {
        "name": "Mistral AI",
        "default_model": "mistral-large-latest",
        "models": ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest"],
    },
    "gemini": {
        "name": "Google Gemini",
        "default_model": "gemini-1.5-pro",
        "models": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"],
    },
}

PROVIDER_ALIASES = {
    "claude": "anthropic",
    "gpt": "openai", "gpt-4": "openai", "gpt-3.5": "openai",
    "google": "gemini", "google-gemini": "gemini",
}


class LLMRouterError(Exception):
    def __init__(self, message: str, provider: str = "", status_code: int = 500):
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code


def _resolve_provider(provider_name: str) -> str:
    p = provider_name.lower().strip()
    return PROVIDER_ALIASES.get(p, p)


def _decrypt_api_key(encrypted_b64: str) -> str:
    """
    Decrypt a customer API key stored in llm_providers.api_key_encrypted.
    Uses Privaro's ENCRYPTION_KEY (AES-256-GCM) — same scheme as token vault.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        enc_key = bytes.fromhex(settings.ENCRYPTION_KEY)
        raw = base64.b64decode(encrypted_b64)
        nonce = raw[:12]
        ciphertext = raw[12:]
        aesgcm = AESGCM(enc_key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception as e:
        raise LLMRouterError(
            f"Failed to decrypt customer API key: {e}. "
            "Check ENCRYPTION_KEY environment variable.",
            status_code=500
        )


async def get_customer_api_key(org_id: str, provider: str) -> str:
    """
    Fetch and decrypt the customer's API key for a provider from Supabase.
    
    Looks up llm_providers table:
        org_id = {org_id}
        provider = {provider}  (e.g. "anthropic", "openai")
        is_active = true
    
    Raises LLMRouterError if no active provider config found.
    """
    import httpx as _httpx

    provider_canonical = _resolve_provider(provider)
    
    url = f"{settings.SUPABASE_URL}/rest/v1/llm_providers"
    headers = {
        "apikey": settings.SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
    }
    params = {
        "org_id": f"eq.{org_id}",
        "provider": f"eq.{provider_canonical}",
        "is_active": "eq.true",
        "select": "id,provider,api_key_encrypted,api_key_hint,available_models",
        "limit": "1",
    }
    
    async with _httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(url, headers=headers, params=params)
        if resp.status_code != 200:
            raise LLMRouterError(
                f"Failed to fetch provider config from Supabase: {resp.status_code}",
                provider_canonical, 500
            )
        rows = resp.json()
    
    if not rows:
        raise LLMRouterError(
            f"No active {provider_canonical} provider configured for this organisation. "
            f"Add your API key at /app/admin/providers.",
            provider_canonical, 503
        )
    
    row = rows[0]
    if not row.get("api_key_encrypted"):
        raise LLMRouterError(
            f"Provider {provider_canonical} is configured but has no API key. "
            f"Add your API key at /app/admin/providers.",
            provider_canonical, 503
        )
    
    return _decrypt_api_key(row["api_key_encrypted"])


# ── Provider call implementations ─────────────────────────────────────────────

async def _call_anthropic(
    model: str, messages: List[Dict], api_key: str,
    max_tokens: int = 2048, temperature: float = 0.7,
    system: Optional[str] = None,
) -> Dict:
    sys_msg = system or next((m["content"] for m in messages if m["role"] == "system"), None)
    conv_messages = [m for m in messages if m["role"] != "system"]
    body: Dict[str, Any] = {
        "model": model or PROVIDERS["anthropic"]["default_model"],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": conv_messages,
    }
    if sys_msg:
        body["system"] = sys_msg
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json=body
        )
        if resp.status_code != 200:
            raise LLMRouterError(f"Anthropic error {resp.status_code}: {resp.text[:300]}",
                                 "anthropic", resp.status_code)
        data = resp.json()
        return {
            "content": data["content"][0]["text"],
            "model": data["model"],
            "provider": "anthropic",
            "usage": {"input_tokens": data["usage"]["input_tokens"],
                      "output_tokens": data["usage"]["output_tokens"]},
        }


async def _call_openai(
    model: str, messages: List[Dict], api_key: str,
    max_tokens: int = 2048, temperature: float = 0.7, **kwargs,
) -> Dict:
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model or PROVIDERS["openai"]["default_model"],
                  "messages": messages, "max_tokens": max_tokens, "temperature": temperature}
        )
        if resp.status_code != 200:
            raise LLMRouterError(f"OpenAI error {resp.status_code}: {resp.text[:300]}",
                                 "openai", resp.status_code)
        data = resp.json()
        return {
            "content": data["choices"][0]["message"]["content"],
            "model": data["model"], "provider": "openai",
            "usage": data.get("usage", {}),
        }


async def _call_mistral(
    model: str, messages: List[Dict], api_key: str,
    max_tokens: int = 2048, temperature: float = 0.7, **kwargs,
) -> Dict:
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.mistral.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": model or PROVIDERS["mistral"]["default_model"],
                  "messages": messages, "max_tokens": max_tokens, "temperature": temperature}
        )
        if resp.status_code != 200:
            raise LLMRouterError(f"Mistral error {resp.status_code}: {resp.text[:300]}",
                                 "mistral", resp.status_code)
        data = resp.json()
        return {
            "content": data["choices"][0]["message"]["content"],
            "model": data["model"], "provider": "mistral",
            "usage": data.get("usage", {}),
        }


async def _call_gemini(
    model: str, messages: List[Dict], api_key: str,
    max_tokens: int = 2048, temperature: float = 0.7, **kwargs,
) -> Dict:
    contents = [
        {"role": "user" if m["role"] in ("user", "system") else "model",
         "parts": [{"text": m["content"]}]}
        for m in messages
    ]
    model_id = model or PROVIDERS["gemini"]["default_model"]
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={api_key}",
            json={"contents": contents,
                  "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature}}
        )
        if resp.status_code != 200:
            raise LLMRouterError(f"Gemini error {resp.status_code}: {resp.text[:300]}",
                                 "gemini", resp.status_code)
        data = resp.json()
        usage = data.get("usageMetadata", {})
        return {
            "content": data["candidates"][0]["content"]["parts"][0]["text"],
            "model": model_id, "provider": "gemini",
            "usage": {"input_tokens": usage.get("promptTokenCount", 0),
                      "output_tokens": usage.get("candidatesTokenCount", 0)},
        }


# ── Main router ────────────────────────────────────────────────────────────────

async def route(
    provider: str,
    messages: List[Dict],
    org_id: str,
    model: Optional[str] = None,
    max_tokens: int = 2048,
    temperature: float = 0.7,
    system: Optional[str] = None,
) -> Dict:
    """
    Route a request to the customer's configured LLM provider.
    
    Reads and decrypts the customer API key from Supabase llm_providers table.
    The key is decrypted in-memory and never logged or persisted.
    
    Args:
        provider:   Provider name (anthropic|openai|mistral|gemini)
        messages:   Chat messages (already tokenised by Privaro)
        org_id:     Customer org ID — used to fetch their API key
        model:      Model override (uses pipeline default if None)
        max_tokens: Max response tokens
        temperature: Sampling temperature
        system:     System prompt
    
    Raises:
        LLMRouterError if provider not configured or API key missing
    """
    provider = _resolve_provider(provider)
    
    # Fetch customer API key from Supabase (decrypted in-memory)
    api_key = await get_customer_api_key(org_id, provider)

    CALLERS = {
        "anthropic": _call_anthropic,
        "openai": _call_openai,
        "mistral": _call_mistral,
        "gemini": _call_gemini,
    }
    caller = CALLERS.get(provider)
    if not caller:
        raise LLMRouterError(
            f"Unsupported provider: {provider}. Supported: {list(CALLERS.keys())}",
            provider, 400
        )
    return await caller(
        model=model, messages=messages, api_key=api_key,
        max_tokens=max_tokens, temperature=temperature, system=system,
    )


def list_providers() -> Dict:
    return {k: v for k, v in PROVIDERS.items()}

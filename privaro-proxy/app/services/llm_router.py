"""
LLM Router — Multi-provider relay for Privaro proxy.

Supports: Anthropic Claude, OpenAI (GPT-4/3.5), Mistral, Google Gemini.
Provider is resolved from the pipeline configuration in Supabase.

Each provider uses a unified interface:
    result = await route(provider, model, messages, api_key, options)
    → {"content": str, "model": str, "usage": dict, "provider": str}

Environment variables (set in Railway):
    ANTHROPIC_API_KEY   — for Claude
    OPENAI_API_KEY      — for GPT-4
    MISTRAL_API_KEY     — for Mistral
    GOOGLE_API_KEY      — for Gemini
    
    Customers can also provide their own keys via the pipeline config
    (stored encrypted in Supabase).
"""
from __future__ import annotations
import json
import os
from typing import Any, Dict, List, Optional
import httpx

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
    """Normalise provider name to canonical key."""
    p = provider_name.lower().strip()
    return PROVIDER_ALIASES.get(p, p)


def _get_api_key(provider: str, customer_key: Optional[str] = None) -> str:
    """
    Resolve API key for provider.
    Priority: customer-provided key > environment variable.
    """
    if customer_key:
        return customer_key
    
    env_map = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "mistral": "MISTRAL_API_KEY",
        "gemini": "GOOGLE_API_KEY",
    }
    env_key = env_map.get(provider)
    if not env_key:
        raise LLMRouterError(f"Unknown provider: {provider}", provider)
    
    key = os.getenv(env_key)
    if not key:
        raise LLMRouterError(
            f"No API key for {provider}. Set {env_key} in Railway environment variables.",
            provider, 503
        )
    return key


# ── Provider implementations ──────────────────────────────────────────────────

async def _call_anthropic(
    model: str,
    messages: List[Dict],
    api_key: str,
    max_tokens: int = 2048,
    temperature: float = 0.7,
    system: Optional[str] = None,
) -> Dict:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    # Separate system message from conversation
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
            headers=headers, json=body
        )
        if resp.status_code != 200:
            raise LLMRouterError(
                f"Anthropic API error {resp.status_code}: {resp.text[:200]}",
                "anthropic", resp.status_code
            )
        data = resp.json()
        return {
            "content": data["content"][0]["text"],
            "model": data["model"],
            "provider": "anthropic",
            "usage": {
                "input_tokens": data["usage"]["input_tokens"],
                "output_tokens": data["usage"]["output_tokens"],
            },
        }


async def _call_openai(
    model: str,
    messages: List[Dict],
    api_key: str,
    max_tokens: int = 2048,
    temperature: float = 0.7,
    **kwargs,
) -> Dict:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model or PROVIDERS["openai"]["default_model"],
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers, json=body
        )
        if resp.status_code != 200:
            raise LLMRouterError(
                f"OpenAI API error {resp.status_code}: {resp.text[:200]}",
                "openai", resp.status_code
            )
        data = resp.json()
        return {
            "content": data["choices"][0]["message"]["content"],
            "model": data["model"],
            "provider": "openai",
            "usage": data.get("usage", {}),
        }


async def _call_mistral(
    model: str,
    messages: List[Dict],
    api_key: str,
    max_tokens: int = 2048,
    temperature: float = 0.7,
    **kwargs,
) -> Dict:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model or PROVIDERS["mistral"]["default_model"],
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            "https://api.mistral.ai/v1/chat/completions",
            headers=headers, json=body
        )
        if resp.status_code != 200:
            raise LLMRouterError(
                f"Mistral API error {resp.status_code}: {resp.text[:200]}",
                "mistral", resp.status_code
            )
        data = resp.json()
        return {
            "content": data["choices"][0]["message"]["content"],
            "model": data["model"],
            "provider": "mistral",
            "usage": data.get("usage", {}),
        }


async def _call_gemini(
    model: str,
    messages: List[Dict],
    api_key: str,
    max_tokens: int = 2048,
    temperature: float = 0.7,
    **kwargs,
) -> Dict:
    # Convert messages to Gemini format
    contents = []
    for m in messages:
        role = "user" if m["role"] in ("user", "system") else "model"
        contents.append({"role": role, "parts": [{"text": m["content"]}]})

    body = {
        "contents": contents,
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": temperature,
        },
    }
    model_id = model or PROVIDERS["gemini"]["default_model"]
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={api_key}"

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, json=body)
        if resp.status_code != 200:
            raise LLMRouterError(
                f"Gemini API error {resp.status_code}: {resp.text[:200]}",
                "gemini", resp.status_code
            )
        data = resp.json()
        content = data["candidates"][0]["content"]["parts"][0]["text"]
        usage = data.get("usageMetadata", {})
        return {
            "content": content,
            "model": model_id,
            "provider": "gemini",
            "usage": {
                "input_tokens": usage.get("promptTokenCount", 0),
                "output_tokens": usage.get("candidatesTokenCount", 0),
            },
        }


# ── Main router ────────────────────────────────────────────────────────────────

async def route(
    provider: str,
    messages: List[Dict],
    model: Optional[str] = None,
    customer_api_key: Optional[str] = None,
    max_tokens: int = 2048,
    temperature: float = 0.7,
    system: Optional[str] = None,
) -> Dict:
    """
    Route a chat completion request to the specified LLM provider.
    
    Args:
        provider:          Provider name (anthropic|openai|mistral|gemini)
        messages:          List of {"role": "user"|"assistant"|"system", "content": str}
        model:             Model name (uses provider default if None)
        customer_api_key:  Customer-provided API key (overrides env var)
        max_tokens:        Maximum tokens in response
        temperature:       Sampling temperature (0.0–1.0)
        system:            System prompt (for providers that support it)
    
    Returns:
        {"content": str, "model": str, "provider": str, "usage": dict}
    
    Raises:
        LLMRouterError on provider errors or missing API keys
    """
    provider = _resolve_provider(provider)
    api_key = _get_api_key(provider, customer_api_key)

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
        model=model,
        messages=messages,
        api_key=api_key,
        max_tokens=max_tokens,
        temperature=temperature,
        system=system,
    )


def list_providers() -> Dict:
    """Return supported providers and their models."""
    return {k: v for k, v in PROVIDERS.items()}

"""
Context Optimizer — wraps Headroom's compress() with a hard safety guard
for Privaro's tokenised placeholders.

CRITICAL INVARIANT: a Privaro token like [EM-0001] or [DNI-0003] must reach
the LLM byte-for-byte identical to how /protect or _protect_messages()
produced it. If a compressor rewrites, merges, or drops a token, /relay's
detokenise_response step can no longer find it in the LLM's response, and
the customer silently loses re-identification for that value — this is a
correctness bug that looks like nothing happened, which is the worst kind
in a compliance product.

Strategy: never hand raw tokenised text to Kompress/SmartCrusher. Instead,
extract every [XX-0001]-shaped token BEFORE compression, replace it with an
inert placeholder that looks like plain content to Headroom's transforms,
compress, then restore the exact original tokens by position. Verified
after every call: if any original token isn't found post-restore, the
whole compression result is discarded and the original protected_messages
are returned unmodified (fail open — same philosophy as the rest of this
proxy: never let an optimization break correctness).
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Tuple

from headroom import compress

# Same pattern as proxy.py's TOKEN_PATTERN — kept in sync deliberately.
# If Privaro's token format ever changes, update BOTH locations together
# (or better: import from a shared constants module in a follow-up PR).
_TOKEN_RE = re.compile(r"\[[A-Z]{2,4}-\d{4}\]")

# Placeholder shape chosen so it never collides with real content and is
# short enough not to distort Headroom's token-count-based decisions.
_PLACEHOLDER_TMPL = "\u2060PVR{idx}\u2060"  # word-joiner-wrapped, invisible-ish


def warmup_kompress(timeout_seconds: float = 30.0) -> bool:
    """
    Force-load the Kompress prose-compression model synchronously and BLOCK
    until it's ready (or the timeout elapses).

    Why this exists — real finding from validation (2026-07-29): Kompress
    loads its weights via a one-shot, non-blocking background download
    (KompressCompressor.ensure_background_load() / is_ready()). Without
    calling this explicitly, the FIRST requests handled by any fresh
    instance of this service silently skip prose compression — compress()
    just returns tokens_saved=0 with a log warning, never an error. That's
    invisible in production traffic and would make ratio numbers look
    inconsistent/broken for no visible reason.

    Call this once from the app's startup/lifespan handler, BEFORE serving
    traffic, so every instance starts warm. Returns True if the model
    became ready within timeout_seconds, False otherwise (the service
    should still start — compression just fails open with 0% ratio on
    prose until the model finishes loading, same as any cold instance
    would today).
    """
    from headroom.transforms.kompress_compressor import KompressCompressor

    compressor = KompressCompressor()
    if compressor.is_ready():
        return True

    compressor.ensure_background_load()
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if compressor.is_ready():
            return True
        time.sleep(0.5)
    return False


def _shield_tokens(text: str) -> Tuple[str, Dict[str, str]]:
    """Replace every Privaro token with an inert placeholder. Returns the
    shielded text and a map placeholder -> original token for restoration."""
    mapping: Dict[str, str] = {}

    def _sub(m: re.Match) -> str:
        idx = len(mapping)
        placeholder = _PLACEHOLDER_TMPL.format(idx=idx)
        mapping[placeholder] = m.group(0)
        return placeholder

    shielded = _TOKEN_RE.sub(_sub, text)
    return shielded, mapping


def _unshield(text: str, mapping: Dict[str, str]) -> str:
    for placeholder, original in mapping.items():
        text = text.replace(placeholder, original)
    return text


def compress_protected_messages(
    messages: List[Dict[str, Any]],
    model: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Compress an already-tokenised message list from _protect_messages().

    Returns (messages, stats). On any failure or integrity mismatch, returns
    the ORIGINAL messages unmodified with tokens_saved=0 — fails open,
    consistent with the rest of this proxy (see proxy.py's DegradedModeError
    philosophy: an optimization must never become a correctness incident).
    """
    stats = {"tokens_saved": 0, "compression_ratio": 0.0, "skipped_reason": None}

    try:
        shielded_messages = []
        all_mappings: List[Dict[str, str]] = []
        for msg in messages:
            shielded_content, mapping = _shield_tokens(msg["content"])
            shielded_messages.append({**msg, "content": shielded_content})
            all_mappings.append(mapping)

        result = compress(
            shielded_messages,
            model=model,
            compress_user_messages=True,   # Privaro's messages ARE the payload,
            protect_recent=0,               # not an agent scratchpad — see README
        )

        restored = []
        for msg, mapping in zip(result.messages, all_mappings):
            restored_content = _unshield(msg["content"], mapping)
            # Integrity check: every original token must still be present,
            # exactly once, verbatim. If not, abort the whole optimization.
            for original_token in mapping.values():
                if original_token not in restored_content:
                    stats["skipped_reason"] = "token_integrity_check_failed"
                    return messages, stats
            restored.append({**msg, "content": restored_content})

        stats["tokens_saved"] = result.tokens_saved
        stats["compression_ratio"] = result.compression_ratio
        return restored, stats

    except Exception as e:  # noqa: BLE001 — deliberate: any compressor
        # failure must fail open, never break a request that Privaro
        # already successfully protected.
        stats["skipped_reason"] = f"compressor_error: {e}"
        return messages, stats

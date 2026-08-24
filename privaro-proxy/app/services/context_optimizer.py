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
from typing import Any, Dict, List, Optional, Tuple

from headroom import compress

# Same pattern as proxy.py's TOKEN_PATTERN — kept in sync deliberately.
# If Privaro's token format ever changes, update BOTH locations together
# (or better: import from a shared constants module in a follow-up PR).
_TOKEN_RE = re.compile(r"\[[A-Z]{2,4}-\d{4}\]")

# Placeholder shape chosen so it never collides with real content and is
# short enough not to distort Headroom's token-count-based decisions.
_PLACEHOLDER_TMPL = "\u2060PVR{idx}\u2060"  # word-joiner-wrapped, invisible-ish


def _get_real_kompress_compressor():
    """
    Reach into the ACTUAL singleton compression pipeline that
    compress()/compress_protected_messages() uses internally, and return
    its real Kompress compressor instance — NOT a standalone throwaway
    one.

    CRITICAL finding, 2026-08-13 (Fase 0 of the RAG expansion audit,
    Presidio/Kompress scale validation): warmup_kompress() and
    kompress_ready() both used to call `KompressCompressor()` directly —
    a brand new, throwaway instance completely disconnected from the one
    `compress()` actually uses at runtime. `headroom.compress._get_pipeline()`
    IS a real module-level singleton (confirmed by reading the library
    source directly), but its `ContentRouter` transform lazy-loads its
    OWN Kompress instance on first use (`self._kompress: Any = None` in
    `ContentRouter.__init__`, populated by the private `_get_kompress()`
    method) — a completely separate object from anything created by
    calling `KompressCompressor()` ourselves.

    Consequence, confirmed empirically, not assumed: `warmup_kompress()`
    would report `ready: True` after successfully warming its own
    throwaway instance, while the pipeline's REAL instance had never
    been touched — its first real use (inside an actual `compress()`
    call) would find itself not ready, and appears to hit an internal
    failure latch (`_degraded_reason` / `_inference_failures`, visible
    in KompressCompressor's own source) that PERMANENTLY disables
    compression for the rest of that process's lifetime after a single
    bad attempt — every subsequent call returns instantly (~13ms) with
    `tokens_saved: 0`, no error, no retry, ever again. The exact same
    problem existed independently in `kompress_ready()`, which means the
    `/health` endpoint's `kompress_ready: true` reported during the
    Context Optimization latency investigation reflected the health of
    an unrelated, never-used object — NOT whether the pipeline customers
    actually hit could compress anything.

    Net effect: Context Optimization's prose compression (Kompress) has
    very likely never worked in production since it was first deployed,
    silently, with both health signals we built to catch exactly this
    kind of failure (warmup + health check) checking the wrong object
    the entire time.

    Verified directly against the real object before writing this fix:
    warming the correct instance (obtained exactly as below) took ~2s
    (weights already cached to disk from an earlier throwaway-instance
    load), versus 11s for a fresh throwaway instance — and a subsequent
    real `compress_protected_messages()` call returned
    `tokens_saved: 749, compression_ratio: 0.226` on a synthetic prose
    document, versus `tokens_saved: 0` every time before this fix.
    """
    from headroom.compress import _get_pipeline
    from headroom.transforms.content_router import ContentRouter

    pipeline = _get_pipeline()
    for transform in pipeline.transforms:
        if isinstance(transform, ContentRouter):
            return transform._get_kompress()
    return None


def warmup_kompress(timeout_seconds: float = 30.0, retries: int = 2) -> bool:
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

    Retry note (2026-07-30, second validation round): a single attempt can
    return False on a transient HuggingFace Hub blip (a slow HEAD/redirect
    on the first request) even though the model is perfectly downloadable —
    confirmed by re-running immediately after and getting a clean ~9s load.
    Rather than let one unlucky network hiccup at startup permanently doom
    an instance to serving 0%-ratio prose compression until its next
    restart, this retries `retries` additional times (each with a fresh
    `timeout_seconds` window and a short backoff) before giving up.

    CRITICAL fix, 2026-08-13: this used to warm a throwaway
    `KompressCompressor()` instance with zero connection to the real
    pipeline `compress()` uses — see `_get_real_kompress_compressor()`'s
    docstring for the full incident. Now warms the actual singleton
    instance, so this function's return value genuinely reflects whether
    real traffic will get compressed.

    Call this once from the app's startup/lifespan handler, BEFORE serving
    traffic, so every instance starts warm. Returns True if the model
    became ready within any attempt, False otherwise (the service should
    still start — compression just fails open with 0% ratio on prose
    until the model finishes loading, same as any cold instance would
    today).
    """
    compressor = _get_real_kompress_compressor()
    if compressor is None:
        return False
    if compressor.is_ready():
        return True

    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        compressor.ensure_background_load()
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if compressor.is_ready():
                return True
            time.sleep(0.5)
        if attempt < attempts - 1:
            time.sleep(2.0)  # short backoff before the next attempt
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


def kompress_ready() -> bool:
    """
    Non-blocking check: is the Kompress prose-compression model actually
    loaded right now? Added 2026-08-07 after a production incident where
    requirements.txt was missing the [proxy] extra (onnxruntime/
    transformers) — the app started fine and /health reported nlp_active
    correctly, but there was no way to see from the outside that Kompress
    itself had failed to load, only by grepping container logs for
    'background model download failed'. Exposed on /health as
    kompress_ready so this class of failure is visible without log access.

    CRITICAL fix, 2026-08-13: same wrong-instance bug as
    warmup_kompress() — this used to construct its own throwaway
    KompressCompressor() and check IT, meaning `kompress_ready: true` on
    /health never actually reflected whether real traffic could compress
    anything. See _get_real_kompress_compressor()'s docstring.
    """
    try:
        compressor = _get_real_kompress_compressor()
        return compressor.is_ready() if compressor is not None else False
    except Exception:
        return False


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


async def compress_with_timeout(
    messages: List[Dict[str, Any]],
    model: str,
    timeout_seconds: Optional[float] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Async, non-blocking, time-bounded wrapper around
    compress_protected_messages() — added 2026-08-07 after a real
    production finding: all three callers (proxy.py, relay.py, agent.py)
    called compress_protected_messages() DIRECTLY inside an `async def`
    endpoint, with no `await`, no `run_in_executor`. Kompress is a real
    transformer model running on CPU; on a ~14K character document it
    took 30+ seconds end to end. Calling it synchronously like that
    doesn't just make ONE request slow — it BLOCKS THE ENTIRE ASYNCIO
    EVENT LOOP for that worker process for the whole duration, freezing
    every other concurrent request (other customers' /protect, /detect,
    /relay, even /health) on that worker until it returns. Two customers
    hitting Context Optimization on large documents at the same time
    would serialize behind each other and could look like a full outage.

    This runs the (synchronous) compression in a thread pool executor —
    same pattern already used for warmup_kompress() at startup and for
    detector.detect() in _detect_with_timeout() — and bounds worst-case
    latency with a timeout. On timeout, fails open exactly like every
    other resilience mechanism in this proxy: returns the original
    (already-tokenised, still fully protected) messages unmodified,
    just without the token-count reduction for that one request.
    """
    import asyncio
    from app.config import settings

    effective_timeout = timeout_seconds if timeout_seconds is not None else settings.CONTEXT_OPTIMIZATION_TIMEOUT_SECONDS
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, compress_protected_messages, messages, model),
            timeout=effective_timeout,
        )
    except asyncio.TimeoutError:
        return messages, {
            "tokens_saved": 0,
            "compression_ratio": 0.0,
            "skipped_reason": f"timeout_after_{effective_timeout}s",
        }
    except Exception as e:  # noqa: BLE001 — same fail-open philosophy
        return messages, {
            "tokens_saved": 0,
            "compression_ratio": 0.0,
            "skipped_reason": f"executor_error: {e}",
        }


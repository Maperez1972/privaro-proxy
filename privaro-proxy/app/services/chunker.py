"""
Document chunker for Privaro Ingest (Fase 1 of the RAG expansion).

CRITICAL INVARIANT, non-negotiable: this operates on ALREADY-TOKENISED
text (protected_document, produced by detector.detect() +
_apply_tokenization() run over the WHOLE document first). Chunking must
happen strictly AFTER tokenisation, never before — chunking a raw
document first and then detecting PII per-chunk reproduces exactly the
"name split across a line/chunk boundary" class of bug this whole
session spent hours finding and fixing in the detector itself (see
detector.py's full_name pattern history). This module's entire reason
to exist is to preserve that invariant at the chunk-boundary level too:
a chunk boundary must NEVER fall inside a [XX-0001]-shaped token, or a
downstream consumer embedding that chunk would silently store half a
token as plain, meaningless text in their vector DB — not a privacy
leak (the real PII was already replaced before this ever runs), but a
correctness bug that would corrupt the reversible token map's
usefulness for that entity.
"""
from __future__ import annotations

import re
from typing import List, NamedTuple

# Same token shape used throughout the codebase (context_optimizer.py's
# shield regex, detector.py's TOKEN_PREFIX-generated tokens). Kept in
# sync deliberately — see the existing cross-file duplication note in
# detector.py/proxy.py/relay.py/agent.py's PREFIX_MAP for why this
# pattern already needs consolidating into one shared constant in a
# follow-up, independent of this new module.
_TOKEN_RE = re.compile(r"\[[A-Z]{2,4}-\d{4}\]")

# Preferred break points, checked in this priority order when looking
# for where to end a chunk near the target size — paragraph breaks
# first (best semantic coherence for a RAG chunk), then sentence-ish
# breaks, then whitespace, with "just cut here" as the last resort
# (still token-safe, just not aligned to natural language structure).
_BREAK_PATTERNS = [
    re.compile(r"\n\s*\n"),      # paragraph break
    re.compile(r"(?<=[.!?])\s+"),  # sentence end
    re.compile(r"\s+"),           # any whitespace
]


class Chunk(NamedTuple):
    index: int
    text: str
    char_start: int
    char_end: int


def _token_spans(text: str) -> List[tuple]:
    return [(m.start(), m.end()) for m in _TOKEN_RE.finditer(text)]


def _adjust_boundary_off_tokens(text: str, pos: int, token_spans: List[tuple]) -> int:
    """
    If `pos` falls strictly inside a token span, push it to the token's
    end instead. `pos` sitting exactly at a token's start or end is fine
    (that's a real, safe boundary) — only the interior is disallowed.
    """
    for start, end in token_spans:
        if start < pos < end:
            return end
    return pos


def _find_break_near(text: str, target: int, lower_bound: int, upper_bound: int) -> int:
    """
    Search for the best natural break point within
    [lower_bound, upper_bound), preferring the pattern closest to
    `target`. Falls back to `target` itself (a hard cut) if nothing
    better is found in range — still corrected for token-safety by the
    caller afterwards regardless of which path produced it.
    """
    window = text[lower_bound:upper_bound]
    best_pos = None
    best_distance = None
    for pattern in _BREAK_PATTERNS:
        for m in pattern.finditer(window):
            candidate = lower_bound + m.end()
            distance = abs(candidate - target)
            if best_pos is None or distance < best_distance:
                best_pos, best_distance = candidate, distance
        if best_pos is not None:
            break  # a higher-priority pattern found something — stop
    return best_pos if best_pos is not None else target


def chunk_protected_document(
    protected_text: str,
    chunk_size: int = 512,
    overlap_search_ratio: float = 0.2,
) -> List[Chunk]:
    """
    Split an ALREADY-TOKENISED document into chunks of approximately
    `chunk_size` characters, never splitting a [XX-0001]-shaped token
    across a chunk boundary.

    `overlap_search_ratio` controls how far around the target size this
    looks for a natural break point (paragraph > sentence > whitespace)
    before falling back to a hard cut — e.g. 0.2 with chunk_size=512
    searches a window of ~102 characters on either side of the target.

    Returns a list of non-overlapping Chunk(index, text, char_start,
    char_end) covering the entire input exactly once, in order.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    n = len(protected_text)
    if n == 0:
        return []

    token_spans = _token_spans(protected_text)
    search_radius = max(1, int(chunk_size * overlap_search_ratio))

    chunks: List[Chunk] = []
    pos = 0
    index = 0
    while pos < n:
        target = pos + chunk_size
        if target >= n:
            end = n
        else:
            lower = max(pos + 1, target - search_radius)
            upper = min(n, target + search_radius)
            end = _find_break_near(protected_text, target, lower, upper)
            end = _adjust_boundary_off_tokens(protected_text, end, token_spans)
            # A token longer than 2*search_radius could still push `end`
            # past `upper` (correctly, for safety) — if it also somehow
            # regressed to <= pos (degenerate, shouldn't happen given
            # token lengths are always small and fixed-format, but this
            # is a hard invariant worth guarding explicitly rather than
            # risking an infinite loop), force forward progress instead
            # of ever looping forever on pathological input.
            if end <= pos:
                end = min(n, pos + chunk_size)
                end = _adjust_boundary_off_tokens(protected_text, end, token_spans)
                if end <= pos:
                    end = n  # last-resort: take the rest of the document

        chunks.append(Chunk(index=index, text=protected_text[pos:end], char_start=pos, char_end=end))
        pos = end
        index += 1

    return chunks

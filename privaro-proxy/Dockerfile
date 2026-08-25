FROM python:3.11-slim

WORKDIR /app

# System deps for spaCy + Tesseract OCR (image-document protection, Tier 1 —
# 2026-08-11). tesseract-ocr-spa is the Spanish language pack; without it
# Tesseract defaults to English-only recognition, which would badly hurt
# accuracy on Spanish documents (DNI, direcciones, etc.) — exactly the
# real-world case this feature targets.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ tesseract-ocr tesseract-ocr-spa && \
    rm -rf /var/lib/apt/lists/*

# Cache bust — increment to force full rebuild including pip + spacy model
ARG CACHE_BUST=24
RUN echo "Cache bust: $CACHE_BUST"

# Install Python deps (including Presidio + spaCy)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy ES model (43MB) — must be after pip install
RUN python -m spacy download es_core_news_md && \
    python -c "import spacy; nlp = spacy.load('es_core_news_md'); print('[spaCy] es_core_news_md OK')"

# Copy application code
COPY app/ ./app/

# Non-root user
RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 8000

# Fixed 2026-08-26 — real deploy issue, confirmed across multiple
# attempts: Railway would not apply this service's "Custom Start
# Command" (python -m app.worker.ingestion_worker) for the ingestion
# worker service, running the default uvicorn CMD instead regardless
# (confirmed by the "🚀 Privaro Proxy API starting" log line, which
# only exists in app/main.py — proof the worker service was still
# running the API). Tried and ruled out: a separate railway.worker.toml
# config file (Railway kept applying railway.toml's config per its own
# deployment detail page, despite the Config File path being correctly
# set), and an embedded /health server (fixed the healthcheck symptom,
# but the underlying process was still uvicorn, not the worker).
#
# Rather than depend on Railway correctly overriding CMD at the
# platform level (whatever the underlying cause — same account, same
# project, unclear why it wasn't working), this bakes the choice into
# the image itself via an environment variable, which IS unambiguously
# per-service in Railway (Settings -> Variables, no path resolution, no
# config-as-code involved at all). Default (WORKER_MODE unset or not
# "true") preserves the exact original behaviour -- zero risk to the
# API service, which needs no changes at all to keep working exactly
# as before.
CMD ["sh", "-c", "if [ \"$WORKER_MODE\" = \"true\" ]; then python -m app.worker.ingestion_worker; else uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 2; fi"]

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

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 2"]

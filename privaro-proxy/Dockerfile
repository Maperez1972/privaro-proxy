FROM python:3.11-slim

WORKDIR /app

# System deps for spaCy
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps (including Presidio + spaCy)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy ES model (43MB) — cached in image layer
RUN python -m spacy download es_core_news_md

# Cache bust — increment to force rebuild of app layer
ARG CACHE_BUST=16
COPY app/ ./app/

# Non-root user
RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 2"]

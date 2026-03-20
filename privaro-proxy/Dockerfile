FROM python:3.11.8-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Patch ibs.py directamente en build — garantiza signatures field
RUN python3 -c "
import re
with open('app/services/ibs.py', 'r') as f:
    content = f.read()
if '\"signatures\"' not in content:
    content = content.replace(
        '\"files\": [{\"name\": \"event.json\", \"file\": payload_hash}],\n        }',
        '\"files\": [{\"name\": \"event.json\", \"file\": payload_hash}],\n        },\n        \"signatures\": []'
    )
    with open('app/services/ibs.py', 'w') as f:
        f.write(content)
    print('PATCHED: signatures field added')
else:
    print('OK: signatures field already present')
"

RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 2"]

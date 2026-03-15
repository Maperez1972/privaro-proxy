"""
Test rápido del endpoint /proxy/protect
Ejecutar desde la carpeta privaro-proxy:
  python test_protect.py
"""
import urllib.request
import json
import os
from pathlib import Path

# Cargar .env manualmente para el diagnóstico
env_path = Path(__file__).parent / ".env"
env_vars = {}
if env_path.exists():
    for line in env_path.read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env_vars[k.strip()] = v.strip()

SUPABASE_URL = env_vars.get("SUPABASE_URL", "")
SUPABASE_KEY = env_vars.get("SUPABASE_SERVICE_KEY", "")
PIPELINE_ID  = "c93aed87-b440-4de0-bb21-54a938e475f2"
DEV_KEY      = "prvr_dev_localtest_only"

print("=" * 60)
print("DIAGNÓSTICO PRIVARO PROXY")
print("=" * 60)
print(f"\n1. SUPABASE_URL:         {SUPABASE_URL}")
print(f"2. SUPABASE_SERVICE_KEY: {SUPABASE_KEY[:20]}..." if len(SUPABASE_KEY) > 20 else f"2. SUPABASE_SERVICE_KEY: {'❌ VACÍA' if not SUPABASE_KEY else SUPABASE_KEY}")
print(f"3. PIPELINE_ID:          {PIPELINE_ID}")

# Test directo a Supabase (sin pasar por el proxy)
print(f"\n--- Test directo Supabase ---")
try:
    supabase_url = f"{SUPABASE_URL}/rest/v1/pipelines?id=eq.{PIPELINE_ID}&select=id,org_id,status&limit=1"
    req = urllib.request.Request(
        supabase_url,
        headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
        }
    )
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read())
        if data:
            print(f"✅ Pipeline encontrado en Supabase: {data[0]}")
        else:
            print(f"❌ Pipeline NO encontrado — UUID incorrecto o RLS bloqueando")
except Exception as e:
    print(f"❌ Error conectando a Supabase: {e}")

# Test al proxy
print(f"\n--- Test al proxy local ---")
payload = {
    "pipeline_id": PIPELINE_ID,
    "prompt": "Cliente Juan Garcia, DNI 12345678A, email juan@test.com",
    "options": {"mode": "tokenise", "include_detections": True}
}

req = urllib.request.Request(
    "http://localhost:8000/v1/proxy/protect",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "X-Privaro-Key": DEV_KEY,
    },
    method="POST"
)

try:
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
        print(f"\n✅ RESPUESTA DEL PROXY:\n")
        print(f"  request_id:       {result.get('request_id')}")
        print(f"  protected_prompt: {result.get('protected_prompt')}")
        print(f"  audit_log_id:     {result.get('audit_log_id')}")
        print(f"  gdpr_compliant:   {result.get('gdpr_compliant')}")
        print(f"  Stats: {result.get('stats')}")
        if result.get("audit_log_id"):
            print(f"\n✅ audit_log escrito en Supabase: {result['audit_log_id']}")
        else:
            print(f"\n⚠️  audit_log_id es null — revisa SUPABASE_SERVICE_KEY")
except urllib.error.HTTPError as e:
    body = e.read().decode()
    print(f"❌ HTTP {e.code}: {body}")
except Exception as e:
    print(f"❌ Error: {e}")
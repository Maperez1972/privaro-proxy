# Privaro Proxy

**The privacy and control layer for AI systems.**

Privaro Proxy intercepts data before it reaches AI models, detects sensitive information, applies policies, and ensures that no raw PII is exposed during inference.

> Use AI without exposing regulated data.

---

## 🚀 What is Privaro?

Privaro is a **runtime data governance layer for AI systems and agents**.

It sits between your application (or agents) and any LLM provider:

Your App / Agents → Privaro → LLM (OpenAI, Anthropic, etc.)

Privaro ensures that:

- Sensitive data is **detected and transformed before inference**
- Models never see raw PII
- Every interaction is **auditable and certifiable**

---

## 🔥 Why this matters

Most AI stacks today:

- Send raw data directly to LLMs
- Rely on contracts and policies for compliance
- Lack structural control of data flows

Privaro introduces:

👉 **Data minimization by architecture**

---

## ⚙️ Core Features

- 🔍 **PII Detection**  
  Hybrid detection (regex + NLP) for names, IDs, IBANs, emails, etc.

- 🔐 **Tokenization / Anonymization**  
  Replace sensitive data with reversible tokens

- 🧠 **Policy Engine**  
  Apply rules by pipeline, use case, or industry

- 🔁 **Re-identification**  
  Recover original values safely outside the model

- 📊 **Audit Logs**  
  Full traceability of every interaction

- ⛓️ **Certified Evidence (iBS)**  
  Blockchain-backed verification of interactions

---

## 🧩 How it works

1. Intercept input (prompt, document, agent message)
2. Detect sensitive data
3. Replace with tokens
4. Forward sanitized input to LLM
5. (Optional) Re-identify output
6. Log and certify the interaction

---

## ⚡ Quickstart

### 1. Get an API Key

Request access at: https://privaro.ai

---

### 2. Protect a prompt

```
curl -X POST "https://privaro-proxy-production.up.railway.app/v1/proxy/protect" \
  -H "Content-Type: application/json" \
  -H "X-Privaro-Key: YOUR_API_KEY" \
  -d '{
    "prompt": "My name is John Doe and my IBAN is ES7620770024003102575766",
    "pipeline_id": "your_pipeline_id"
  }'
```

### Example response

```
{
  "protected_prompt": "My name is [NM-0001] and my IBAN is [BK-0001]",
  "detections": [
    {"type": "full_name"},
    {"type": "iban"}
  ],
  "audit_log_id": "..."
}
```

---

## 🤖 Agent Support

Privaro is designed for modern AI systems, including **multi-step agents**.

### Start a run

POST /v1/agent/run/start

### Protect messages

POST /v1/agent/protect

### Reveal (optional)

POST /v1/agent/reveal

### End run

POST /v1/agent/run/end

---

## 🏗️ Architecture

Privaro Proxy is built as:

- FastAPI backend
- Stateless processing layer
- Secure token vault
- Async certification pipeline (iBS)

Key concepts:

- pipeline_id → defines policies
- conversation_id / agent_run_id → token scope
- audit_log_id → traceability unit

---

## 🔐 Security Model

- Tokenization is reversible but controlled
- Original data never leaves your trusted boundary
- Encryption: AES-256-GCM
- Optional: BYOK (Bring Your Own Key)

---

## 📦 Supported Inputs

- Text prompts
- Emails
- Documents (PDF, DOCX, CSV, Excel)
- Agent messages
- Tool outputs

---

## 🌍 Supported Providers

Privaro works with any LLM:

- OpenAI
- Anthropic
- Google
- Azure OpenAI
- Local models

---

## 🧠 Use Cases

- Legal document analysis
- Financial workflows (KYC, IBAN, AML)
- Healthcare data processing
- AI agents with sensitive data
- Customer support automation

---

## 📈 Positioning

Privaro is:

- Not a DLP tool  
- Not a policy layer  
- Not just observability  

👉 It is a **runtime control layer for AI**

---

## 🛠️ Development

### Run locally

```
uvicorn app.main:app --reload
```

---

### Requirements

- Python 3.10+
- FastAPI
- Supabase (for persistence)
- External LLM provider (optional)

---

## 🤝 Contributing

We welcome contributions.

Please open an issue or submit a PR.

---

## 📜 License

MIT (or specify your license)

---

## 🔗 Related Repositories

- Python SDK → https://github.com/Maperez1972/privaro-sdk-python  
- JS SDK → https://github.com/Maperez1972/privaro-sdk-js  
- Frontend → https://github.com/Maperez1972/privaro-7938a3bd  

---

## 🌐 Learn more

- Website → https://privaro.ai  
- Docs → (coming soon)

---

## 🧭 Final Thought

The question is no longer:

“Can AI work?”

It is:

👉 **“Can it be trusted with real data?”**

Privaro makes that possible.

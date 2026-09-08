# AI Firewall - Enterprise Security for LLMs

## 🚀 Overview

AI Firewall is a security gateway for Large Language Models (LLMs). Applications send AI traffic through the firewall, which authenticates the application, evaluates the prompt, applies security policies, routes allowed requests to an AI provider, filters the response, and records security/usage telemetry.

### Product flow

```text
Customer AI app
      ↓  Bearer AI Firewall API key
AI Firewall /v1/chat/completions
      ↓
Security validation + risk scoring
      ↓
Prompt sanitization / guard
      ↓
OpenAI / Anthropic provider
      ↓
Response filtering
      ↓
Customer AI app
```

### Features
- 🛡️ Real-time prompt injection detection
- 🔒 PII detection and redaction
- ⚡ Parallel validation
- 🎯 Risk scoring and policy enforcement
- 🔑 Per-user API keys with hashed storage, expiry and revocation
- 📊 Real-time dashboard and audit logs
- 🔄 Multi-LLM routing with fallback
- 💰 Cost and token tracking
- 🌐 Threat telemetry

## 🔌 Customer API integration

Users create an API key from **Dashboard → Settings → API Keys**. The raw key is shown only when it is created; the database stores a SHA-256 hash.

The gateway is OpenAI-compatible at:

```text
https://ai-firewall-enhanced.onrender.com/v1/chat/completions
```

Example:

```javascript
const response = await fetch(
  'https://ai-firewall-enhanced.onrender.com/v1/chat/completions',
  {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer aifw_YOUR_API_KEY',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'user', content: 'Hello!' }
      ]
    })
  }
)

const data = await response.json()
```

If the firewall blocks a request, the gateway returns HTTP `403` with a `firewall_blocked` error and risk information. Allowed requests return an OpenAI-style `chat.completion` response plus firewall risk metadata.

## 📦 Quick Start

```bash
# Clone and setup
git clone https://github.com/BSMbennet/ai-firewall-enhanced
cd ai-firewall-enhanced
./setup.sh

# Start development
cd backend && uvicorn app.main:app --reload
cd frontend && npm run dev
```

## 🧱 Infrastructure

- **Frontend**: Vercel
- **API**: Render
- **Database/Auth**: Supabase
- **Cache**: Upstash Redis
- **Storage**: Cloudflare R2
- **Monitoring**: BetterStack
- **CI/CD**: GitHub Actions

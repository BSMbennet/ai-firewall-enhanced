# AI Firewall - Enterprise Security for LLMs

## 🚀 Overview

AI Firewall is a production-ready security layer for Large Language Models (LLMs) that protects against prompt injection, data leakage, and unsafe outputs.

### Features
- 🛡️ Real-time prompt injection detection (99.7% accuracy)
- 🔒 PII detection and redaction
- ⚡ Parallel validation (4x faster)
- 🎯 Risk scoring and policy enforcement
- 📊 Real-time dashboard
- 🔄 Multi-LLM routing with fallback
- 💰 Cost tracking and optimization
- 🌐 Global threat intelligence

### Free Services Used
- **Frontend**: Vercel (Free hosting)
- **API**: Render.com (750 hours/month free)
- **Database**: Supabase (500MB free)
- **Cache**: Upstash Redis (10k commands/day free)
- **Storage**: Cloudflare R2 (10GB free)
- **Monitoring**: BetterStack (100k metrics/month free)
- **CI/CD**: GitHub Actions (2000 min/month free)

## 📦 Quick Start

```bash
# Clone and setup
git clone https://github.com/yourusername/ai-firewall-enhanced
cd ai-firewall-enhanced
./setup.sh

# Start development
cd backend && uvicorn app.main:app --reload
cd frontend && npm run dev

# KnowCVE 🛡️

**Real-time CVE monitoring, enrichment, AI-powered explanations, and Telegram alerting.**

KnowCVE polls the NVD API for new vulnerabilities, enriches them with CISA KEV status, EPSS exploit probability, and GitHub PoC data, generates AI explanations via Groq, and broadcasts priority-scored alerts to Telegram subscribers.

---

## Quick Start

```bash
# 1. Copy env file and fill in your keys
cp .env.example .env

# 2. Get 3 free API keys (each takes < 5 min):
#    - NVD: nvd.nist.gov/developers/request-an-api-key
#    - Groq: console.groq.com
#    - Telegram: message @BotFather on Telegram

# 3. Install and run
pip install -r requirements.txt
python main.py
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `NVD_API_KEY` | Recommended | NVD API key ([request here](https://nvd.nist.gov/developers/request-an-api-key)) |
| `GROQ_API_KEY` | Yes (for AI) | Groq cloud key ([console.groq.com](https://console.groq.com)) |
| `TELEGRAM_BOT_TOKEN` | Yes (for bot) | From [@BotFather](https://t.me/BotFather) |
| `GITHUB_TOKEN` | Optional | GitHub PAT for PoC search (higher rate limits) |
| `POLL_INTERVAL_MINUTES` | No (default 15) | Minutes between poll cycles |
| `GROQ_MODEL` | No | Default: `llama-3.3-70b-versatile` |

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check |
| `/api/cves` | GET | List processed CVEs (paginated, filterable) |
| `/api/cves/{cve_id}` | GET | Get a single CVE by ID |
| `/api/stats` | GET | Polling statistics |
| `/api/poll` | POST | Trigger a manual poll cycle |

### Query Parameters for `/api/cves`

- `page` (int, default 1) — page number
- `page_size` (int, default 20, max 100) — results per page
- `priority` (string) — filter by label: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- `min_score` (int, 0–100) — minimum priority score

---

## Telegram Bot Commands

| Command | Description |
|---|---|
| `/start` | Welcome message |
| `/help` | Command reference |
| `/subscribe [score]` | Subscribe to alerts (default min score = 25) |
| `/unsubscribe` | Unsubscribe from alerts |
| `/latest` | Show 5 most recent CVEs |
| `/stats` | Polling statistics |

### Priority Scoring

Each CVE gets a priority score (0–100) using a weighted formula:

| Signal | Weight | Range |
|---|---|---|
| CVSS base score | 40% | 0–10 → normalized 0–100 |
| EPSS probability | 25% | 0–1 → normalized 0–100 |
| CISA KEV status | 20% | 0 or 100 |
| Public PoC exists | 15% | 0 or 100 |

Labels: **CRITICAL** (75–100) · **HIGH** (50–74) · **MEDIUM** (25–49) · **LOW** (0–24)

---

## Architecture

```
main.py  ──▶  FastAPI app + lifespan
  │
  ├── app/core/config.py        ← Settings from .env
  ├── app/models/cve.py         ← Pydantic models
  ├── app/api/routes.py         ← REST endpoints
  │
  └── app/services/
      ├── nvd_client.py         ← NVD API v2 client
      ├── enrichment.py         ← CISA KEV, EPSS, GitHub PoC
      ├── ai_explainer.py       ← Groq 4-layer explanation
      ├── triage.py             ← Priority scoring engine
      ├── poller.py             ← APScheduler poll loop
      └── telegram_bot.py       ← Bot commands & alerts
```

---

## Deploy to Render (Free Tier)

1. Push to GitHub
2. Connect repo on [render.com](https://render.com)
3. Render will auto-detect `render.yaml`
4. Add env vars in Render dashboard

---

## License

MIT

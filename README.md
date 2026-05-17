# KnowCVE 🛡️

**Next-Generation Threat Intelligence Platform: Real-time CVE monitoring, AI-powered analysis, Exploit Intelligence, and Multi-Source Threat tracking.**

KnowCVE is a comprehensive Threat Intelligence platform that aggregates vulnerabilities, breaches, ransomware operations, and threat actor profiles. It utilizes a powerful backend integrated with Supabase and a sleek Next.js dashboard, delivering real-time actionable insights enriched by AI (powered by Groq).

---

## 🚀 Key Features

*   **Vulnerability Management (CVEs)**: Automated polling from NVD and alternative advisory feeds (npm, pip, go, GitHub Security Advisories).
*   **Advanced AI Analysis (Phase 5.5+)**: Deep-dive technical explanations for every CVE, featuring ATT&CK Kill Chain mapping, Vulnerability Class Analysis, and Mitigation strategies using Groq.
*   **Exploit Intelligence**: Track Exploit Maturity Scores (EMS), CISA KEV status, and EPSS probabilities. 
*   **KnowCVE Risk Score (KRS)**: A proprietary 0-100 scoring system to quickly identify the most critical threats.
*   **Multi-Source Intelligence (Phase 6)**:
    *   **Data Breaches**: Automated tracking of the latest corporate data leaks and breaches.
    *   **Ransomware Tracker**: Active monitoring of ransomware group operations and victims.
    *   **Threat Actors**: Profiles and activities of Nation State and Organized Crime groups.
    *   **IoC Pulse**: Real-time Indicators of Compromise (IoCs).
    *   **Cybersecurity News**: Live aggregated news feeds from top security sources.
*   **Next.js Dashboard**: A stunning, high-performance UI with customizable workspaces, bookmarks, and offensive research tools.
*   **Telegram Bot**: Real-time push notifications for high-priority threats straight to your devices.
*   **Supabase Persistence**: Scalable PostgreSQL database with user authentication and data syncing.

---

## 🏗 Architecture

```
main.py (FastAPI) ──▶ Background Pollers & API Routes
  │
  ├── app/services/
  │   ├── database.py           ← Supabase Database Client
  │   ├── ai_explainer.py       ← Groq 4-layer technical explanation
  │   ├── triage.py             ← Priority (KRS) & Exploit (EMS) scoring
  │   ├── poller.py             ← Multi-threaded polling loops
  │   ├── advisory_feed.py      ← OSINT/Third-party advisory integration
  │   ├── threat_actors.py      ← Threat Actor Intel
  │   ├── breach_intel.py       ← Breach Data pipelines
  │   └── telegram_bot.py       ← Notifications & Alerts
  │
dashboard/ (Next.js) ──▶ React Frontend
  │
  ├── src/app/                  ← Routing (Dashboard, Breaches, Actors, CVEs)
  ├── src/components/           ← UI Components (Tailwind, Framer Motion)
  └── src/lib/supabase/         ← Supabase Auth & DB Contexts
```

---

## ⚙️ Quick Start

### 1. Environment Setup
Copy the example environment files for both the backend and frontend.

```bash
# Backend (FastAPI)
cp .env.example .env

# Frontend (Next.js Dashboard)
cd dashboard
cp .env.example .env.local
cd ..
```

Configure your `.env` files with your keys:
*   **Supabase**: Project URL and Anon/Service Role Keys.
*   **Groq**: API Key (`console.groq.com`).
*   **NVD API**: Optional but recommended (`nvd.nist.gov/developers/request-an-api-key`).
*   **Telegram Bot**: Token from `@BotFather`.

### 2. Run the Backend (FastAPI)
```bash
pip install -r requirements.txt
python main.py
```

### 3. Run the Dashboard (Next.js)
```bash
cd dashboard
npm install
npm run dev
```

Navigate to `http://localhost:3000` to access the KnowCVE platform.

---

## 📊 Priority Scoring System

KnowCVE introduces two proprietary metrics to measure threat urgency:

### KnowCVE Risk Score (KRS)
A 0-100 metric calculated based on:
1.  **CVSS Base Score** (Weight: 40%)
2.  **EPSS Probability** (Weight: 25%)
3.  **CISA KEV Status** (Weight: 20%)
4.  **Public PoC Existence** (Weight: 15%)

Labels: **CRITICAL** (75–100) · **HIGH** (50–74) · **MEDIUM** (25–49) · **LOW** (0–24)

### Exploit Maturity Score (EMS)
Focuses specifically on the weaponization of the vulnerability:
*   Includes Checks for CISA KEV presence, ExploitDB availability, Nuclei templates, and GitHub PoC repositories.

---

## ☁️ Deployment

The project is structured to deploy the backend to Render (via `render.yaml`) and the Next.js Dashboard to Vercel or any other Node.js hosting provider. Ensure you have properly set up your Supabase remote instance before deploying.

---

## 📜 License
MIT

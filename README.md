# CHEQ Automated Threat Mitigation Pipeline — Setup Guide

## Two Ways to Run

### Option 1 — GitHub Pages Dashboard (primary)

Visit the live dashboard deployed to GitHub Pages — no installation needed.

### Option 2 — Local Pipeline (standalone executable)

Download the pre-built `pipeline.exe` from the latest [GitHub Actions run](../../actions/workflows/build-exe.yml) (click the most recent run → **pipeline-windows-exe** artifact) and double-click it, or run it from the command prompt:

```cmd
:: Fetch data from the remote endpoint automatically
pipeline.exe

:: Or supply a local CSV file
pipeline.exe --file data.csv
```

No Python installation required — the executable is fully self-contained.

---

### Running from source (requires Python 3.10+)

```bash
# Run the pipeline (fetches data from remote endpoint automatically)
python pipeline.py

# Or use a local CSV file
python pipeline.py --file sample-traffic-data.csv
```

## What Happens When You Run It

### 1. INGEST
The pipeline makes an **HTTP GET request** to:
```
https://cheq.free.nf/sample-traffic-data.csv
```
This fetches the raw traffic log CSV. The response is parsed into structured session objects with proper type conversion (strings → floats, booleans, datetimes).

If the endpoint is unavailable, you can pass `--file` to use a local CSV.

### 2. DETECT
Each session is scored by **four independent rules** (scores are additive):

| Rule | Score | Trigger |
|------|-------|---------|
| Velocity | +45 | >10 page views from same IP in <60 seconds |
| Impossible Behavior | +50 | 0 seconds on page + form submitted |
| Bot User Agent | +45 | UA contains "bot", "crawl", "scrapy", etc. or is empty |
| Geofencing | +40 | Traffic from China or Russia |

**Verdicts:**
- Score 0 → **Valid** (clean)
- Score 1–80 → **Suspicious** (monitor)
- Score 81–100 → **Bot** (block)

### 3. REMEDIATE
Sessions scoring >80 ("Bot") trigger:
- IP logged to `blocked_ips.json` (simulates firewall update)
- Saved spend calculated at **$5.00 CPC** per bot click
- Fake form submissions counted

### 4. EXPORT
Three output files are generated:

| File | Contents |
|------|----------|
| `processed_sessions.json` | Every session with `risk_score`, `verdict`, `flags` |
| `blocked_ips.json` | Blocked IPs with per-IP click counts and savings |
| `pipeline_summary.json` | Aggregated KPIs for the dashboard |

## Dashboard

Open `dashboard.jsx` in a React environment. It renders the Proof of Value dashboard with:
- KPI cards (sessions, money saved, IPs blocked, forms blocked)
- Traffic breakdown pie chart
- Detection rules bar chart
- 24h traffic timeline
- Interactive session log with click-to-investigate
- Threat origin world map
- Rule tuning panel with live recalculation
- Customer email preview with copy button

## Automation

The pipeline is designed to run unattended. To schedule hourly:

```bash
# crontab -e
0 * * * * cd /path/to/cheq-pipeline && python pipeline.py >> pipeline.log 2>&1
```

Each run is **idempotent** — same input always produces the same output. Safe to rerun.

## Architecture

```
Remote CSV Endpoint
        │
        ▼ HTTP GET (urllib)
   ┌─────────┐
   │  INGEST  │  Parse CSV → typed dicts
   └────┬────┘
        ▼
   ┌─────────┐
   │  DETECT  │  4-rule scoring engine
   └────┬────┘
        ▼
   ┌───────────┐
   │ REMEDIATE │  Block IPs, calc ROI
   └────┬─────┘
        ▼
   ┌─────────┐
   │  EXPORT  │  JSON files
   └────┬────┘
        ▼
   Dashboard (React)
```

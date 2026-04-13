"""
CHEQ Automated Threat Mitigation Pipeline
==========================================
Ingests traffic CSV from remote endpoint → detects threats via 4-rule engine →
blocks bot IPs → calculates ROI → exports results for dashboard.

Designed to run unattended on a schedule (e.g., hourly cron job).
Zero external dependencies — Python 3.10+ standard library only.

Usage:
    python pipeline.py                          # fetch from remote endpoint
    python pipeline.py --file data.csv          # use local CSV file
"""

import csv
import io
import json
import re
import sys
import argparse
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────
DATA_URL = "https://cheq.free.nf/sample-traffic-data.csv"
CPC = 5.00                              # Cost per click ($)
BOT_SCORE_THRESHOLD = 80                # Risk score above which session = "Bot"
VELOCITY_THRESHOLD = 10                 # Max page views per IP in time window
VELOCITY_WINDOW_SECONDS = 60            # Sliding window size (seconds)
BLOCKED_COUNTRIES = {"China", "Russia"} # Geofenced countries (extend via --blocked-countries)

# Base patterns used to detect known bot/crawler/scraper user agent strings.
# Extend at runtime via --bot-ua-patterns.
BASE_BOT_UA_PATTERNS = [
    "bot", "crawl", "spider", "scrapy", "python-requests",
    "curl", "wget", "httpclient", "libwww", "java/",
]

def _build_bot_ua_regex(extra_patterns: list[str] | None = None) -> re.Pattern:
    """Compile the bot UA regex from base patterns plus any extra patterns.

    Patterns are treated as regex substrings (not escaped), so you can pass
    plain strings like 'go-http-client' or regex fragments like r'go-http.*'.
    """
    patterns = list(BASE_BOT_UA_PATTERNS)
    if extra_patterns:
        patterns.extend(extra_patterns)
    return re.compile("|".join(patterns), re.IGNORECASE)

BOT_UA_PATTERNS = _build_bot_ua_regex()

# Output file paths
OUTPUT_RESULTS = Path("processed_sessions.json")
OUTPUT_BLOCKED = Path("blocked_ips.json")
OUTPUT_SUMMARY = Path("pipeline_summary.json")


# ══════════════════════════════════════════════════════════════════
# STEP 1: INGEST — Fetch and parse the traffic data
# ══════════════════════════════════════════════════════════════════

def fetch_csv_from_url(url: str) -> str:
    """
    HTTP GET request to fetch CSV data from a remote endpoint.

    Uses urllib (stdlib) so there are zero external dependencies.
    In production you might use `requests` for retries, auth headers, etc.

    This is equivalent to:
        curl https://cheq.free.nf/sample-traffic-data.csv

    Or in JavaScript:
        const response = await fetch(url);
        const csvText = await response.text();
    """
    print(f"[ingest] Fetching data from {url}")

    # Build the request — you could add headers here (API keys, auth tokens)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "CHEQ-Pipeline/1.0"}  # Identify ourselves
    )

    try:
        # This is the actual HTTP GET call
        with urllib.request.urlopen(request, timeout=30) as response:
            # Read the response body and decode from bytes → string
            raw_bytes = response.read()
            csv_text = raw_bytes.decode("utf-8")

            status = response.status
            content_length = len(csv_text)
            print(f"[ingest] HTTP {status} — received {content_length:,} bytes")
            return csv_text

    except urllib.error.HTTPError as e:
        print(f"[ingest] ERROR: HTTP {e.code} — {e.reason}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[ingest] ERROR: Could not connect — {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[ingest] ERROR: {e}")
        sys.exit(1)


def read_csv_from_file(path: Path) -> str:
    """Read CSV from a local file as a fallback."""
    print(f"[ingest] Reading data from local file: {path}")
    if not path.exists():
        print(f"[ingest] ERROR: File not found: {path}")
        sys.exit(1)
    return path.read_text(encoding="utf-8")


def parse_csv(csv_text: str) -> list[dict]:
    """
    Parse raw CSV text into a list of session dictionaries.

    Each row becomes a dict like:
    {
        "timestamp": datetime(2025, 4, 8, 12, 30, 0),
        "session_id": "abc-123",
        "ip_address": "185.92.212.7",
        "user_agent": "Mozilla/5.0 ...",
        "page_url": "/pricing",
        "time_on_page": 0.0,
        "clicks": 31,
        "form_submitted": True,
        "referrer": "direct",
        "country": "China",
        "device_type": "Desktop"
    }
    """
    sessions = []
    reader = csv.DictReader(io.StringIO(csv_text))

    for row in reader:
        # Type conversion — CSV gives us everything as strings
        try:
            row["time_on_page"] = float(row.get("time_on_page", 0))
        except (ValueError, TypeError):
            row["time_on_page"] = 0.0

        try:
            row["clicks"] = int(row.get("clicks", 0))
        except (ValueError, TypeError):
            row["clicks"] = 0

        # Convert "true"/"false" string → Python boolean
        form_val = row.get("form_submitted", "false").strip().lower()
        row["form_submitted"] = form_val == "true"

        # Parse timestamp string → datetime object for time comparisons
        try:
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
        except (ValueError, KeyError):
            row["timestamp"] = datetime.now()

        sessions.append(row)

    print(f"[ingest] Parsed {len(sessions)} sessions")
    return sessions


# ══════════════════════════════════════════════════════════════════
# STEP 2: DETECT — Apply the 4-rule threat detection engine
# ══════════════════════════════════════════════════════════════════

def find_velocity_ips(sessions: list[dict]) -> set[str]:
    """
    Velocity Check: Find IPs that made > VELOCITY_THRESHOLD requests
    within a VELOCITY_WINDOW_SECONDS sliding window.

    Algorithm:
    1. Group all session timestamps by IP address
    2. Sort timestamps for each IP
    3. Use a sliding window: for each timestamp, count how many
       subsequent timestamps fall within the window
    4. If count > threshold, flag the IP

    This catches bots that scrape pages at machine speed.
    A real human doesn't visit 10+ pages in under 60 seconds.
    """
    # Step 1: Group timestamps by IP
    ip_timestamps: dict[str, list[datetime]] = defaultdict(list)
    for session in sessions:
        ip_timestamps[session["ip_address"]].append(session["timestamp"])

    # Step 2 & 3: Sliding window check
    flagged_ips = set()
    for ip, times in ip_timestamps.items():
        times.sort()
        for i in range(len(times)):
            count = 1
            for j in range(i + 1, len(times)):
                delta = (times[j] - times[i]).total_seconds()
                if delta <= VELOCITY_WINDOW_SECONDS:
                    count += 1
                else:
                    break  # Times are sorted, so all subsequent are > window
            if count > VELOCITY_THRESHOLD:
                flagged_ips.add(ip)
                break  # No need to check more windows for this IP

    if flagged_ips:
        print(f"[detect] Velocity: flagged {len(flagged_ips)} IPs")
    return flagged_ips


def detect_threats(
    sessions: list[dict],
    bot_ua_regex: re.Pattern | None = None,
    blocked_countries: set[str] | None = None,
) -> list[dict]:
    """
    Score each session using 4 independent detection rules.
    Scores are ADDITIVE — a session triggering multiple rules gets a higher score.

    Rules:
        +45  Velocity spike (>10 req/min from same IP)
        +50  Impossible behavior (0s on page + form submitted)
        +45  Bot user agent (matches known bot/crawler pattern)
        +40  Geofenced (traffic from blocklisted country)

    Verdicts:
        Score 0       → "Valid"      (clean traffic)
        Score 1-80    → "Suspicious" (monitor, don't block)
        Score 81-100  → "Bot"        (block immediately)

    Args:
        bot_ua_regex:       Compiled regex for bot UA detection. Defaults to
                            BOT_UA_PATTERNS (built from BASE_BOT_UA_PATTERNS).
                            Pass a custom regex to extend or replace patterns.
        blocked_countries:  Set of country names to geofence. Defaults to
                            BLOCKED_COUNTRIES. Pass a custom set to add or
                            change which countries are blocked.
    """
    if bot_ua_regex is None:
        bot_ua_regex = BOT_UA_PATTERNS
    if blocked_countries is None:
        blocked_countries = BLOCKED_COUNTRIES

    velocity_ips = find_velocity_ips(sessions)

    for session in sessions:
        score = 0
        flags = []

        # Rule 1: Velocity Check
        if session["ip_address"] in velocity_ips:
            score += 45
            flags.append("velocity")

        # Rule 2: Impossible Behavior
        # A human cannot submit a form in 0 seconds — this catches bots
        # that POST form data directly without rendering the page
        if session["time_on_page"] == 0 and session["form_submitted"]:
            score += 50
            flags.append("impossible_behavior")

        # Rule 3: Bot User Agent
        # Many bots use automated HTTP libraries that identify themselves
        ua = session.get("user_agent", "")
        if not ua or bot_ua_regex.search(ua):
            score += 45
            flags.append("bot_ua")

        # Rule 4: Geofencing
        # Block traffic from countries where the client has no business
        if session.get("country", "").strip() in blocked_countries:
            score += 40
            flags.append("geofenced")

        # Cap at 100 and assign verdict
        session["risk_score"] = min(score, 100)
        session["flags"] = flags

        if score > BOT_SCORE_THRESHOLD:
            session["verdict"] = "Bot"
        elif score > 0:
            session["verdict"] = "Suspicious"
        else:
            session["verdict"] = "Valid"

    # Count results
    verdicts = defaultdict(int)
    for s in sessions:
        verdicts[s["verdict"]] += 1
    print(f"[detect] Results: {verdicts['Valid']} valid, "
          f"{verdicts['Suspicious']} suspicious, {verdicts['Bot']} bot")

    return sessions


# ══════════════════════════════════════════════════════════════════
# STEP 3: REMEDIATE — Block bot IPs and calculate ROI
# ══════════════════════════════════════════════════════════════════

def remediate(sessions: list[dict]) -> dict:
    """
    For every confirmed Bot (risk_score > 80):
    1. Add the IP to the blocklist (simulates firewall update)
    2. Calculate saved spend: clicks × $5.00 CPC
    3. Track fake form submissions that were intercepted

    In production, this step would:
    - Make an API call to Cloudflare/AWS WAF to block the IP
    - Write to a database instead of a JSON file
    - Send alerts via Slack/PagerDuty
    """
    blocked_ips: dict[str, dict] = {}
    total_saved = 0.0
    fake_forms_blocked = 0
    total_bot_clicks = 0

    for session in sessions:
        if session["verdict"] != "Bot":
            continue

        ip = session["ip_address"]
        clicks = session["clicks"]
        saved = clicks * CPC

        total_saved += saved
        total_bot_clicks += clicks

        if session["form_submitted"]:
            fake_forms_blocked += 1

        # Aggregate per-IP stats
        if ip not in blocked_ips:
            blocked_ips[ip] = {
                "ip": ip,
                "first_seen": session["timestamp"].isoformat(),
                "total_clicks_blocked": 0,
                "total_saved": 0.0,
                "flags": [],
                "sessions_count": 0,
            }
        blocked_ips[ip]["total_clicks_blocked"] += clicks
        blocked_ips[ip]["total_saved"] += saved
        blocked_ips[ip]["sessions_count"] += 1
        for flag in session["flags"]:
            if flag not in blocked_ips[ip]["flags"]:
                blocked_ips[ip]["flags"].append(flag)

    # Write blocked IPs to file (simulates firewall update)
    blocked_list = sorted(blocked_ips.values(), key=lambda x: -x["total_saved"])
    with open(OUTPUT_BLOCKED, "w") as f:
        json.dump(blocked_list, f, indent=2)

    # Build summary for dashboard
    verdicts = defaultdict(int)
    for s in sessions:
        verdicts[s["verdict"]] += 1

    summary = {
        "total_sessions": len(sessions),
        "valid": verdicts["Valid"],
        "suspicious": verdicts["Suspicious"],
        "bot": verdicts["Bot"],
        "blocked_ips_count": len(blocked_ips),
        "total_bot_clicks": total_bot_clicks,
        "total_money_saved": round(total_saved, 2),
        "fake_forms_blocked": fake_forms_blocked,
        "cpc": CPC,
        "blocked_ips": blocked_list,
        "recent_threats": [
            {
                "session_id": s["session_id"],
                "ip": s["ip_address"],
                "risk_score": s["risk_score"],
                "flags": s["flags"],
                "country": s.get("country", "Unknown"),
                "clicks": s["clicks"],
                "timestamp": s["timestamp"].isoformat(),
            }
            for s in sorted(sessions, key=lambda x: x["timestamp"], reverse=True)
            if s["verdict"] == "Bot"
        ][:20],
    }

    with open(OUTPUT_SUMMARY, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[remediate] Blocked {len(blocked_ips)} IPs | "
          f"Saved ${total_saved:,.2f} | "
          f"Fake forms blocked: {fake_forms_blocked}")
    return summary


# ══════════════════════════════════════════════════════════════════
# STEP 4: EXPORT — Write processed sessions to JSON
# ══════════════════════════════════════════════════════════════════

def export_results(sessions: list[dict]):
    """
    Export all sessions with their risk scores and verdicts.
    This is the processed dataset that could feed a database or API.
    """
    output = []
    for s in sessions:
        output.append({
            "session_id": s.get("session_id", ""),
            "timestamp": s["timestamp"].isoformat(),
            "ip_address": s["ip_address"],
            "user_agent": s.get("user_agent", ""),
            "page_url": s.get("page_url", ""),
            "time_on_page": s["time_on_page"],
            "clicks": s["clicks"],
            "form_submitted": s["form_submitted"],
            "referrer": s.get("referrer", ""),
            "country": s.get("country", ""),
            "device_type": s.get("device_type", ""),
            "risk_score": s["risk_score"],
            "verdict": s["verdict"],
            "flags": s["flags"],
        })

    with open(OUTPUT_RESULTS, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[export] Wrote {len(output)} sessions → {OUTPUT_RESULTS}")


# ══════════════════════════════════════════════════════════════════
# MAIN — Run the full pipeline
# ══════════════════════════════════════════════════════════════════

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="CHEQ Threat Mitigation Pipeline")
    parser.add_argument(
        "--file", type=str, default=None,
        help="Path to local CSV file (if not provided, fetches from remote URL)"
    )
    parser.add_argument(
        "--blocked-countries", type=str, default=None,
        metavar="COUNTRY1,COUNTRY2,...",
        help=(
            "Comma-separated list of additional countries to geofence "
            "(added to the default: China, Russia). "
            "Example: --blocked-countries 'Iran,North Korea'"
        ),
    )
    parser.add_argument(
        "--bot-ua-patterns", type=str, default=None,
        metavar="PATTERN1,PATTERN2,...",
        help=(
            "Comma-separated list of additional user-agent substrings to flag "
            "as bots (added to the built-in list). "
            "Example: --bot-ua-patterns 'go-http-client,axios,okhttp'"
        ),
    )
    args = parser.parse_args()

    # Build runtime-configurable blocked countries set
    blocked_countries = set(BLOCKED_COUNTRIES)
    if args.blocked_countries:
        extra = {c.strip() for c in args.blocked_countries.split(",") if c.strip()}
        blocked_countries |= extra
        print(f"[config] Blocked countries: {sorted(blocked_countries)}")

    # Build runtime-configurable bot UA regex
    extra_ua_patterns = None
    if args.bot_ua_patterns:
        extra_ua_patterns = [p.strip() for p in args.bot_ua_patterns.split(",") if p.strip()]
        print(f"[config] Extra bot UA patterns: {extra_ua_patterns}")
    bot_ua_regex = _build_bot_ua_regex(extra_ua_patterns)

    print("=" * 60)
    print("  CHEQ Automated Threat Mitigation Pipeline")
    print("=" * 60)

    # ── INGEST ──
    if args.file:
        csv_text = read_csv_from_file(Path(args.file))
    else:
        csv_text = fetch_csv_from_url(DATA_URL)

    sessions = parse_csv(csv_text)

    if not sessions:
        print("[error] No sessions found in data. Exiting.")
        sys.exit(1)

    # ── DETECT ──
    sessions = detect_threats(sessions, bot_ua_regex=bot_ua_regex, blocked_countries=blocked_countries)

    # ── REMEDIATE ──
    summary = remediate(sessions)

    # ── EXPORT ──
    export_results(sessions)

    # ── REPORT ──
    print("\n" + "=" * 60)
    print("  PIPELINE COMPLETE")
    print("=" * 60)
    print(f"  Total Sessions Analyzed : {summary['total_sessions']}")
    print(f"  Valid                   : {summary['valid']}")
    print(f"  Suspicious              : {summary['suspicious']}")
    print(f"  Bot (blocked)           : {summary['bot']}")
    print(f"  Unique IPs Blocked      : {summary['blocked_ips_count']}")
    print(f"  Total Bot Clicks        : {summary['total_bot_clicks']}")
    print(f"  Money Saved             : ${summary['total_money_saved']:,.2f}")
    print(f"  Fake Forms Blocked      : {summary['fake_forms_blocked']}")
    print(f"  Annualized Savings      : ${summary['total_money_saved'] * 365:,.2f}")
    print("=" * 60)
    print(f"\n  Output files:")
    print(f"    {OUTPUT_RESULTS}")
    print(f"    {OUTPUT_BLOCKED}")
    print(f"    {OUTPUT_SUMMARY}")


if __name__ == "__main__":
    main()

# Security Log Analyzer

An AI-powered security log analysis tool that parses Linux `auth.log` and Nginx access logs, detects suspicious patterns using rule-based logic, and classifies threats on-demand using the Anthropic Claude API.

---

## Live Demo

A live demo is available at:  
[security-log-analyzer-production.up.railway.app](https://security-log-analyzer-production.up.railway.app/)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        FastAPI Backend                        │
│                                                              │
│  ┌─────────────┐   ┌──────────────────┐   ┌──────────────┐  │
│  │  Log Parser  │──▶│ Detection Engine │──▶│ AI Classifier│  │
│  │  auth / nginx│   │  (rule-based)    │   │  (on demand) │  │
│  └─────────────┘   └──────────────────┘   └──────────────┘  │
│         │                   │                     │          │
│         ▼                   ▼                     ▼          │
│     LogEvent[]       SuspiciousEvent[]     severity +        │
│     (structured)     + reasons             threat_type       │
└──────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Vanilla HTML/JS   │
                    │  Single-page UI    │
                    └────────────────────┘
```

---

## Detection Logic

### Auth Log Rules

| Rule                | Threshold                   | Reason                                   |
| ------------------- | --------------------------- | ---------------------------------------- |
| Brute force         | ≥8 failed logins / IP       | Password spraying or credential stuffing |
| Invalid user probe  | Any                         | Automated user enumeration               |
| After-hours login   | Success outside 06:00–22:00 | Anomalous access time                    |
| Suspicious keywords | Any match                   | Tooling signatures (sqlmap, nikto, etc.) |

### Nginx Log Rules

| Rule                      | Threshold           | Reason                                        |
| ------------------------- | ------------------- | --------------------------------------------- |
| Sensitive endpoint access | Any                 | `/admin`, `/.env`, `/.git`, `/wp-admin`, etc. |
| HTTP error flood          | ≥15 401/403 / IP    | Scanning or fuzzing                           |
| SQL injection signature   | Keyword match       | `UNION SELECT`, `../`, `%2e%2e`               |
| After-hours write request | Outside 06:00–22:00 | Suspicious mutation activity                  |

The rule engine assigns a **baseline severity** before any AI classification:

- **High**: Brute force, SQLi, RCE signatures
- **Medium**: Scanning, sensitive path access, after-hours activity
- **Low**: Single low-confidence indicators

---

## AI Integration

AI classification is **on-demand per event** — the user clicks "Classify" on individual suspicious events rather than classifying everything automatically. This keeps costs low and gives the analyst control.

Flagged events are sent to the Claude API with **structured data only** — never raw log lines. This enforces data hygiene and prevents accidental leakage of credentials or PII that may appear in raw logs.

Each event payload includes:

- `log_source`, `event_type`, `source_ip`, `username`
- `endpoint`, `http_method`, `http_status_code`
- `detection_reasons` (from rule engine)

The model returns a JSON object with:

- `severity`: `low | medium | high`
- `threat_type`: `brute_force | scanning | unauthorized_access | benign | unknown`
- `explanation`: 1–2 sentence analyst summary

Uses `claude-haiku-4-5-20251001` for cost efficiency.

---

## Security Considerations

- **No raw logs sent to AI**: Only structured, sanitized fields are transmitted.
- **No log storage**: Uploaded files are processed in-memory and discarded.
- **File size limit**: Uploads capped at 500 KB to prevent abuse.
- **API key via environment variable**: Never hardcoded; loaded via `python-dotenv`.
- **Input validation**: Pydantic models enforce schema at every layer boundary.
- **Error isolation**: AI failures are caught and logged; the pipeline continues without crashing.

---

## Limitations

- Auth log parser assumes standard OpenSSH/syslog format; custom formats may not parse.
- Detection thresholds are static — a production system would use adaptive baselines.
- No persistence layer: results are lost on page refresh (by design, for privacy).
- AI classification is per-event and synchronous; not suitable for bulk classification of large files.
- No IPv6 support in current regex patterns.

---

## Future Improvements

- [ ] Add GeoIP lookup for source IPs
- [ ] IP reputation check via AbuseIPDB or Shodan API
- [ ] Time-series visualization of attack patterns
- [ ] Persistent storage with SQLite / PostgreSQL
- [ ] Streaming log ingestion (Kafka / file watch)
- [ ] SIEM integration (Elastic / Splunk export format)
- [ ] Alerting via webhook (Slack, PagerDuty)
- [ ] IPv6 support
- [ ] Bulk AI classification with rate limit handling

---

## Quick Start

```bash
# 1. Clone and set up
git clone https://github.com/yourname/security-log-analyzer
cd security-log-analyzer
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env

# 3. Run
python -m uvicorn backend.main:app --reload

# 4. Open http://localhost:8000
# Use the demo buttons or upload a file from /logs

# ── Docker ──
docker compose up --build
```

## Run Tests

```bash
python -m pytest tests/ -v
```

import csv
import json
import tempfile
from backend.models.schemas import SuspiciousEvent


def _serialize_events(events: list[SuspiciousEvent]) -> list[dict]:
    out = []
    for ev in events:
        e = ev.event
        out.append({
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source_ip": e.source_ip,
            "username": e.username,
            "event_type": e.event_type,
            "log_source": e.log_source.value,
            "endpoint": e.endpoint,
            "http_status_code": e.http_status_code,
            "reasons": ev.reasons,
            "severity": ev.severity.value,
            "threat_type": ev.threat_type.value,
            "ai_explanation": ev.ai_explanation,
        })
    return out


def export_json(events: list[SuspiciousEvent]) -> str:
    data = _serialize_events(events)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w")
    json.dump(data, tmp, indent=2)
    tmp.close()
    return tmp.name


def export_csv(events: list[SuspiciousEvent]) -> str:
    rows = _serialize_events(events)
    if not rows:
        rows = [{}]
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv", mode="w", newline="")
    writer = csv.DictWriter(tmp, fieldnames=rows[0].keys())
    writer.writeheader()
    for row in rows:
        row["reasons"] = " | ".join(row["reasons"])
        writer.writerow(row)
    tmp.close()
    return tmp.name
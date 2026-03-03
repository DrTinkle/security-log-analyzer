import json
import logging
import os
from anthropic import AsyncAnthropic
from backend.models.schemas import SuspiciousEvent, Severity, ThreatType

logger = logging.getLogger(__name__)

_client: AsyncAnthropic | None = None


def _get_client() -> AsyncAnthropic:
    global _client
    if _client is None:
        _client = AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    return _client


_SYSTEM_PROMPT = """You are a cybersecurity analyst assistant specializing in log analysis.
You will receive structured data about suspicious security events — never raw log files.
Respond ONLY with valid JSON. No markdown, no explanation outside the JSON object.

Your response must conform to this exact schema:
{
  "severity": "low" | "medium" | "high",
  "threat_type": "brute_force" | "scanning" | "unauthorized_access" | "benign" | "unknown",
  "explanation": "1-2 sentence explanation of why this is or isn't a threat"
}

Guidelines:
- high:   Active exploitation, credential success after brute force, command injection
- medium: Brute force in progress, scanning, repeated access denied, after-hours activity
- low:    Single probe, low-confidence indicator, likely automated crawler
- benign: Monitoring tool, health check, known-good pattern
"""


def _build_event_payload(ev: SuspiciousEvent) -> dict:
    """
    Construct a clean, minimal payload for the LLM.
    We deliberately exclude raw log lines to avoid leaking sensitive data.
    """
    e = ev.event
    return {
        "log_source": e.log_source.value,
        "event_type": e.event_type,
        "source_ip": e.source_ip,
        "username": e.username,
        "status": e.status,
        "endpoint": e.endpoint,
        "http_method": e.http_method,
        "http_status_code": e.http_status_code,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "detection_reasons": ev.reasons,
    }


async def classify_event(ev: SuspiciousEvent) -> SuspiciousEvent:
    """Classify a single suspicious event via the Anthropic API."""
    payload = _build_event_payload(ev)

    try:
        response = await _get_client().messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=150,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"Classify this security event:\n{json.dumps(payload, indent=2)}",
                }
            ],
        )

        raw_text = response.content[0].text.strip()
        logger.debug("AI raw response: %s", raw_text)

        clean = raw_text.replace("```json", "").replace("```", "").strip()
        result = json.loads(clean)

        ev.severity = Severity(result.get("severity", "unknown"))
        ev.threat_type = ThreatType(result.get("threat_type", "unknown"))
        ev.ai_explanation = result.get("explanation", "")

    except json.JSONDecodeError:
        logger.warning("AI returned non-JSON response for event %s", ev.event.id)
        ev.severity = Severity.UNKNOWN
        ev.ai_explanation = "Classification failed: model returned unexpected format."

    except Exception as exc:
        logger.error("AI classification error for event %s: %s", ev.event.id, exc)
        ev.severity = Severity.UNKNOWN
        ev.ai_explanation = f"Classification unavailable: {str(exc)}"

    return ev


async def classify_batch(events: list[SuspiciousEvent], max_concurrent: int = 5) -> list[SuspiciousEvent]:
    """
    Classify a batch of events with controlled concurrency to respect rate limits.
    Processes in chunks of `max_concurrent` events at a time.
    """
    import asyncio
    results = []

    for i in range(0, len(events), max_concurrent):
        chunk = events[i: i + max_concurrent]
        classified = await asyncio.gather(*[classify_event(ev) for ev in chunk])
        results.extend(classified)

    return results
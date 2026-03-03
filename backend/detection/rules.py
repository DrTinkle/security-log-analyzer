from collections import defaultdict
from datetime import time as dtime
from backend.models.schemas import LogEvent, SuspiciousEvent, LogSource, Severity

# ── Thresholds (easily configurable) ────────────────────────────────────────
FAILED_LOGIN_THRESHOLD = 8        # per IP
HTTP_ERROR_THRESHOLD = 15         # 401/403 per IP
AFTER_HOURS_START = dtime(22, 0)  # 10 PM
AFTER_HOURS_END = dtime(6, 0)     # 6 AM

# Nginx paths that are always suspicious
SUSPICIOUS_PATHS = {
    "/admin", "/wp-admin", "/.env", "/etc/passwd",
    "/phpmyadmin", "/.git", "/backup", "/shell", "/cmd", "/eval",
    "/config", "/wp-login.php",
}

# Keywords in raw log lines that warrant attention
SUSPICIOUS_KEYWORDS = [
    "sqlmap", "nikto", "nmap", "masscan",
    "../", "%2e%2e", "union select", "<script",
    "wget ", "curl ", "/bin/bash", "/bin/sh",
]


def _is_after_hours(event: LogEvent) -> bool:
    if not event.timestamp:
        return False
    t = event.timestamp.time()
    if AFTER_HOURS_START <= AFTER_HOURS_END:
        return AFTER_HOURS_START <= t <= AFTER_HOURS_END
    # Spans midnight
    return t >= AFTER_HOURS_START or t <= AFTER_HOURS_END


def _check_suspicious_keywords(raw: str) -> list[str]:
    raw_lower = raw.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in raw_lower]


def _default_severity(reasons: list[str]) -> Severity:
    """
    Assign a baseline severity from detection reasons before AI classification.
    Intentionally conservative — the AI refines downward when appropriate.

    HIGH:   Active exploitation signatures (brute force success, SQLi, RCE)
    MEDIUM: Reconnaissance, scanning, policy violations, after-hours activity
    LOW:    Single low-confidence indicators
    """
    joined = " ".join(reasons).lower()
    if any(k in joined for k in ("brute force", "sql", "injection", "/bin/bash", "/bin/sh")):
        return Severity.HIGH
    if any(k in joined for k in ("scanning", "sensitive path", "after-hours", "probe")):
        return Severity.MEDIUM
    return Severity.LOW


class DetectionEngine:
    """
    Rule-based detection engine.
    Processes a list of LogEvents and returns SuspiciousEvents.

    Rules applied:
      AUTH:
        1. Brute force: ≥N failed logins from same IP
        2. Invalid user probe
        3. After-hours successful login
        4. Suspicious keywords in raw line

      NGINX:
        1. Access to sensitive endpoint
        2. ≥N 401/403 errors from same IP
        3. Suspicious keywords (SQLi, XSS, scanner UA)
        4. After-hours write requests
    """

    def run(self, events: list[LogEvent]) -> list[SuspiciousEvent]:
        # ── Build per-IP counters in a single pass ───────────────────────
        failed_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        http_errors_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

        for ev in events:
            if ev.log_source == LogSource.AUTH and ev.event_type == "failed_login" and ev.source_ip:
                failed_by_ip[ev.source_ip].append(ev)

            if ev.log_source == LogSource.NGINX and ev.http_status_code in (401, 403) and ev.source_ip:
                http_errors_by_ip[ev.source_ip].append(ev)

        # IPs that crossed the threshold
        brute_force_ips = {ip for ip, evs in failed_by_ip.items() if len(evs) >= FAILED_LOGIN_THRESHOLD}
        scanning_ips = {ip for ip, evs in http_errors_by_ip.items() if len(evs) >= HTTP_ERROR_THRESHOLD}

        # ── Evaluate each event ──────────────────────────────────────────
        suspicious: list[SuspiciousEvent] = []

        for ev in events:
            reasons: list[str] = []

            # ── AUTH rules ───────────────────────────────────────────────
            if ev.log_source == LogSource.AUTH:
                ip = ev.source_ip or ""

                if ev.event_type == "failed_login" and ip in brute_force_ips:
                    count = len(failed_by_ip[ip])
                    reasons.append(f"Brute force: {count} failed logins from {ip}")

                if ev.event_type == "invalid_user":
                    reasons.append(f"Probe: invalid username '{ev.username}' attempted from {ip}")

                if ev.event_type == "successful_login" and _is_after_hours(ev):
                    reasons.append(f"After-hours login ({ev.timestamp.strftime('%H:%M')}) from {ip}")

            # ── NGINX rules ──────────────────────────────────────────────
            elif ev.log_source == LogSource.NGINX:
                ip = ev.source_ip or ""

                if ev.event_type == "sensitive_endpoint_access":
                    reasons.append(f"Sensitive path accessed: {ev.endpoint}")

                if ip in scanning_ips and ev.http_status_code in (401, 403):
                    count = len(http_errors_by_ip[ip])
                    reasons.append(f"Likely scanning: {count} auth errors from {ip}")

                if ev.http_status_code in (401, 403) and ip not in scanning_ips:
                    reasons.append(f"Access denied ({ev.http_status_code}) to {ev.endpoint}")

                if ev.event_type == "write_request" and _is_after_hours(ev):
                    reasons.append(f"After-hours {ev.http_method} to {ev.endpoint}")

            # ── Cross-source: suspicious keywords ────────────────────────
            kw_hits = _check_suspicious_keywords(ev.raw)
            if kw_hits:
                reasons.append(f"Suspicious keyword(s) detected: {', '.join(kw_hits)}")

            if reasons:
                suspicious.append(SuspiciousEvent(
                    event=ev,
                    suspicious=True,
                    reasons=reasons,
                    severity=_default_severity(reasons),
                ))

        return suspicious
import re
import uuid
from datetime import datetime, timezone
from backend.parsers.base import BaseLogParser
from backend.models.schemas import LogEvent, LogSource


# ── Regex patterns ──────────────────────────────────────────────────────────

# Standard syslog timestamp: "Jan  3 14:22:01"
_TIMESTAMP_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

# Failed password: "Failed password for [invalid user] <user> from <ip> port <n> ssh2"
_FAILED_PW_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)

# Accepted password / publickey
_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)

# Invalid user (no password attempt, just probe)
_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
)

# sudo: user NOT in sudoers / command execution
_SUDO_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)"
)

# Connection closed / disconnected
_DISCONNECT_RE = re.compile(
    r"Received disconnect from (?P<ip>[\d.]+)"
)

_CURRENT_YEAR = datetime.now(timezone.utc).year


def _parse_timestamp(line: str) -> datetime | None:
    m = _TIMESTAMP_RE.match(line)
    if not m:
        return None
    try:
        raw = f"{m.group('month')} {m.group('day')} {m.group('time')} {_CURRENT_YEAR}"
        return datetime.strptime(raw, "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


class AuthLogParser(BaseLogParser):
    """
    Parser for Linux /var/log/auth.log (and similar syslog-format auth files).
    Handles SSH, sudo, and PAM events.
    """

    def parse_line(self, line: str, line_num: int) -> LogEvent | None:
        ts = _parse_timestamp(line)

        # ── Failed password ──────────────────────────────────────────────
        m = _FAILED_PW_RE.search(line)
        if m:
            return LogEvent(
                id=str(uuid.uuid4()),
                timestamp=ts,
                source_ip=m.group("ip"),
                username=m.group("user"),
                event_type="failed_login",
                status="failure",
                log_source=LogSource.AUTH,
                raw=line,
            )

        # ── Accepted login ───────────────────────────────────────────────
        m = _ACCEPTED_RE.search(line)
        if m:
            return LogEvent(
                id=str(uuid.uuid4()),
                timestamp=ts,
                source_ip=m.group("ip"),
                username=m.group("user"),
                event_type="successful_login",
                status="success",
                log_source=LogSource.AUTH,
                raw=line,
            )

        # ── Invalid user probe ───────────────────────────────────────────
        m = _INVALID_USER_RE.search(line)
        if m:
            return LogEvent(
                id=str(uuid.uuid4()),
                timestamp=ts,
                source_ip=m.group("ip"),
                username=m.group("user"),
                event_type="invalid_user",
                status="failure",
                log_source=LogSource.AUTH,
                raw=line,
            )

        # ── Sudo command ─────────────────────────────────────────────────
        m = _SUDO_RE.search(line)
        if m:
            return LogEvent(
                id=str(uuid.uuid4()),
                timestamp=ts,
                source_ip=None,
                username=m.group("user"),
                event_type="sudo_command",
                status="executed",
                endpoint=m.group("cmd").strip(),
                log_source=LogSource.AUTH,
                raw=line,
            )

        # ── Disconnect ───────────────────────────────────────────────────
        m = _DISCONNECT_RE.search(line)
        if m:
            return LogEvent(
                id=str(uuid.uuid4()),
                timestamp=ts,
                source_ip=m.group("ip"),
                username=None,
                event_type="disconnect",
                status="info",
                log_source=LogSource.AUTH,
                raw=line,
            )

        # Unrecognised line — still store it with minimal metadata
        return LogEvent(
            id=str(uuid.uuid4()),
            timestamp=ts,
            event_type="unknown",
            status="info",
            log_source=LogSource.AUTH,
            raw=line,
        )
import re
import uuid
from datetime import datetime
from backend.parsers.base import BaseLogParser
from backend.models.schemas import LogEvent, LogSource


# ── Nginx combined log format ────────────────────────────────────────────────
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
_NGINX_RE = re.compile(
    r'(?P<ip>[\d.]+)\s+'          # client IP
    r'\S+\s+'                      # ident (usually -)
    r'(?P<user>\S+)\s+'            # auth user (usually -)
    r'\[(?P<ts>[^\]]+)\]\s+'       # timestamp
    r'"(?P<method>\S+)\s+'         # HTTP method
    r'(?P<path>\S+)\s+'            # request path
    r'\S+"\s+'                     # protocol
    r'(?P<status>\d{3})\s+'        # status code
    r'(?P<size>\d+|-)'             # response size
)

_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# Sensitive paths worth flagging at parser level
_SENSITIVE_PATH_RE = re.compile(
    r"(/admin|/wp-admin|/\.env|/config|/etc/passwd|/phpmyadmin|"
    r"/.git|/backup|/shell|/cmd|/eval)",
    re.IGNORECASE,
)


def _parse_nginx_ts(raw: str) -> datetime | None:
    try:
        return datetime.strptime(raw, _TS_FORMAT)
    except ValueError:
        return None


def _classify_event(method: str, path: str, status: int) -> str:
    if _SENSITIVE_PATH_RE.search(path):
        return "sensitive_endpoint_access"
    if status in (401, 403):
        return "access_denied"
    if status == 404:
        return "not_found"
    if status >= 500:
        return "server_error"
    if method in ("POST", "PUT", "DELETE", "PATCH"):
        return "write_request"
    return "normal_request"


class NginxLogParser(BaseLogParser):
    """
    Parser for Nginx combined access log format.
    """

    def parse_line(self, line: str, line_num: int) -> LogEvent | None:
        m = _NGINX_RE.match(line)
        if not m:
            return None  # Skip lines that don't match the expected format

        status_code = int(m.group("status"))
        method = m.group("method").upper()
        path = m.group("path")
        user = m.group("user")

        return LogEvent(
            id=str(uuid.uuid4()),
            timestamp=_parse_nginx_ts(m.group("ts")),
            source_ip=m.group("ip"),
            username=None if user == "-" else user,
            event_type=_classify_event(method, path, status_code),
            status=m.group("status"),
            endpoint=path,
            http_method=method,
            http_status_code=status_code,
            log_source=LogSource.NGINX,
            raw=line,
        )
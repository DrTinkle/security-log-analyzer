import uuid
from datetime import datetime
from backend.detection.rules import DetectionEngine, FAILED_LOGIN_THRESHOLD
from backend.models.schemas import LogEvent, LogSource


def _make_failed_login(ip: str) -> LogEvent:
    return LogEvent(
        id=str(uuid.uuid4()),
        timestamp=datetime(2026, 1, 3, 10, 0, 0),
        source_ip=ip,
        username="root",
        event_type="failed_login",
        status="failure",
        log_source=LogSource.AUTH,
        raw="fake line",
    )


def _make_nginx_event(ip: str, path: str, status: int) -> LogEvent:
    return LogEvent(
        id=str(uuid.uuid4()),
        timestamp=datetime(2026, 1, 3, 10, 0, 0),
        source_ip=ip,
        event_type="access_denied" if status in (401, 403) else "normal_request",
        status=str(status),
        endpoint=path,
        http_method="GET",
        http_status_code=status,
        log_source=LogSource.NGINX,
        raw="fake nginx line",
    )


class TestDetectionEngine:
    engine = DetectionEngine()

    def test_brute_force_flagged(self):
        events = [_make_failed_login("1.2.3.4") for _ in range(FAILED_LOGIN_THRESHOLD + 2)]
        results = self.engine.run(events)
        assert any("Brute force" in r for ev in results for r in ev.reasons)

    def test_below_threshold_not_flagged_for_brute_force(self):
        events = [_make_failed_login("9.9.9.9") for _ in range(FAILED_LOGIN_THRESHOLD - 1)]
        results = self.engine.run(events)
        assert not any("Brute force" in r for ev in results for r in ev.reasons)

    def test_keyword_detection(self):
        ev = LogEvent(
            id=str(uuid.uuid4()),
            event_type="normal_request",
            log_source=LogSource.NGINX,
            raw="GET /search?q=sqlmap+test HTTP/1.1 200",
        )
        results = self.engine.run([ev])
        assert results
        assert any("sqlmap" in r for ev in results for r in ev.reasons)
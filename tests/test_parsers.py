import pytest
from backend.parsers.auth_log import AuthLogParser
from backend.parsers.nginx_log import NginxLogParser
from backend.models.schemas import LogSource


class TestAuthLogParser:
    parser = AuthLogParser()

    def test_failed_login(self):
        line = "Jan  3 02:15:01 server sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
        ev = self.parser.parse_line(line, 1)
        assert ev is not None
        assert ev.event_type == "failed_login"
        assert ev.source_ip == "1.2.3.4"
        assert ev.username == "root"
        assert ev.status == "failure"

    def test_accepted_login(self):
        line = "Jan  3 09:01:12 server sshd[2]: Accepted password for alice from 10.0.0.1 port 22 ssh2"
        ev = self.parser.parse_line(line, 1)
        assert ev.event_type == "successful_login"
        assert ev.username == "alice"
        assert ev.source_ip == "10.0.0.1"

    def test_invalid_user(self):
        line = "Jan  3 02:16:00 server sshd[3]: Invalid user ftpuser from 5.6.7.8 port 44321"
        ev = self.parser.parse_line(line, 1)
        assert ev.event_type == "invalid_user"
        assert ev.username == "ftpuser"

    def test_blank_line_filtered_in_parse_file(self):
        # parse_line falls through to 'unknown' — blank filtering happens in parse_file
        events = self.parser.parse_file("")
        assert events == []

    def test_log_source(self):
        line = "Jan  3 02:15:01 server sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
        ev = self.parser.parse_line(line, 1)
        assert ev.log_source == LogSource.AUTH


class TestNginxLogParser:
    parser = NginxLogParser()

    def test_normal_get(self):
        line = '10.0.0.1 - - [03/Jan/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024'
        ev = self.parser.parse_line(line, 1)
        assert ev is not None
        assert ev.http_status_code == 200
        assert ev.http_method == "GET"
        assert ev.event_type == "normal_request"

    def test_sensitive_path(self):
        line = '10.0.0.1 - - [03/Jan/2026:10:00:01 +0000] "GET /wp-admin HTTP/1.1" 404 512'
        ev = self.parser.parse_line(line, 1)
        assert ev.event_type == "sensitive_endpoint_access"

    def test_access_denied(self):
        line = '10.0.0.1 - - [03/Jan/2026:10:00:01 +0000] "GET /admin HTTP/1.1" 403 256'
        ev = self.parser.parse_line(line, 1)
        assert ev.event_type in ("sensitive_endpoint_access", "access_denied")

    def test_malformed_line_returns_none(self):
        assert self.parser.parse_line("not a real log line", 1) is None
"""
generate_logs.py
Run standalone to write files: python generate_logs.py
Or imported by main.py for the /demo endpoint.
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

OUTPUT_DIR = Path("logs")

LEGIT_IPS   = ["10.0.0.5", "10.0.0.8", "192.168.1.10", "192.168.1.20"]
BRUTE_IPS   = ["185.220.101.45", "194.165.16.77"]
SCANNER_IPS = ["45.33.32.156", "198.20.69.74"]
SQLI_IP     = "203.0.113.99"
LEGIT_USERS = ["alice", "bob", "deploy", "carol"]

BASE_TIME = datetime(2026, 1, 3, 8, 0, 0)


def _tick(dt: datetime, seconds: int = None) -> datetime:
    return dt + timedelta(seconds=seconds or random.randint(1, 10))

def _fmt_auth_ts(dt: datetime) -> str:
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")

def _fmt_nginx_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def _nginx_line(dt, ip, method, path, status, size=None) -> str:
    size = size or random.randint(200, 5000)
    return f'{ip} - - [{_fmt_nginx_ts(dt)}] "{method} {path} HTTP/1.1" {status} {size}'


NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/api/health",
    "/static/style.css", "/static/app.js", "/favicon.ico",
    "/api/products", "/api/users/me",
]

SENSITIVE_PATHS = [
    "/wp-admin", "/.env", "/phpmyadmin", "/admin",
    "/admin/login", "/.git/config", "/backup", "/config",
]

SCANNER_PATHS = SENSITIVE_PATHS + [
    "/cgi-bin/test", "/shell.php", "/cmd.php", "/eval.php",
    "/api/v1/../../etc/passwd", "/.htaccess",
]


def generate_auth_log_content() -> str:
    lines = []
    t = BASE_TIME

    # Lots of normal logins throughout the day
    for _ in range(30):
        t = _tick(t, random.randint(120, 600))
        user = random.choice(LEGIT_USERS)
        ip = random.choice(LEGIT_IPS)
        lines.append(f"{_fmt_auth_ts(t)} server sshd[1000]: Accepted password for {user} from {ip} port 22 ssh2")

    # One brute force IP (not two)
    brute_ip = BRUTE_IPS[0]
    for _ in range(random.randint(9, 12)):
        t = _tick(t, random.randint(1, 4))
        user = random.choice(["root", "admin", "ubuntu", "oracle", "test"])
        lines.append(f"{_fmt_auth_ts(t)} server sshd[1001]: Failed password for {user} from {brute_ip} port {random.randint(40000, 65000)} ssh2")

    # A few scattered failed logins from legit IPs (typos etc)
    for _ in range(4):
        t = _tick(t, random.randint(300, 900))
        user = random.choice(LEGIT_USERS)
        ip = random.choice(LEGIT_IPS)
        lines.append(f"{_fmt_auth_ts(t)} server sshd[1001]: Failed password for {user} from {ip} port 22 ssh2")

    # Two invalid user probes
    for probe_user in ["ftpuser", "oracle"]:
        t = _tick(t, random.randint(60, 300))
        lines.append(f"{_fmt_auth_ts(t)} server sshd[1002]: Invalid user {probe_user} from {brute_ip} port {random.randint(40000, 65000)}")

    # Normal sudo
    t = _tick(t, 600)
    lines.append(f"{_fmt_auth_ts(t)} server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")

    # One after-hours successful login
    t = BASE_TIME.replace(hour=23, minute=47)
    lines.append(f"{_fmt_auth_ts(t)} server sshd[1010]: Accepted password for alice from 198.51.100.25 port 54321 ssh2")

    # Disconnects
    for _ in range(3):
        t = _tick(t, random.randint(5, 20))
        lines.append(f"{_fmt_auth_ts(t)} server sshd[1012]: Received disconnect from {brute_ip} port {random.randint(40000,65000)}: 11: Bye Bye [preauth]")

    lines.sort()
    return "\n".join(lines) + "\n"


def generate_nginx_log_content() -> str:
    lines = []
    t = BASE_TIME

    # Heavy normal traffic
    for _ in range(80):
        t = _tick(t, random.randint(5, 60))
        ip = random.choice(LEGIT_IPS)
        path = random.choice(NORMAL_PATHS)
        lines.append(_nginx_line(t, ip, "GET", path, 200))

    # A few normal POSTs
    for _ in range(10):
        t = _tick(t, random.randint(30, 120))
        ip = random.choice(LEGIT_IPS)
        lines.append(_nginx_line(t, ip, "POST", "/api/users/me", 200))

    # One scanner IP hitting sensitive paths
    scanner_ip = SCANNER_IPS[0]
    for path in random.sample(SCANNER_PATHS, 8):
        t = _tick(t, random.randint(1, 5))
        status = random.choice([401, 403, 404])
        lines.append(_nginx_line(t, scanner_ip, "GET", path, status, 256))

    # One SQLi attempt
    t = _tick(t, 30)
    lines.append(_nginx_line(t, SQLI_IP, "GET", "/search?q=1+UNION+SELECT+*+FROM+users--", 200, 2048))

    # One after-hours DELETE
    t = BASE_TIME.replace(hour=23, minute=58)
    lines.append(_nginx_line(t, "172.16.0.55", "DELETE", "/api/records/42", 200, 64))

    lines.sort()
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    OUTPUT_DIR.mkdir(exist_ok=True)

    auth_content = generate_auth_log_content()
    auth_path = OUTPUT_DIR / "demo_auth.log"
    auth_path.write_text(auth_content)
    print(f"✔ Generated {auth_path} ({auth_content.count(chr(10))} lines)")

    nginx_content = generate_nginx_log_content()
    nginx_path = OUTPUT_DIR / "demo_nginx.log"
    nginx_path.write_text(nginx_content)
    print(f"✔ Generated {nginx_path} ({nginx_content.count(chr(10))} lines)")

    print("\nDone. Upload these files at http://localhost:8000")
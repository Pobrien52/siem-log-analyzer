
from collections import defaultdict
from datetime import datetime, timedelta
import re


FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5


def detect_failed_logins(log_lines):
    """Detect repeated failed logins within a time window."""

    failed_attempts = defaultdict(list)

    for line in log_lines:
        if "LOGIN_FAILED" not in line:
            continue

        timestamp_match = re.match(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
            line
        )
        ip_match = re.search(r"\bip=(\S+)", line)
        user_match = re.search(r"\buser=(\S+)", line)

        if not all([
            timestamp_match,
            ip_match,
            user_match
        ]):
            continue

        try:
            timestamp = datetime.strptime(
                timestamp_match.group(1),
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue

        ip = ip_match.group(1)
        user = user_match.group(1)

        failed_attempts[ip].append({
            "timestamp": timestamp,
            "user": user
        })

    alerts = []
    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for ip, attempts in failed_attempts.items():
        attempts.sort(key=lambda x: x["timestamp"])

        left = 0
        detected_window = None

        for right, attempt in enumerate(attempts):
            while (
                attempt["timestamp"]
                - attempts[left]["timestamp"]
                > window
            ):
                left += 1

            count = right - left + 1

            if count >= FAILED_LOGIN_THRESHOLD:
                detected_window = attempts[left:right + 1]
                break

        if detected_window:
            alerts.append({
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "ip": ip,
                "attempts": len(detected_window),
                "window_minutes": TIME_WINDOW_MINUTES,
                "first_attempt": (
                    detected_window[0]["timestamp"].isoformat()
                ),
                "last_attempt": (
                    detected_window[-1]["timestamp"].isoformat()
                ),
                "message": (
                    f"Possible brute-force attack from {ip}"
                )
            })

    return alerts


def detect_successful_logins(log_lines):
    """Identify successful login events."""

    alerts = []

    for line in log_lines:
        if "LOGIN_SUCCESS" not in line:
            continue

        ip_match = re.search(r"\bip=(\S+)", line)
        user_match = re.search(r"\buser=(\S+)", line)

        if ip_match and user_match:
            alerts.append({
                "type": "SUCCESSFUL_LOGIN",
                "severity": "INFO",
                "ip": ip_match.group(1),
                "user": user_match.group(1)
            })

    return alerts

from collections import defaultdict
import re


FAILED_LOGIN_THRESHOLD = 5


def detect_failed_logins(log_lines):
    failed_attempts = defaultdict(list)

    for line in log_lines:
        if "LOGIN_FAILED" not in line:
            continue

        ip_match = re.search(r"ip=(\S+)", line)
        user_match = re.search(r"user=(\S+)", line)

        if ip_match and user_match:
            ip = ip_match.group(1)
            user = user_match.group(1)

            failed_attempts[ip].append({
                "user": user,
                "log": line.strip()
            })

    alerts = []

    for ip, attempts in failed_attempts.items():
        if len(attempts) >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "ip": ip,
                "attempts": len(attempts),
                "message": f"Possible brute-force attack from {ip}"
            })

    return alerts


def detect_successful_logins(log_lines):
    alerts = []

    for line in log_lines:
        if "LOGIN_SUCCESS" in line:
            ip_match = re.search(r"ip=(\S+)", line)
            user_match = re.search(r"user=(\S+)", line)

            if ip_match and user_match:
                alerts.append({
                    "type": "SUCCESSFUL_LOGIN",
                    "severity": "INFO",
                    "ip": ip_match.group(1),
                    "user": user_match.group(1)
                })

    return alerts

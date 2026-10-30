import sys
import os

from detector import (
    detect_failed_logins,
    detect_successful_logins
)

from reporter import generate_report


def read_log_file(file_path):
    with open(file_path, "r") as file:
        return file.readlines()


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <log_file>")
        return

    log_file = sys.argv[1]

    if not os.path.exists(log_file):
        print(f"Error: {log_file} does not exist.")
        return

    print("=" * 50)
    print("SIEM LOG ANALYZER")
    print("=" * 50)

    logs = read_log_file(log_file)

    print(f"Analyzing {len(logs)} log entries...")

    brute_force_alerts = detect_failed_logins(logs)
    successful_logins = detect_successful_logins(logs)

    alerts = brute_force_alerts + successful_logins

    print(f"Total alerts detected: {len(alerts)}")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['type']} - "
            f"{alert.get('ip', 'N/A')}"
        )

    os.makedirs("reports", exist_ok=True)

    generate_report(
        alerts,
        "reports/security_report.json"
    )


if __name__ == "__main__":
    main()

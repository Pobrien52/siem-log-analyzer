
import sys
import unittest
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "src")
)

from detector import detect_failed_logins


def make_logs(seconds, ip="192.168.1.50"):
    start = datetime(2026, 10, 6, 8, 0, 0)

    return [
        (
            f"{(start + timedelta(seconds=s)):%Y-%m-%d %H:%M:%S} "
            f"WARN LOGIN_FAILED user=admin ip={ip}"
        )
        for s in seconds
    ]


class TestTimeWindow(unittest.TestCase):

    def test_five_attempts_in_one_minute(self):
        logs = make_logs([0, 10, 20, 30, 40])
        alerts = detect_failed_logins(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "BRUTE_FORCE")
        self.assertEqual(alerts[0]["attempts"], 5)

    def test_attempts_spread_over_hours(self):
        logs = make_logs([0, 3600, 7200, 10800, 14400])
        alerts = detect_failed_logins(logs)

        self.assertEqual(alerts, [])

    def test_exact_window_boundary(self):
        logs = make_logs([0, 60, 120, 180, 300])
        alerts = detect_failed_logins(logs)

        self.assertEqual(len(alerts), 1)

    def test_outside_window_boundary(self):
        logs = make_logs([0, 60, 120, 180, 301])
        alerts = detect_failed_logins(logs)

        self.assertEqual(alerts, [])

    def test_unsorted_logs(self):
        logs = make_logs([40, 0, 30, 10, 20])
        alerts = detect_failed_logins(logs)

        self.assertEqual(len(alerts), 1)

    def test_separate_ip_addresses(self):
        logs = (
            make_logs([0, 10, 20], "192.168.1.50")
            + make_logs([0, 10, 20], "10.0.0.55")
        )

        self.assertEqual(detect_failed_logins(logs), [])

    def test_missing_timestamp(self):
        logs = [
            "LOGIN_FAILED user=admin ip=192.168.1.50"
        ] * 5

        self.assertEqual(detect_failed_logins(logs), [])

    def test_alert_timestamps(self):
        logs = make_logs([0, 10, 20, 30, 40])
        alerts = detect_failed_logins(logs)

        self.assertEqual(alerts[0]["window_minutes"], 5)
        self.assertEqual(
            alerts[0]["first_attempt"],
            "2026-10-06T08:00:00"
        )
        self.assertEqual(
            alerts[0]["last_attempt"],
            "2026-10-06T08:00:40"
        )


if __name__ == "__main__":
    unittest.main()

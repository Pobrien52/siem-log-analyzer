
import sys
import unittest
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "src")
)

from detector import (
    detect_failed_logins,
    detect_successful_logins
)


class TestSIEMDetector(unittest.TestCase):

    def test_brute_force_detected(self):
        logs = [
            f"2026-10-06 08:00:{i:02d} WARN LOGIN_FAILED "
            "user=admin ip=192.168.1.50"
            for i in range(5)
        ]

        alerts = detect_failed_logins(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "BRUTE_FORCE")
        self.assertEqual(alerts[0]["attempts"], 5)

    def test_below_threshold(self):
        logs = [
            "LOGIN_FAILED user=admin ip=192.168.1.50"
            for _ in range(4)
        ]

        self.assertEqual(detect_failed_logins(logs), [])

    def test_separate_ip_addresses(self):
        logs = [
            "LOGIN_FAILED user=admin ip=192.168.1.50"
            for _ in range(3)
        ] + [
            "LOGIN_FAILED user=admin ip=10.0.0.55"
            for _ in range(3)
        ]

        self.assertEqual(detect_failed_logins(logs), [])

    def test_successful_login(self):
        logs = [
            "LOGIN_SUCCESS user=patrick ip=192.168.1.20"
        ]

        alerts = detect_successful_logins(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "INFO")
        self.assertEqual(alerts[0]["user"], "patrick")

    def test_empty_logs(self):
        self.assertEqual(detect_failed_logins([]), [])
        self.assertEqual(detect_successful_logins([]), [])

    def test_unrelated_events(self):
        logs = [
            "INFO SYSTEM_START",
            "WARN DISK_USAGE_HIGH"
        ]

        self.assertEqual(detect_failed_logins(logs), [])
        self.assertEqual(detect_successful_logins(logs), [])


if __name__ == "__main__":
    unittest.main()

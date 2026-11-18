# SIEM Log Analyzer

**Python-Based Security Monitoring, Threat Detection & Log Analysis**

A Python cybersecurity project that analyzes authentication logs, identifies suspicious login activity, and generates structured JSON security reports.

This project demonstrates practical experience with **Python, SIEM concepts, security log analysis, threat detection engineering, and automated testing**.

## Features

- **Brute-Force Detection:** Identifies five failed login attempts from the same source IP within five minutes.
- **Sliding Time Window:** Correlates authentication failures based on timestamps rather than counting all failures in a log.
- **Successful Login Monitoring:** Records successful authentication events for security analysis.
- **IP-Based Correlation:** Groups failed authentication attempts by source IP address.
- **Severity Classification:** Assigns HIGH severity to potential brute-force attacks and INFO severity to successful logins.
- **JSON Reporting:** Generates structured reports containing alert types, IP addresses, timestamps, and detection information.
- **Automated Testing:** Includes 14 Python unit tests.
- **GitHub Actions:** Automatically tests the analyzer and validates report generation.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Core application |
| Regular Expressions | Extract authentication indicators |
| datetime | Timestamp parsing and time-window correlation |
| JSON | Structured security reporting |
| unittest | Automated testing |
| Git & GitHub | Version control |
| GitHub Actions | Continuous integration |

## Project Structure

```text
siem-log-analyzer/
├── src/
│   ├── analyzer.py
│   ├── detector.py
│   └── reporter.py
├── logs/
│   └── sample_auth.log
├── reports/
├── tests/
│   ├── test_detector.py
│   └── test_time_window.py
├── .github/
│   └── workflows/
│       └── tests.yml
├── .gitignore
└── README.md
```

## Installation

Requires Python 3.9 or newer. No external Python packages are required.

```powershell
git clone https://github.com/Pobrien52/siem-log-analyzer.git
cd siem-log-analyzer
```

## Usage

Run the analyzer using the included sample authentication log:

```powershell
python src/analyzer.py logs/sample_auth.log
```

The application reads authentication events, detects potential brute-force attacks, identifies successful logins, and saves a security report.

View the generated report:

```powershell
Get-Content .\reports\security_report.json
```

## Example Detection Results

The included sample dataset produces:

- 14 authentication log entries analyzed
- 2 potential brute-force alerts
- 4 successful login informational alerts
- 6 total alerts

Example brute-force alert:

```json
{
  "type": "BRUTE_FORCE",
  "severity": "HIGH",
  "ip": "192.168.1.50",
  "attempts": 5,
  "window_minutes": 5,
  "first_attempt": "2026-10-06T08:03:21",
  "last_attempt": "2026-10-06T08:03:37",
  "message": "Possible brute-force attack from 192.168.1.50"
}
```

## Detection Logic

The analyzer groups failed authentication attempts by source IP and sorts them by timestamp.

A potential brute-force alert is generated when at least five failed logins occur within a five-minute sliding window.

The detector currently generates one brute-force alert per IP address, even if multiple qualifying windows occur. Failed-login records without valid timestamps are skipped.

These thresholds are configurable in the source code and are intended for demonstration, not production deployment.

## Automated Testing

Run all tests:

```powershell
python -m unittest discover -s tests -v
```

The test suite covers authentication event parsing, failed-login thresholds, IP separation, successful logins, time-window boundaries, unsorted logs, and invalid or missing timestamps.

GitHub Actions runs the tests and checks the generated security report after pushes and pull requests.

## Current Limitations

- Supports the project's predefined authentication log format
- Processes log files in batches rather than streaming live events
- Does not currently integrate with a commercial SIEM platform
- Uses source IP correlation rather than user-specific behavioral baselines
- Does not automatically enrich alerts with threat intelligence
- Requires valid timestamps for brute-force detection

## Future Improvements

- Real-time log monitoring
- Failed-login followed by successful-login correlation
- Alert deduplication and multiple attack-window detection
- Configurable detection thresholds
- Windows Event Log and Linux authentication log ingestion
- Security dashboard
- Threat intelligence enrichment

## Skills Demonstrated

Python programming, security event monitoring, log parsing, SIEM detection engineering, timestamp correlation, JSON reporting, automated unit testing, and CI/CD.

## Author

**Patrick O'Brien**

Cybersecurity Student | Division I Student-Athlete | Aspiring Cybersecurity Engineer

[GitHub](https://github.com/Pobrien52) | [LinkedIn](https://www.linkedin.com/in/patrick-o-brien-381971334)

---

*Developed for cybersecurity education and defensive security engineering practice.*
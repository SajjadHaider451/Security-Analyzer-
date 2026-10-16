# Python Security Log Analyzer

A beginner-friendly, educational cybersecurity tool that ingests raw authentication logs, parses structured events, detects suspicious authentication patterns (such as rapid brute-force attacks and failed-then-successful compromise sequences), and generates executive reports and actionable alerts for security analysts.

---

## What This Application Accomplishes

In security operations (SOC), analysts frequently encounter thousands or millions of lines of raw text logs. Manually reading through them is impossible.

This tool automatically answers the central question of security log analysis:  
> **"What happened in this log, and is there anything here that deserves a security analyst's attention?"**

### Core Capabilities Checklist

| Capability | Status | Description |
| :--- | :---: | :--- |
| **Read log files** | ✅ | Streams logs line-by-line for high performance and low memory footprint. |
| **Parse individual events** | ✅ | Splits and validates raw text into structured records. |
| **Extract timestamps** | ✅ | Parses dates and times into Python `datetime` objects for math and time diffs. |
| **Extract usernames** | ✅ | Isolates targeted user accounts (e.g., `admin`, `root`, `sajjad`). |
| **Extract IP addresses** | ✅ | Identifies source IP addresses generating connections. |
| **Identify event types** | ✅ | Distinguishes between `SUCCESS_LOGIN` and `FAILED_LOGIN`. |
| **Count successful logins** | ✅ | Aggregates successful authentication volume. |
| **Count failed logins** | ✅ | Aggregates failure volume across users and hosts. |
| **Track activity by IP** | ✅ | Measures connection attempts and failure rates per IP address. |
| **Track activity by username** | ✅ | Identifies which usernames are targeted most frequently. |
| **Detect repeated failures** | ✅ | Ranks top failed-login sources. |
| **Detect potential brute force** | ✅ | Flags rapid bursts of failed attempts exceeding threshold limits. |
| **Analyze activity in time windows** | ✅ | Uses sliding time windows (e.g., 45 seconds vs. 8 hours). |
| **Detect failed → successful patterns** | ✅ | Detects account takeover indicators (multiple fails followed by success). |
| **Assign alert severity** | ✅ | Labels findings with `HIGH` or `MEDIUM` based on targets and volume. |
| **Generate security alerts** | ✅ | Creates structured visual alert boxes with evidence and rationale. |
| **Generate summary reports** | ✅ | Produces clean executive summaries with top sources and recommendations. |
| **Handle malformed log entries** | ✅ | Defensively skips corrupt or incomplete lines without crashing. |
| **Handle missing files/errors** | ✅ | Validates file paths and permissions with user-friendly error messages. |
| **Run from command line** | ✅ | Supports CLI arguments (`--threshold`, `--window`, `--save`). |
| **Save analysis results** | ✅ | Automatically exports formatted reports to disk (`analysis_report.txt`). |

---

## Key Concepts Explained for Beginners

### 1. Networking Concepts
- **IP Address (Internet Protocol Address):** The unique address identifying a computer on a network.
- **Source IP:** The IP address of the machine attempting to log in. In security analysis, tracking the source IP tells us *who* or *where* the attack is originating from.
- **Private vs. Public IPs:**
  - `192.168.x.x`, `10.x.x.x`, and `172.16.x.x` are **Private IP addresses** used inside a home, office, or company network.
  - `203.0.113.x` is a **Public IP address** located on the external internet.

### 2. Cybersecurity Concepts
- **Authentication:** Verifying that a user or machine is who they claim to be (usually username + password).
- **Brute-Force Attack:** An automated trial-and-error attack where an unauthorized user rapidly guesses passwords. For example, 15 failed logins within 45 seconds is almost certainly an automated attack script.
- **Time-Window Analysis:** Why time matters: 5 failed logins spread across 8 hours is usually an employee forgetting their password. 5 failed logins within 20 seconds is an active attack!
- **Suspicious Authentication Sequence (Failed → Success):** When an IP fails multiple times on an account and then suddenly succeeds, it strongly indicates that the attacker successfully guessed or cracked the password. This is a critical indicator of account compromise.
- **Account Targeting Analysis:** Identifying *which* accounts an attacker wants. Seeing an IP try `admin`, `root`, and `test` shows an intentional effort to compromise privileged accounts.
- **Alert Severity:**
  - `HIGH`: Poses an immediate threat or possible breach (e.g., attacks on `admin`/`root`, or failed-then-success sequences).
  - `MEDIUM`: Unusual behavior exceeding thresholds on non-privileged accounts.
  - `LOW`: Baseline informational events.

### 3. Python Concepts
- **`datetime.strptime()` & `total_seconds()`:** Raw timestamps (like `"2026-09-28 10:15:32"`) are just strings. Converting them to `datetime` objects lets Python subtract them (`time2 - time1`) to find the exact number of seconds between events.
- **Dictionaries (`dict`):** Key-value data structures used to store structured log records (`{"username": "admin", "ip": "192.168.1.50"}`).
- **Sets (`set()`):** Collections that store only unique items. Used to count unique IPs and users effortlessly without counting duplicates.
- **Defensive Programming (`try...except`):** Anticipating errors (e.g., missing files, malformed lines, unexpected text) and handling them gracefully so the script continues running reliably.

---

## File Structure

```text
CyberSecurity/
├── analyzer.py            # Complete Python Security Log Analyzer
├── security.log           # Realistic security log containing 1,250 events & attack scenarios
├── analysis_report.txt    # Generated security analysis report and alerts
└── README.md              # Project documentation and guide
```

---

## How to Run

### Basic Run (uses default `security.log`)
```bash
python analyzer.py
```

### Analyze a Specific Log File
```bash
python analyzer.py path/to/another.log
```

### Save Report to a Custom File
```bash
python analyzer.py security.log --save custom_report.txt
```

### Customize Detection Rules
Adjust the brute force threshold (e.g., 10 failures) and time window (e.g., 60 seconds):
```bash
python analyzer.py security.log --threshold 10 --window 60
```

### View Help & Options
```bash
python analyzer.py --help
```

---

## Sample Output

```text
========================================
      PYTHON SECURITY LOG ANALYZER      
========================================

[*] Target Log File: security.log
[*] Brute Force Rule: >= 5 failures within 120 seconds
[*] Sequence Rule:   >= 3 failures followed by SUCCESS

[*] Ingestion complete: 1250 events parsed successfully.
[*] [Defensive Parser] Skipped 1 malformed or unparseable line(s) safely.

========================================
       SECURITY LOG ANALYSIS REPORT
========================================

Log File: security.log

Total Events:              1,250
Successful Logins:           940
Failed Logins:               310
Unique IP Addresses:          87
Unique Users:                 24

----------------------------------------
TOP FAILED-LOGIN SOURCES
----------------------------------------

192.168.1.50        47 failures
10.0.0.15           31 failures
172.16.0.25         18 failures

----------------------------------------
ACCOUNT-TARGET ANALYSIS
----------------------------------------

Suspicious IP: 192.168.1.50

Targeted Accounts:
    admin:   12 attempts
    root:    7 attempts
    test:    3 attempts

Suspicious IP: 10.0.0.15

Targeted Accounts:
    admin:   10 attempts
    guest:   6 attempts
    root:    5 attempts

Suspicious IP: 172.16.0.25

Targeted Accounts:
    guest:   6 attempts
    test:    6 attempts
    backup:  6 attempts

----------------------------------------
SUSPICIOUS ACTIVITY
----------------------------------------

Potential Brute Force:        3
Suspicious Login Sequences:   2
High-Severity Alerts:         2

----------------------------------------
RECOMMENDATION
----------------------------------------

Review the high-severity alerts and
investigate the associated IP addresses
and user accounts.

----------------------------------------
DETAILED SECURITY ALERTS
----------------------------------------

========================================
        SECURITY ALERT
========================================

Alert Type: Potential Brute Force
Severity: HIGH

Source IP: 192.168.1.50
Target Account: admin
Failed Attempts: 15
Time Window: 45 seconds

Reason:
15 failed authentication attempts were
detected from the same source within
the configured threshold.

========================================
        SECURITY ALERT
========================================

Alert Type: Potentially Suspicious Authentication Sequence
Severity: HIGH

Source IP: 192.168.1.50
Target Account: admin
Failed Attempts: 8
Successful Login: 1

Reason:
Multiple failed authentication attempts were followed
by a successful authentication from the same source.
```

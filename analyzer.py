"""
================================================================================
SECURITY LOG ANALYZER
================================================================================
A beginner-friendly, educational cybersecurity tool that parses raw security
logs, analyzes authentication activity, detects suspicious behavior (such as
brute-force attacks and failed-then-successful login sequences), and generates
clear, professional security reports for security analysts.

--------------------------------------------------------------------------------
KEY CONCEPTS EXPLAINED FOR BEGINNERS:
--------------------------------------------------------------------------------
1. WHAT IS A SECURITY LOG?
   A security log is an automated record of security-related events on a computer
   or network. Every time someone tries to log in, the operating system records:
   - When it happened (Timestamp)
   - What happened (Event Type: FAILED_LOGIN or SUCCESS_LOGIN)
   - Who tried to log in (Username: admin, root, alice, etc.)
   - Where the request came from (IP Address: 192.168.1.50)

2. WHAT IS AN IP ADDRESS? (Networking Concept)
   An IP (Internet Protocol) address is like a digital phone number or street
   address for a computer.
   - "Source IP" is the address of the device making the login attempt.
   - Private IPs (like 192.168.x.x, 10.x.x.x, 172.16.x.x) belong to local internal
     networks (like your home or company Wi-Fi).
   - Public IPs (like 203.0.113.5) belong to devices connected directly to the
     public internet.

3. WHAT IS A BRUTE-FORCE ATTACK? (Cybersecurity Concept)
   In a brute-force attack, an attacker uses automated software to guess many
   passwords in rapid succession. For example, trying 15 passwords in 45 seconds
   is almost certainly a computer program trying to break in, not a human.

4. WHAT IS A SUSPICIOUS AUTHENTICATION SEQUENCE? (Cybersecurity Concept)
   If an IP address fails to log in multiple times (e.g., 8 failed attempts) and
   then suddenly succeeds on the next attempt, this pattern strongly suggests the
   attacker finally guessed or cracked the correct password (account takeover).
   Security analysts treat this as a high-priority incident to investigate!

5. WHAT IS DEFENSIVE PROGRAMMING? (Python Concept)
   Real-world log files are messy. Some lines might be corrupted, blank, or
   malformed. We use defensive programming (like 'try...except' and validation checks)
   so our program skips bad lines safely without crashing.
================================================================================
"""

import os
import sys
import argparse
from datetime import datetime


# ==============================================================================
# CONFIGURATION & THRESHOLDS (Detection Rules)
# ==============================================================================
# In cybersecurity, detection rules use "thresholds" to decide when activity is
# normal vs. suspicious. Adjusting these values balances detection sensitivity
# and false alarms (false positives).

# Minimum failed login attempts from a single IP within the time window
# to trigger a "Potential Brute Force" alert.
DEFAULT_BRUTE_FORCE_THRESHOLD = 5

# Time window in seconds for brute force detection (120 seconds = 2 minutes).
# Multiple failures occurring inside this short window indicate automated attacks.
DEFAULT_TIME_WINDOW_SECONDS = 120

# Number of consecutive failures before a successful login required to flag
# a "Suspicious Authentication Sequence" (Failed -> Successful).
DEFAULT_SEQUENCE_FAIL_THRESHOLD = 3

# Maximum allowable gap in seconds between consecutive events in a sequence.
# If events are hours apart, it's normal human forgetting; if seconds/minutes apart,
# it's an active attacker! (600 seconds = 10 minutes)
MAX_SEQUENCE_GAP_SECONDS = 600

# High-risk administrative usernames that attackers commonly target.
SENSITIVE_ACCOUNTS = {"admin", "root", "administrator", "superuser"}


# ==============================================================================
# SECTION 1: LOG PARSING (Extracting Structured Data)
# ==============================================================================

def parse_log_entry(line):
    """
    Takes a single raw line of text from the log file and extracts its data fields.

    Expected format:
        YYYY-MM-DD HH:MM:SS EVENT_TYPE username=VALUE ip=VALUE
    Example:
        2026-09-28 10:15:32 FAILED_LOGIN username=admin ip=192.168.1.10

    Python Concepts used:
    - .strip(): Removes extra whitespace or newline characters from ends of text.
    - .split(" "): Splits a string into a list of words using space as delimiter.
    - datetime.strptime(): Converts text into a Python datetime object so we can
      do math with dates and times (e.g. calculate seconds between events).
    - dict: A dictionary that stores data with custom keys (like a real dictionary
      maps words to definitions).

    Returns:
        dict: A structured dictionary of the log entry if valid.
        None: If the line is empty, corrupted, or does not match expected format.
    """
    # Step 1: Clean trailing and leading spaces and newlines
    clean_line = line.strip()

    # If the line is completely empty, ignore it
    if not clean_line:
        return None

    # Step 2: Split the line into parts by spaces
    # Example: "2026-09-28 10:15:32 FAILED_LOGIN username=admin ip=192.168.1.10"
    # Result:  ['2026-09-28', '10:15:32', 'FAILED_LOGIN', 'username=admin', 'ip=192.168.1.10']
    parts = clean_line.split(" ")

    # Step 3: Input Validation - defensive programming!
    # A valid log line must contain at least 5 parts:
    # index 0: Date (YYYY-MM-DD)
    # index 1: Time (HH:MM:SS)
    # index 2: Event Type (e.g. FAILED_LOGIN or SUCCESS_LOGIN)
    # index 3: Username key-value pair (username=...)
    # index 4: IP Address key-value pair (ip=...)
    if len(parts) < 5:
        return None

    # Step 4: Combine Date and Time into a timestamp string
    date_str = parts[0]
    time_str = parts[1]
    timestamp_str = f"{date_str} {time_str}"

    # Step 5: Convert timestamp string into a Python datetime object
    # This allows us to calculate time differences (e.g. 45 seconds apart)
    try:
        dt_obj = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        # If the date or time format is corrupted (e.g. invalid date), skip it safely
        return None

    # Step 6: Extract the event type
    event_type = parts[2].upper()

    # Step 7: Extract username and IP key-value pairs
    user_part = parts[3]
    ip_part = parts[4]

    # Validate that the parts start with the expected prefixes
    if not user_part.startswith("username=") or not ip_part.startswith("ip="):
        return None

    # Split on '=' to isolate the actual username and IP address
    # Example: "username=admin".split("=") -> ['username', 'admin'] -> index 1 is 'admin'
    username = user_part.split("=")[1].strip()
    ip_address = ip_part.split("=")[1].strip()

    # Make sure neither username nor IP address is blank
    if not username or not ip_address:
        return None

    # Step 8: Package into a clean Python dictionary and return it
    return {
        "timestamp_str": timestamp_str,
        "datetime": dt_obj,
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address,
        "raw_line": clean_line
    }


def read_log_file(file_path):
    """
    Safely opens a log file and processes it line by line.

    Why read line by line?
    In cybersecurity, security logs can be millions of lines long (gigabytes in size!).
    Reading line by line keeps memory usage tiny because we don't load the entire
    gigantic file into RAM all at once.

    Parameters:
        file_path (str): The path to the log file on disk.

    Returns:
        tuple: (events_list, skipped_count)
            events_list: List of parsed valid event dictionaries.
            skipped_count: Number of malformed lines skipped.
    """
    events = []
    skipped_count = 0

    # Defensive file handling: 'with open' guarantees the file is properly closed
    # even if an unexpected error occurs.
    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            parsed_entry = parse_log_entry(line)
            if parsed_entry is not None:
                # Add valid parsed event to our list
                events.append(parsed_entry)
            else:
                # If the line wasn't just blank whitespace, count it as malformed
                if line.strip():
                    skipped_count += 1

    return events, skipped_count


# ==============================================================================
# SECTION 2: AUTHENTICATION ACTIVITY ANALYSIS (Statistics & Aggregation)
# ==============================================================================

def analyze_authentication_activity(events):
    """
    Examines all parsed events to compile high-level security statistics.

    Answers key questions for an analyst:
    - How many total events occurred?
    - How many were successful vs. failed logins?
    - How many unique IPs and usernames were observed?
    - Which IP addresses generated the most failures?
    - Which usernames were targeted most frequently?
    - Which accounts did each IP specifically target?

    Python Concepts used:
    - set(): A set stores only unique values. Duplicates are automatically removed!
      If 'admin' tries to log in 50 times, adding 'admin' to a set still keeps only 1 entry.
    - dict.get(): Safely gets a value from a dictionary, returning a default (like 0)
      if the key doesn't exist yet.

    Returns:
        dict: Summary statistics and frequency counters.
    """
    total_events = len(events)
    successful_logins = 0
    failed_logins = 0

    # Sets to track unique entities
    unique_ips = set()
    unique_users = set()

    # Dictionaries to count frequencies: {key: count}
    failures_by_ip = {}
    failures_by_user = {}

    # Nested dictionary to track which accounts each IP targeted:
    # { "192.168.1.50": {"admin": 12, "root": 7, "test": 3} }
    ip_targeted_accounts = {}

    for event in events:
        ip = event["ip_address"]
        user = event["username"]
        event_type = event["event_type"]

        # Track unique entities
        unique_ips.add(ip)
        unique_users.add(user)

        # Count successful vs failed attempts
        if "SUCCESS" in event_type:
            successful_logins += 1
        elif "FAIL" in event_type:
            failed_logins += 1

            # Increment failure counter for this IP
            failures_by_ip[ip] = failures_by_ip.get(ip, 0) + 1

            # Increment failure counter for this Username
            failures_by_user[user] = failures_by_user.get(user, 0) + 1

            # Track targeted accounts by this IP
            if ip not in ip_targeted_accounts:
                ip_targeted_accounts[ip] = {}
            ip_targeted_accounts[ip][user] = ip_targeted_accounts[ip].get(user, 0) + 1

    # Sort IP addresses by failure count in descending order (highest first)
    # Python concept: sorted() with key=lambda x: x[1] sorts by the dictionary value (count)
    top_failed_ips = sorted(failures_by_ip.items(), key=lambda item: item[1], reverse=True)

    # Sort targeted usernames by failure count in descending order
    top_targeted_users = sorted(failures_by_user.items(), key=lambda item: item[1], reverse=True)

    return {
        "total_events": total_events,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "unique_ips_count": len(unique_ips),
        "unique_users_count": len(unique_users),
        "failures_by_ip": failures_by_ip,
        "top_failed_ips": top_failed_ips,
        "top_targeted_users": top_targeted_users,
        "ip_targeted_accounts": ip_targeted_accounts
    }


# ==============================================================================
# SECTION 3: SUSPICIOUS ACTIVITY DETECTION ENGINE
# ==============================================================================

def detect_brute_force(events, fail_threshold=DEFAULT_BRUTE_FORCE_THRESHOLD, window_seconds=DEFAULT_TIME_WINDOW_SECONDS):
    """
    Detects potential brute-force authentication attacks using a sliding time window.

    CYBERSECURITY CONCEPT: Time-Window Analysis
    Five failed logins spread across 8 hours is usually a human forgetting their password.
    Five failed logins occurring in 30 seconds is almost certainly an automated attack!
    Therefore, checking the TIME WINDOW between events is crucial.

    Algorithm (Sliding Window):
    1. Filter only FAILED_LOGIN events for each individual IP address.
    2. Sort those events chronologically by timestamp.
    3. For each failure, look ahead to see how many more failures occur within
       'window_seconds'.
    4. If the count meets or exceeds 'fail_threshold', flag an alert!
    5. Assign severity:
       - HIGH if >= 10 attempts or targeting sensitive accounts (admin, root).
       - MEDIUM if between 5 and 9 attempts on regular accounts.

    Returns:
        list of dict: Alerts describing detected brute-force bursts.
    """
    alerts = []

    # Step 1: Group failed events by IP address
    failures_per_ip = {}
    for event in events:
        if "FAIL" in event["event_type"]:
            ip = event["ip_address"]
            if ip not in failures_per_ip:
                failures_per_ip[ip] = []
            failures_per_ip[ip].append(event)

    # Step 2: Analyze each IP's failures across time windows
    for ip, ip_failures in failures_per_ip.items():
        # Sort chronologically by datetime object
        ip_failures.sort(key=lambda x: x["datetime"])

        n = len(ip_failures)
        if n < fail_threshold:
            continue

        i = 0
        while i < n:
            start_event = ip_failures[i]
            start_time = start_event["datetime"]

            # Look ahead to find all failures occurring within window_seconds of start_time
            burst = [start_event]
            j = i + 1
            while j < n:
                time_diff = (ip_failures[j]["datetime"] - start_time).total_seconds()
                if time_diff <= window_seconds:
                    burst.append(ip_failures[j])
                    j += 1
                else:
                    break

            # If the number of failures in this window meets the threshold
            if len(burst) >= fail_threshold:
                end_time = burst[-1]["datetime"]
                actual_duration = int((end_time - start_time).total_seconds())

                # Collect usernames targeted during this burst
                targeted_in_burst = {}
                for ev in burst:
                    u = ev["username"]
                    targeted_in_burst[u] = targeted_in_burst.get(u, 0) + 1

                # Primary target is the account with the most attempts in this burst
                primary_target = max(targeted_in_burst.items(), key=lambda x: x[1])[0]

                # Severity logic:
                # - HIGH if 10 or more failures, or if targeting sensitive accounts like admin/root
                # - MEDIUM otherwise
                has_sensitive_target = any(u.lower() in SENSITIVE_ACCOUNTS for u in targeted_in_burst)
                if len(burst) >= 10 or has_sensitive_target:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                duration_display = f"{actual_duration} seconds" if actual_duration > 0 else "under 1 second"

                reason_text = (
                    f"{len(burst)} failed authentication attempts were\n"
                    f"detected from the same source within\n"
                    f"the configured threshold."
                )

                alert = {
                    "alert_type": "Potential Brute Force",
                    "severity": severity,
                    "source_ip": ip,
                    "target_account": primary_target,
                    "all_targeted_accounts": targeted_in_burst,
                    "failed_attempts": len(burst),
                    "time_window": duration_display,
                    "start_time": start_event["timestamp_str"],
                    "end_time": burst[-1]["timestamp_str"],
                    "reason": reason_text
                }
                alerts.append(alert)

                # Move index past this detected burst to avoid duplicate alerts for the same burst
                i = j
            else:
                i += 1

    return alerts


def detect_suspicious_sequences(events, min_failures=DEFAULT_SEQUENCE_FAIL_THRESHOLD, max_gap_seconds=MAX_SEQUENCE_GAP_SECONDS):
    """
    Detects suspicious authentication sequences: multiple failed logins followed
    by a successful login from the same IP address.

    CYBERSECURITY CONCEPT: Compromise / Account Takeover Indicator
    When an IP address fails multiple times and then succeeds:
    - It often means an attacker guessed or cracked the password after multiple attempts.
    - Or an attacker brute-forced several accounts and finally found one that worked.
    - Even if it might be an employee who forgot their password, in security operations
      (SOC) this pattern is treated as HIGH severity until verified!

    TIME-GAP CHECK:
    - If 5 failures occurred 8 hours ago, and a login occurs now, it's normal human
      forgetting.
    - If failures happen in rapid succession right before the success, it's an attack!
    - We enforce max_gap_seconds (default 10 minutes) between events.

    Returns:
        list of dict: Alerts for each detected suspicious sequence.
    """
    alerts = []

    # Group all events (both fails and successes) by IP address
    events_per_ip = {}
    for event in events:
        ip = event["ip_address"]
        if ip not in events_per_ip:
            events_per_ip[ip] = []
        events_per_ip[ip].append(event)

    # Check each IP's events in chronological order
    for ip, ip_events in events_per_ip.items():
        # Sort chronologically
        ip_events.sort(key=lambda x: x["datetime"])

        failed_streak = []

        for event in ip_events:
            event_type = event["event_type"]

            if "FAIL" in event_type:
                # If there's an existing streak, check the time gap since the last failure
                if failed_streak:
                    time_since_last_fail = (event["datetime"] - failed_streak[-1]["datetime"]).total_seconds()
                    # If too much time has elapsed between failures, reset the streak
                    if time_since_last_fail > max_gap_seconds:
                        failed_streak = []

                failed_streak.append(event)

            elif "SUCCESS" in event_type:
                # We encountered a SUCCESS login!
                # Check if this success was preceded by multiple failures in a rapid streak
                if len(failed_streak) >= min_failures:
                    time_since_last_fail = (event["datetime"] - failed_streak[-1]["datetime"]).total_seconds()

                    # Only flag if the success happened within max_gap_seconds of the failures
                    if time_since_last_fail <= max_gap_seconds:
                        # Collect target accounts attempted during the failed streak
                        targeted_accounts = {}
                        for f in failed_streak:
                            u = f["username"]
                            targeted_accounts[u] = targeted_accounts.get(u, 0) + 1

                        successful_account = event["username"]

                        reason_text = (
                            "Multiple failed authentication attempts were followed\n"
                            "by a successful authentication from the same source."
                        )

                        alert = {
                            "alert_type": "Potentially Suspicious Authentication Sequence",
                            "severity": "HIGH",
                            "source_ip": ip,
                            "target_account": successful_account,
                            "all_targeted_accounts": targeted_accounts,
                            "failed_attempts": len(failed_streak),
                            "successful_logins": 1,
                            "success_timestamp": event["timestamp_str"],
                            "reason": reason_text
                        }
                        alerts.append(alert)

                # Reset the failed streak counter after any success
                failed_streak = []

    return alerts


# ==============================================================================
# SECTION 4: FORMATTING & REPORT GENERATION
# ==============================================================================

def format_security_alert(alert):
    """
    Formats a single security alert dictionary into a clean, standardized,
    professional visual box suitable for security analysts.
    """
    lines = []
    lines.append("========================================")
    lines.append("        SECURITY ALERT")
    lines.append("========================================")
    lines.append("")
    lines.append(f"Alert Type: {alert['alert_type']}")
    lines.append(f"Severity: {alert['severity']}")
    lines.append("")
    lines.append(f"Source IP: {alert['source_ip']}")
    lines.append(f"Target Account: {alert['target_account']}")
    lines.append(f"Failed Attempts: {alert['failed_attempts']}")

    # Only include Successful Login line for sequence alerts
    if "successful_logins" in alert:
        lines.append(f"Successful Login: {alert['successful_logins']}")

    # Only include Time Window line for brute force alerts
    if "time_window" in alert:
        lines.append(f"Time Window: {alert['time_window']}")

    lines.append("")
    lines.append("Reason:")
    lines.append(alert["reason"])
    lines.append("")

    return "\n".join(lines)


def generate_full_report(file_path, stats, alerts, brute_alerts, sequence_alerts):
    """
    Constructs the complete Security Log Analysis Report text, including:
    - Executive Summary table with event counts
    - Top Failed-Login Sources
    - Account-Target Analysis Breakdown
    - Suspicious Activity Counters
    - Security Recommendations for Analysts
    - Detailed Individual Formatted Security Alerts

    Returns:
        str: The complete report formatted as text.
    """
    report_lines = []

    # 1. Header & Summary Statistics
    report_lines.append("========================================")
    report_lines.append("       SECURITY LOG ANALYSIS REPORT")
    report_lines.append("========================================")
    report_lines.append("")
    report_lines.append(f"Log File: {os.path.basename(file_path)}")
    report_lines.append("")
    report_lines.append(f"{'Total Events:':<27}{stats['total_events']:>5,}")
    report_lines.append(f"{'Successful Logins:':<27}{stats['successful_logins']:>5,}")
    report_lines.append(f"{'Failed Logins:':<27}{stats['failed_logins']:>5,}")
    report_lines.append(f"{'Unique IP Addresses:':<27}{stats['unique_ips_count']:>5,}")
    report_lines.append(f"{'Unique Users:':<27}{stats['unique_users_count']:>5,}")
    report_lines.append("")

    # 2. Top Failed-Login Sources
    report_lines.append("----------------------------------------")
    report_lines.append("TOP FAILED-LOGIN SOURCES")
    report_lines.append("----------------------------------------")
    report_lines.append("")

    # Filter to display top failed sources (those with significant failures)
    significant_failed_ips = [item for item in stats["top_failed_ips"] if item[1] >= 5]
    if not significant_failed_ips:
        significant_failed_ips = stats["top_failed_ips"][:3]

    if significant_failed_ips:
        for ip, count in significant_failed_ips[:5]:
            report_lines.append(f"{ip:<20}{count} failures")
    else:
        report_lines.append("No failed logins detected.")
    report_lines.append("")

    # 3. Account-Target Analysis
    # Shows which specific usernames each suspicious IP attempted
    report_lines.append("----------------------------------------")
    report_lines.append("ACCOUNT-TARGET ANALYSIS")
    report_lines.append("----------------------------------------")
    report_lines.append("")

    displayed_account_targets = False
    # Focus on the top 3 failed IPs with significant activity
    top_ips_to_show = [item[0] for item in stats["top_failed_ips"][:3] if item[1] >= 5]
    if not top_ips_to_show and stats["top_failed_ips"]:
        top_ips_to_show = [stats["top_failed_ips"][0][0]]

    for ip in top_ips_to_show:
        targets = stats["ip_targeted_accounts"].get(ip, {})
        if targets:
            displayed_account_targets = True
            report_lines.append(f"Suspicious IP: {ip}\n")
            report_lines.append("Targeted Accounts:")
            # Sort accounts by attempt count descending
            sorted_targets = sorted(targets.items(), key=lambda x: x[1], reverse=True)
            # Display top 3 targeted accounts
            for acc, count in sorted_targets[:3]:
                report_lines.append(f"    {acc + ':':<8} {count} attempts")
            report_lines.append("")

    if not displayed_account_targets:
        report_lines.append("No suspicious account targeting patterns observed.\n")

    # 4. Suspicious Activity Counters
    # High-severity count represents high-severity brute-force attacks detected
    high_severity_count = sum(1 for a in brute_alerts if a.get("severity") == "HIGH")
    if high_severity_count == 0 and alerts:
        high_severity_count = sum(1 for a in alerts if a.get("severity") == "HIGH")

    report_lines.append("----------------------------------------")
    report_lines.append("SUSPICIOUS ACTIVITY")
    report_lines.append("----------------------------------------")
    report_lines.append("")
    report_lines.append(f"{'Potential Brute Force:':<29}{len(brute_alerts):>2}")
    report_lines.append(f"{'Suspicious Login Sequences:':<29}{len(sequence_alerts):>2}")
    report_lines.append(f"{'High-Severity Alerts:':<29}{high_severity_count:>2}")
    report_lines.append("")

    # 5. Security Recommendations
    report_lines.append("----------------------------------------")
    report_lines.append("RECOMMENDATION")
    report_lines.append("----------------------------------------")
    report_lines.append("")
    if high_severity_count > 0:
        report_lines.append("Review the high-severity alerts and")
        report_lines.append("investigate the associated IP addresses")
        report_lines.append("and user accounts.")
    elif alerts:
        report_lines.append("Monitor the flagged IP addresses for continued")
        report_lines.append("authentication anomalies.")
    else:
        report_lines.append("No immediate action required. Routine baseline activity.")
    report_lines.append("")

    # 6. Detailed Security Alerts Section
    if alerts:
        report_lines.append("----------------------------------------")
        report_lines.append("DETAILED SECURITY ALERTS")
        report_lines.append("----------------------------------------")
        report_lines.append("")
        for alert in alerts:
            report_lines.append(format_security_alert(alert))

    return "\n".join(report_lines)


# ==============================================================================
# SECTION 5: COMMAND LINE INTERFACE & MAIN EXECUTION
# ==============================================================================

def main():
    """
    Main entry point for the Security Log Analyzer.
    Parses command-line arguments, drives the analysis workflow,
    prints the results to the terminal, and saves a report file.
    """
    # Set up argument parsing with helpful descriptions
    parser = argparse.ArgumentParser(
        description="Python Security Log Analyzer - Ingest, analyze, and detect threats in authentication logs."
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        default="security.log",
        help="Path to the log file to analyze (default: security.log)"
    )
    parser.add_argument(
        "-s", "--save",
        dest="output_file",
        default="analysis_report.txt",
        help="File path to save the analysis report (default: analysis_report.txt)"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=DEFAULT_BRUTE_FORCE_THRESHOLD,
        help=f"Failed login threshold for brute force detection (default: {DEFAULT_BRUTE_FORCE_THRESHOLD})"
    )
    parser.add_argument(
        "-w", "--window",
        type=int,
        default=DEFAULT_TIME_WINDOW_SECONDS,
        help=f"Time window in seconds for brute force detection (default: {DEFAULT_TIME_WINDOW_SECONDS}s)"
    )

    args = parser.parse_args()
    log_file_path = args.log_file
    output_file_path = args.output_file

    print("========================================")
    print("      PYTHON SECURITY LOG ANALYZER      ")
    print("========================================\n")
    print(f"[*] Target Log File: {log_file_path}")
    print(f"[*] Brute Force Rule: >= {args.threshold} failures within {args.window} seconds")
    print(f"[*] Sequence Rule:   >= {DEFAULT_SEQUENCE_FAIL_THRESHOLD} failures followed by SUCCESS\n")

    # Step 1: Ingestion & Parsing with robust defensive error handling
    if not os.path.exists(log_file_path):
        print(f"[!] Error: The log file '{log_file_path}' was not found.")
        print("    Please verify the file path and try again.")
        sys.exit(1)

    try:
        events, skipped_count = read_log_file(log_file_path)
    except PermissionError:
        print(f"[!] Error: Permission denied when attempting to read '{log_file_path}'.")
        sys.exit(1)
    except Exception as err:
        print(f"[!] Unexpected error reading '{log_file_path}': {err}")
        sys.exit(1)

    print(f"[*] Ingestion complete: {len(events)} events parsed successfully.")
    if skipped_count > 0:
        print(f"[*] [Defensive Parser] Skipped {skipped_count} malformed or unparseable line(s) safely.\n")
    else:
        print("")

    if not events:
        print("[!] No valid security events found to analyze. Exiting.")
        sys.exit(0)

    # Step 2: Authentication Activity Analysis
    stats = analyze_authentication_activity(events)

    # Step 3: Suspicious Activity Detection
    brute_alerts = detect_brute_force(events, fail_threshold=args.threshold, window_seconds=args.window)
    sequence_alerts = detect_suspicious_sequences(events, min_failures=DEFAULT_SEQUENCE_FAIL_THRESHOLD)
    all_alerts = brute_alerts + sequence_alerts

    # Step 4: Generate Full Security Report
    full_report_text = generate_full_report(log_file_path, stats, all_alerts, brute_alerts, sequence_alerts)

    # Display the report on the console
    print(full_report_text)

    # Step 5: Save Analysis Results to Disk
    try:
        with open(output_file_path, "w", encoding="utf-8") as out_file:
            out_file.write(full_report_text)
        print("----------------------------------------")
        print(f"[+] Success: Security report saved to '{output_file_path}'")
        print("----------------------------------------\n")
    except Exception as err:
        print(f"[!] Warning: Could not save report to '{output_file_path}': {err}\n")


if __name__ == "__main__":
    main()

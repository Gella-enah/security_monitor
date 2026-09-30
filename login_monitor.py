import csv
import os
from datetime import datetime, timedelta
 
# ---- Configuration ----
CSV_FILE = "login_attempts.csv"
FAIL_THRESHOLD = 5          # how many failures trigger an alert
TIME_WINDOW_MINUTES = 5     # within this many minutes
 
 
def ensure_csv_exists():
    """Create the CSV file with a header if it doesn't exist yet."""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "username", "ip_address", "status"])
 
 
def record_attempt(username, ip_address, success):
    """Append one login attempt to the CSV file."""
    ensure_csv_exists()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "SUCCESS" if success else "FAILED"
 
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, username, ip_address, status])
 
    print("Recorded: " + timestamp + " | " + username + " | " + ip_address + " | " + status)
 
 
def load_attempts():
    """Read all rows from the CSV file as a list of dictionaries."""
    ensure_csv_exists()
    attempts = []
    with open(CSV_FILE, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            attempts.append(row)
    return attempts
 
 
def parse_timestamp(ts):
    """Convert a timestamp string to a datetime object."""
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
 
 
def count_recent_failures(ip_address, minutes=TIME_WINDOW_MINUTES):
    """
    Count how many FAILED attempts came from this IP
    within the last N minutes.
    """
    attempts = load_attempts()
    cutoff = datetime.now() - timedelta(minutes=minutes)
 
    count = 0
    for a in attempts:
        if a["ip_address"] != ip_address:
            continue
        if a["status"] != "FAILED":
            continue
        try:
            ts = parse_timestamp(a["timestamp"])
        except ValueError:
            continue
        if ts >= cutoff:
            count += 1
    return count
 
 
def check_for_brute_force(ip_address):
    """Print an alert if the IP has too many recent failures."""
    count = count_recent_failures(ip_address)
    if count >= FAIL_THRESHOLD:
        print("")
        print("!! ALERT: " + str(count) + " failed login attempts detected from " + ip_address)
        print("!! Possible brute-force attack in progress.")
        print("")
    else:
        print("Recent failed attempts from " + ip_address + ": " + str(count))
 
 
def show_recent_attempts(limit=10):
    """Display the most recent login attempts."""
    attempts = load_attempts()
    if not attempts:
        print("No login attempts recorded yet.")
        return
 
    recent = attempts[-limit:]
    print("")
    print("Last " + str(len(recent)) + " login attempts:")
    print("-" * 70)
    print("TIMESTAMP            USERNAME     IP ADDRESS        STATUS")
    print("-" * 70)
    for a in recent:
        print(
            a["timestamp"].ljust(20) +
            a["username"].ljust(13) +
            a["ip_address"].ljust(18) +
            a["status"]
        )
    print("-" * 70)
 
def count_recent_failures_by_username(username, minutes=TIME_WINDOW_MINUTES):

    """Count recent FAILED attempts for a specific username."""

    attempts = load_attempts()

    cutoff = datetime.now() - timedelta(minutes=minutes)

    count = 0

    for a in attempts:

        if a["username"] != username:

            continue

        if a["status"] != "FAILED":

            continue

        try:

            ts = parse_timestamp(a["timestamp"])

        except ValueError:

            continue

        if ts >= cutoff:

            count += 1

    return count

 

 

def get_suspicious_ips(minutes=TIME_WINDOW_MINUTES, min_failures=FAIL_THRESHOLD):

    """Return a list of (ip, failure_count) sorted most-suspicious first."""

    attempts = load_attempts()

    cutoff = datetime.now() - timedelta(minutes=minutes)

    counts = {}

 

    for a in attempts:

        if a["status"] != "FAILED":

            continue

        try:

            ts = parse_timestamp(a["timestamp"])

        except ValueError:

            continue

        if ts < cutoff:

            continue

        ip = a["ip_address"]

        counts[ip] = counts.get(ip, 0) + 1

 

    suspects = [(ip, c) for ip, c in counts.items() if c >= min_failures]

    suspects.sort(key=lambda x: x[1], reverse=True)

    return suspects

 

 

def compute_risk_score(ip_address, minutes=TIME_WINDOW_MINUTES):

    """Give an IP a risk score from 0 to 10."""

    attempts = load_attempts()

    cutoff = datetime.now() - timedelta(minutes=minutes)

    failures = 0

    usernames_tried = set()

 

    for a in attempts:

        if a["ip_address"] != ip_address:

            continue

        if a["status"] != "FAILED":

            continue

        try:

            ts = parse_timestamp(a["timestamp"])

        except ValueError:

            continue

        if ts < cutoff:

            continue

        failures += 1

        usernames_tried.add(a["username"])

 

    score = failures

    if failures >= FAIL_THRESHOLD:

        score += 2

    if len(usernames_tried) > 1:

        score += 2

 

    return min(score, 10)

 

 

def security_summary():

    """Print a quick overview of current suspicious activity."""

    print("")

    print("=========== SECURITY SUMMARY ===========")

 

    suspects = get_suspicious_ips()

    if not suspects:

        print("No suspicious activity detected.")

        print("========================================")

        return

 

    print("Suspicious IPs (in last " + str(TIME_WINDOW_MINUTES) + " min):")

    print("-" * 40)

    for ip, count in suspects:

        score = compute_risk_score(ip)

        print(ip + " - " + str(count) + " failures - risk score: " + str(score) + "/10")

    print("========================================")


# ---- Manual test ----
"""
this has been commented out so that the script can be imported without running the test code.

if __name__ == "__main__":
    print("Login Monitor - Test Mode")
    print("")
 
    # Simulate 6 failed attempts from the same IP (to trigger the alert)
    for i in range(6):
        record_attempt("admin", "192.168.1.15", False)
 
    # Simulate one successful login
    record_attempt("savz", "192.168.1.20", True)
 
    # Show what's stored
    show_recent_attempts()
 
    # Check for brute force
    check_for_brute_force("192.168.1.15")
    """

if __name__ == "__main__":

    print("Login Monitor - Test Mode")

    print("")

 

    # Simulated brute-force from one IP (same user, many tries)

    for i in range(6):

        record_attempt("admin", "192.168.1.15", False)

 

    # Simulated username-spray from a second IP (many users)

    for user in ["root", "test", "oracle", "postgres"]:

        record_attempt(user, "10.0.0.99", False)

 

    # One legit login

    record_attempt("savz", "192.168.1.20", True)

 

    show_recent_attempts()

    check_for_brute_force("192.168.1.15")

    security_summary()
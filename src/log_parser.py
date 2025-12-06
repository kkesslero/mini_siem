import re
from datetime import datetime

LOG_PATH = "data/sample_logs/auth.log"

MONTH_MAP = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
    'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
    'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

CURRENT_YEAR = datetime.now().year

# ------------ Extraction regex (must be defined before use) ------------
IP_RE = re.compile(r'(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)')
USER_RE = re.compile(r'for (?:(?:invalid user )|)(?P<user>[\w.-]+)')

# ------------ Helper function to extract IP + user + event type --------
def extract_fields(msg):
    ip_match = IP_RE.search(msg)
    user_match = USER_RE.search(msg)

    ip = ip_match.group('ip') if ip_match else None
    user = user_match.group('user') if user_match else None

    event_type = None
    if "Failed password" in msg:
        event_type = "failed_login"
    elif "Accepted password" in msg:
        event_type = "successful_login"
    elif "sudo" in msg:
        event_type = "privilege_escalation"

    return {"ip": ip, "user": user, "event_type": event_type}

# ------------ Main log regex -------------------------------------------
LOG_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>\S+)\[\d+\]:\s+'
    r'(?P<message>.*)'
)

# ------------ Main parse function --------------------------------------
def parse_auth_log():
    events = []

    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            match = LOG_PATTERN.match(line)
            if not match:
                continue

            data = match.groupdict()

            # Build timestamp
            timestamp_str = (
                f"{CURRENT_YEAR}-"
                f"{MONTH_MAP[data['month']]:02}-"
                f"{int(data['day']):02} "
                f"{data['time']}"
            )
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            event = {
                'timestamp': timestamp,
                'host': data['host'],
                'process': data['process'],
                'raw_message': data['message']
            }

            # Add extracted fields (ip, user, event_type)
            fields = extract_fields(data['message'])
            event.update(fields)

            events.append(event)

    return events


# ------------ Run the parser -------------------------------------------
if __name__ == "__main__":
    parsed_events = parse_auth_log()

    for event in parsed_events:
        print(event)
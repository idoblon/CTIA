import re
import validators

# Regex for IPv4
IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

def is_ip(value):
    return re.fullmatch(IP_REGEX, value) is not None

def is_domain(value):
    if "." not in value:
        return False
    return validators.domain(value)

def is_url(value):
    return validators.url(value)

def normalize_feed_line(line):
    """
    Takes a single line from feed and returns structured IOC if valid.
    """
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    if is_ip(line):
        return {"type": "ip", "value": line}

    if is_url(line):
        return {"type": "url", "value": line}

    if is_domain(line):
        return {"type": "domain", "value": line}

    return None

def normalize_feed(file_path):
    normalized = []

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            result = normalize_feed_line(line)
            if result:
                normalized.append(result)

    return normalized

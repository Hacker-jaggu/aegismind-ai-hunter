from urllib.parse import urlparse, urljoin

def normalize_host(host):
    return (host or "").rstrip(".").lower()

def in_scope(url, allowed_hosts):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and normalize_host(parsed.hostname) in {
            normalize_host(h) for h in allowed_hosts
        }
    except Exception:
        return False

def safe_join(base, location, allowed_hosts):
    candidate = urljoin(base, location)
    return candidate if in_scope(candidate, allowed_hosts) else None

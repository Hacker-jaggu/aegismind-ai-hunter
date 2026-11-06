"""Small, bounded same-host HTML link collector. No forms or scripts are executed."""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse

SKIP_PATH_PARTS = {"logout", "log-out", "signout", "sign-out", "delete", "remove", "unsubscribe", "checkout", "purchase", "payment", "transfer"}

class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() not in {"a", "area"}:
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.hrefs.append(value.strip())

def extract_links(base_url, html_text, allowed_hosts, limit=100):
    parser = _Links()
    try:
        parser.feed(html_text)
    except Exception:
        return []
    base = urlparse(base_url)
    allowed = {h.lower().rstrip(".") for h in allowed_hosts}
    found, seen = [], set()
    for href in parser.hrefs:
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        candidate = urlparse(urljoin(base_url, href))
        if candidate.scheme not in {"http", "https"} or (candidate.hostname or "").lower().rstrip(".") not in allowed:
            continue
        if candidate.query or any(part.lower() in SKIP_PATH_PARTS for part in candidate.path.split("/")):
            continue
        clean = urlunparse((candidate.scheme, candidate.netloc, candidate.path or "/", "", "", ""))
        if clean not in seen and clean != base_url:
            seen.add(clean)
            found.append(clean)
        if len(found) >= limit:
            break
    return found

import math
import os, time
from datetime import datetime, timezone
import requests
from requests.exceptions import RequestException
from .scope import in_scope
from .crawler import extract_links
from .checks import inspect_response, inspect_options
from .ai_review import review_findings

class Scanner:
    def __init__(self, allowed_hosts, max_urls=None, delay=None, max_body_bytes=None):
        self.allowed_hosts = {h.lower().rstrip(".") for h in allowed_hosts}

        raw_timeout = float(os.getenv("REQUEST_TIMEOUT", "10"))
        if not math.isfinite(raw_timeout) or raw_timeout <= 0:
            raise ValueError("REQUEST_TIMEOUT must be a finite positive number")
        self.timeout = min(30.0, max(1.0, raw_timeout))

        raw_delay = float(delay if delay is not None else os.getenv("REQUEST_DELAY", "1.0"))
        if not math.isfinite(raw_delay) or raw_delay < 0:
            raise ValueError("REQUEST_DELAY/--delay must be a finite non-negative number")
        self.delay = min(10.0, max(0.5, raw_delay))

        self.max_urls = min(100, max(1, int(max_urls if max_urls is not None else os.getenv("MAX_URLS", "30"))))
        self.max_body_bytes = min(1_000_000, max(16_384, int(max_body_bytes or os.getenv("MAX_BODY_BYTES", "262144"))))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "AegisMind-AI-Hunter/0.2 (+authorized security assessment)"})

    def request(self, method, url):
        if method not in {"GET", "OPTIONS"}:
            raise ValueError("Only GET and OPTIONS observation methods are enabled")
        if not in_scope(url, self.allowed_hosts):
            raise ValueError("Out-of-scope URL blocked")
        time.sleep(self.delay)
        return self.session.request(method, url, timeout=self.timeout, allow_redirects=False, verify=True, stream=True)

    def _read_bounded_html(self, response):
        ctype = response.headers.get("Content-Type", "").lower()
        if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
            return ""
        chunks, size = [], 0
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = self.max_body_bytes - size
            chunks.append(chunk[:remaining])
            size += min(len(chunk), remaining)
            if size >= self.max_body_bytes:
                break
        return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")

    def run(self, start_url):
        if not in_scope(start_url, self.allowed_hosts):
            raise ValueError("Starting URL host must exactly match --allow-host")
        queue, seen, findings, observations = [start_url], set(), [], []
        while queue and len(seen) < self.max_urls:
            url = queue.pop(0)
            if url in seen or not in_scope(url, self.allowed_hosts):
                continue
            seen.add(url)
            try:
                response = self.request("GET", url)
                observation = {"url": url, "method": "GET", "status": response.status_code,
                               "content_type": response.headers.get("Content-Type", ""),
                               "redirect": response.headers.get("Location"),
                               "server": response.headers.get("Server", "")[:120]}
                observations.append(observation)
                findings.extend(inspect_response(url, response))
                location = response.headers.get("Location")
                if location:
                    observation["redirect_in_scope"] = bool(in_scope(requests.compat.urljoin(url, location), self.allowed_hosts))
                html_text = self._read_bounded_html(response)
                response.close()
                for candidate in extract_links(url, html_text, self.allowed_hosts, limit=self.max_urls):
                    if candidate not in seen and candidate not in queue and len(seen) + len(queue) < self.max_urls:
                        queue.append(candidate)
                try:
                    opt = self.request("OPTIONS", url)
                    findings.extend(inspect_options(url, opt))
                    observations.append({"url": url, "method": "OPTIONS", "status": opt.status_code,
                                         "allow": opt.headers.get("Allow", "")})
                    opt.close()
                except (RequestException, ValueError) as e:
                    observations.append({"url": url, "method": "OPTIONS", "error": type(e).__name__})
            except (RequestException, ValueError) as e:
                observations.append({"url": url, "error": type(e).__name__})
        unique = {(f.id, f.url): f for f in findings}
        findings = [f.to_dict() for f in unique.values()]
        ai = review_findings(findings)
        return {"tool": "AegisMind AI Hunter", "version": "0.2.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scope": {"allowed_hosts": sorted(self.allowed_hosts), "start_url": start_url,
                          "max_pages": self.max_urls, "visited_pages": len(seen)},
                "limitations": ["Bounded, unauthenticated passive HTTP assessment; GET/OPTIONS only",
                                "HTML links are collected without executing scripts or submitting forms",
                                "Query-string URLs and action-like paths are excluded from crawling",
                                "No authenticated access-control testing, injection payloads, SSRF probes, or exploit confirmation",
                                "AI review is advisory and cannot confirm vulnerabilities"],
                "observations": observations, "findings": findings, "ai_review": ai}

import os, time
from datetime import datetime, timezone
import requests
from requests.exceptions import RequestException
from .scope import in_scope, safe_join
from .checks import inspect_response, inspect_options
from .ai_review import review_findings

class Scanner:
    def __init__(self, allowed_hosts):
        self.allowed_hosts = allowed_hosts
        self.timeout = float(os.getenv("REQUEST_TIMEOUT", "10"))
        self.delay = max(0.5, float(os.getenv("REQUEST_DELAY", "1.0")))
        self.max_urls = min(100, max(1, int(os.getenv("MAX_URLS", "30"))))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent":"AegisMind-AI-Hunter/0.1 (+authorized security assessment)"})

    def request(self, method, url):
        if not in_scope(url, self.allowed_hosts):
            raise ValueError("Out-of-scope URL blocked")
        time.sleep(self.delay)
        return self.session.request(method, url, timeout=self.timeout, allow_redirects=False, verify=True, stream=True)

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
                observations.append({"url":url,"method":"GET","status":response.status_code,"content_type":response.headers.get("Content-Type",""),"redirect":response.headers.get("Location")})
                findings.extend(inspect_response(url, response))
                location = response.headers.get("Location")
                if location:
                    next_url = safe_join(url, location, self.allowed_hosts)
                    if next_url and next_url not in seen:
                        queue.append(next_url)
                response.close()
                try:
                    opt = self.request("OPTIONS", url)
                    findings.extend(inspect_options(url, opt))
                    observations.append({"url":url,"method":"OPTIONS","status":opt.status_code})
                    opt.close()
                except RequestException as e:
                    observations.append({"url":url,"method":"OPTIONS","error":type(e).__name__})
            except (RequestException, ValueError) as e:
                observations.append({"url":url,"error":type(e).__name__})
        unique = {(f.id, f.url):f for f in findings}
        items = [f.to_dict() for f in unique.values()]
        return {"tool":"AegisMind AI Hunter","version":"0.1.0","generated_at":datetime.now(timezone.utc).isoformat(),
                "scope":{"allowed_hosts":sorted(self.allowed_hosts),"start_url":start_url},
                "limitations":["Conservative unauthenticated HTTP checks only","No authenticated access-control testing","No injection or SSRF payload testing","AI review is advisory and cannot confirm vulnerabilities"],
                "observations":observations,"findings":items,"ai_review":review_findings(items)}

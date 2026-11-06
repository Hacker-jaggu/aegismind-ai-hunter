from http.cookies import SimpleCookie
from .models import Finding
SECURITY_HEADERS={"content-security-policy":("Content-Security-Policy missing","A05:2021 Security Misconfiguration","Define a restrictive Content-Security-Policy."),"x-content-type-options":("X-Content-Type-Options missing","A05:2021 Security Misconfiguration","Set X-Content-Type-Options: nosniff."),"referrer-policy":("Referrer-Policy missing","A05:2021 Security Misconfiguration","Set a privacy-preserving Referrer-Policy."),"permissions-policy":("Permissions-Policy missing","A05:2021 Security Misconfiguration","Disable browser features the application does not need.")}
def _set_cookie_headers(response):
 raw=getattr(getattr(response,"raw",None),"headers",None)
 if raw is not None and hasattr(raw,"getlist"):
  values=raw.getlist("Set-Cookie")
  if values:return values
 value=response.headers.get("Set-Cookie")
 return [value] if value else []
def inspect_response(url,response):
 findings=[]; headers={k.lower():v for k,v in response.headers.items()}; layers=["L1: live HTTP response observed","L2: deterministic header-presence comparison"]
 for name,(title,category,fix) in SECURITY_HEADERS.items():
  if name not in headers:
   findings.append(Finding(id="HEADER-"+name.upper().replace("-",""),title=title,category=category,severity="LOW",status="CONFIRMED",confidence="HIGH",url=url,evidence={"missing_header":name,"http_status":response.status_code},verification_layers=layers.copy(),why_it_matters=f"The response did not include {name}; this removes a browser-side defense or policy.",impact_limitations="Header absence alone does not prove an exploitable vulnerability or data exposure.",remediation=fix,references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]))
 if url.lower().startswith("https://") and "strict-transport-security" not in headers:
  findings.append(Finding(id="HEADER-HSTS",title="HSTS header missing",category="A02:2021 Cryptographic Failures",severity="LOW",status="CONFIRMED",confidence="HIGH",url=url,evidence={"missing_header":"strict-transport-security"},verification_layers=["L1: HTTPS response observed","L2: HSTS header absent"],why_it_matters="The HTTPS response did not advertise HSTS.",impact_limitations="This does not prove downgrade is possible; topology and preload status matter.",remediation="After confirming all subdomains support HTTPS, deploy an appropriate HSTS policy.",references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"]))
 for index,raw_cookie in enumerate(_set_cookie_headers(response),1):
  parsed=SimpleCookie()
  try:parsed.load(raw_cookie)
  except Exception:continue
  for name,morsel in parsed.items():
   gaps=[]
   if url.lower().startswith("https://") and not morsel["secure"]:gaps.append("Secure")
   if not morsel["httponly"]:gaps.append("HttpOnly")
   if not morsel["samesite"]:gaps.append("SameSite")
   if gaps:findings.append(Finding(id=f"COOKIE-{index}-{name[:24]}",title="Cookie security attributes need review",category="A07:2021 Identification and Authentication Failures",severity="LOW",status="NEEDS_REVIEW",confidence="MEDIUM",url=url,evidence={"cookie_name":name,"missing_attributes":gaps,"cookie_value_saved":False},verification_layers=["L1: Set-Cookie observed","L2: cookie attributes parsed","L3: HTTPS context considered"],why_it_matters="This cookie is missing one or more recommended security attributes.",impact_limitations="Correct attributes depend on cookie purpose; HttpOnly is not suitable for every JavaScript-readable cookie.",remediation="Review purpose; set Secure on HTTPS cookies, HttpOnly when script access is unnecessary, and an appropriate SameSite value.",references=["https://owasp.org/www-project-web-security-testing-guide/"]))
 csp=headers.get("content-security-policy","")
 if csp:
  directives={}
  for item in csp.split(";"):
   bits=item.strip().split()
   if bits:directives[bits[0].lower()]=[x.lower() for x in bits[1:]]
  weak=[]
  for directive in ("default-src","script-src","object-src","base-uri","frame-ancestors"):
   values=directives.get(directive,[])
   if "*" in values or "'unsafe-eval'" in values or "'unsafe-inline'" in values:weak.append({"directive":directive,"values":values})
  missing=[x for x in ("object-src","base-uri") if x not in directives]
  if missing:weak.append({"directive":"recommended_directive_missing","values":missing})
  if weak:findings.append(Finding(id="CSP-WEAK-DIRECTIVES",title="CSP contains directives that warrant review",category="A05:2021 Security Misconfiguration",severity="INFO",status="NEEDS_REVIEW",confidence="MEDIUM",url=url,evidence={"csp_review_items":weak},verification_layers=["L1: CSP header observed","L2: directive tokens parsed","L3: conservative policy heuristic applied"],why_it_matters="Some CSP directives are broad or recommended hardening directives are absent.",impact_limitations="This heuristic does not prove XSS or a CSP bypass.",remediation="Review compatibility; prefer nonce/hash-based scripts and explicit source lists.",references=["https://developer.mozilla.org/docs/Web/HTTP/CSP"]))
 acao=headers.get("access-control-allow-origin",""); acc=headers.get("access-control-allow-credentials","").lower()
 if acao=="*" and acc=="true":findings.append(Finding(id="CORS-WILDCARD-CREDENTIALS",title="CORS wildcard origin combined with credentials header",category="A05:2021 Security Misconfiguration",severity="INFO",status="NEEDS_REVIEW",confidence="MEDIUM",url=url,evidence={"access_control_allow_origin":acao,"access_control_allow_credentials":acc},verification_layers=["L1: CORS response headers observed","L2: wildcard/credentials combination detected"],why_it_matters="The response advertises wildcard origin with credentials, an inconsistent configuration.",impact_limitations="Browsers reject credentialed CORS access when ACAO is '*'; this is not proof of data theft.",remediation="Use an explicit allowlist of trusted origins and validate Origin server-side.",references=["https://developer.mozilla.org/docs/Web/HTTP/CORS"]))
 return findings
def inspect_options(url,response):
 methods=response.headers.get("Allow",""); risky=[m.strip().upper() for m in methods.split(",") if m.strip().upper() in {"TRACE","PUT","DELETE","CONNECT"}]
 if not risky:return []
 return [Finding(id="HTTP-METHODS",title="Potentially sensitive HTTP methods advertised",category="A05:2021 Security Misconfiguration",severity="INFO",status="NEEDS_REVIEW",confidence="LOW",url=url,evidence={"advertised_methods":methods,"review_methods":risky},verification_layers=["L1: OPTIONS response observed","L2: method names compared against review list"],why_it_matters="The server advertises methods that should be reviewed against application requirements.",impact_limitations="An advertised method does not prove it is enabled or exploitable.",remediation="Disable unneeded methods and enforce authorization for every method and route.",references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"])]

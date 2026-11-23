import base64
import hashlib
import ipaddress
import os
import re
import uuid
from pathlib import Path
from typing import Optional, Literal

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()
app = FastAPI(title="Threat Intelligence Hub API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)
UPLOAD_DIR = Path("quarantine")
UPLOAD_DIR.mkdir(exist_ok=True)
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
TIMEOUT = 15.0

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "").strip()
BAZAAR_KEY = os.getenv("MALWAREBAZAAR_AUTH_KEY", "").strip()
OTX_KEY = os.getenv("OTX_API_KEY", "").strip()
NVD_KEY = os.getenv("NVD_API_KEY", "").strip()
URLHAUS_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()

class IPRequest(BaseModel): ip: str
class DomainRequest(BaseModel): domain: str
class URLRequest(BaseModel): url: str
class HashRequest(BaseModel): value: str
class CVERequest(BaseModel): cve_id: str
class PhishingRequest(BaseModel):
    mode: Literal["domain", "email"]
    value: str
    email_header: Optional[str] = None
class SearchRequest(BaseModel):
    query: str = ""
    category: str = "all"
    timeframe: str = "7d"


def get_json(url, *, headers=None, params=None, data=None):
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
            r = client.get(url, headers=headers, params=params) if data is None else client.post(url, headers=headers, data=data)
        if r.status_code == 404:
            return None, "No matching record found"
        if r.status_code == 429:
            return None, "Provider rate limit reached"
        r.raise_for_status()
        return r.json(), None
    except httpx.TimeoutException:
        return None, "Provider request timed out"
    except httpx.HTTPStatusError as e:
        return None, f"Provider returned HTTP {e.response.status_code}"
    except Exception as e:
        return None, f"Provider unavailable: {type(e).__name__}"


def result(module, submitted, sources, details=None):
    usable = [s for s in sources if s.get("status") == "success"]
    configured = [s for s in sources if s.get("status") != "not_configured"]
    verdict = "Unknown"
    risk = None
    for s in usable:
        d = s.get("details", {})
        if d.get("malicious", False) or d.get("abuse_confidence_score", 0) >= 50:
            verdict, risk = "Malicious / High risk", max(risk or 0, d.get("abuse_confidence_score", 0), d.get("malicious_count", 0))
            break
        if d.get("suspicious_count", 0) > 0:
            verdict, risk = "Suspicious", max(risk or 0, d.get("suspicious_count", 0))
    if not usable:
        status = "NOT CONFIGURED" if not configured else "UNAVAILABLE"
        message = "No provider returned data. Configure API keys in backend/.env or try again later."
    elif len(usable) < len(sources):
        status, message = "PARTIAL", "Some providers returned data; others are not configured or unavailable."
    else:
        status, message = "LIVE", "Live provider data retrieved. A clean result means no match was returned by these sources, not a guarantee of safety."
    return {"module": module, "submitted": submitted, "status": status, "verdict": verdict,
            "risk_score": risk, "message": message, "details": details or {}, "sources": sources}


def not_configured(name, note="API key not configured"):
    return {"name": name, "status": "not_configured", "summary": note, "details": {}}


def vt_lookup(kind, value):
    if not VT_KEY: return not_configured("VirusTotal")
    path_value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") if kind == "urls" else value
    data, err = get_json(f"https://www.virustotal.com/api/v3/{kind}/{path_value}", headers={"x-apikey": VT_KEY})
    if err: return {"name": "VirusTotal", "status": "error", "summary": err, "details": {}}
    a = data.get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    return {"name": "VirusTotal", "status": "success", "summary": f"{malicious} malicious, {suspicious} suspicious detections across reporting engines",
            "details": {"malicious": malicious > 0, "malicious_count": malicious, "suspicious_count": suspicious,
                        "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0),
                        "reputation": a.get("reputation"), "last_analysis_date": a.get("last_analysis_date")}}


def abuse_lookup(ip):
    if not ABUSE_KEY: return not_configured("AbuseIPDB")
    data, err = get_json("https://api.abuseipdb.com/api/v2/check", headers={"Key": ABUSE_KEY, "Accept": "application/json"}, params={"ipAddress": ip, "maxAgeInDays": 90})
    if err: return {"name": "AbuseIPDB", "status": "error", "summary": err, "details": {}}
    d = data.get("data", {})
    score = int(d.get("abuseConfidenceScore", 0) or 0)
    return {"name": "AbuseIPDB", "status": "success", "summary": f"Abuse confidence {score}% · {d.get('totalReports', 0)} reports in last 90 days",
            "details": {"abuse_confidence_score": score, "total_reports": d.get("totalReports"), "country_code": d.get("countryCode"), "isp": d.get("isp"), "domain": d.get("domain"), "usage_type": d.get("usageType"), "last_reported_at": d.get("lastReportedAt")}}


def otx_lookup(section, indicator):
    if not OTX_KEY: return not_configured("AlienVault OTX")
    data, err = get_json(f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general", headers={"X-OTX-API-KEY": OTX_KEY})
    if err: return {"name": "AlienVault OTX", "status": "error", "summary": err, "details": {}}
    pulses = data.get("pulse_info", {}).get("count", 0)
    return {"name": "AlienVault OTX", "status": "success", "summary": f"Referenced in {pulses} threat-intelligence pulse(s)", "details": {"pulse_count": pulses, "reputation": data.get("reputation")}}


def rdap_lookup(domain):
    data, err = get_json(f"https://rdap.org/domain/{domain}")
    if err: return {"name": "Domain RDAP", "status": "error", "summary": err, "details": {}}
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    nameservers = [n.get("ldhName") for n in data.get("nameservers", []) if n.get("ldhName")]
    registrar = next((v.get("name") for ent in data.get("entities", []) if "registrar" in ent.get("roles", []) for v in ent.get("vcardArray", [None, []])[1] if v and v[0] == "fn"), None)
    return {"name": "Domain RDAP", "status": "success", "summary": "Domain registration data retrieved via RDAP",
            "details": {"registrar": registrar, "created": events.get("registration"), "updated": events.get("last changed"), "expires": events.get("expiration"), "nameservers": nameservers}}


def urlscan_search(url):
    headers = {"API-Key": URLSCAN_KEY} if URLSCAN_KEY else {}
    params = {"q": f'task.url:"{url}"', "size": 5}
    data, err = get_json("https://urlscan.io/api/v1/search/", headers=headers, params=params)
    if err: return {"name": "urlscan.io", "status": "error", "summary": err, "details": {}}
    items = data.get("results", [])
    if not items: return {"name": "urlscan.io", "status": "success", "summary": "No existing indexed scan found; no scan was submitted", "details": {"matches": 0}}
    first = items[0]
    verdict = first.get("verdicts", {}).get("overall", {})
    return {"name": "urlscan.io", "status": "success", "summary": f"Found {len(items)} existing scan(s); latest verdict malicious={verdict.get('malicious', 'unknown')}",
            "details": {"matches": len(items), "scan_id": first.get("_id"), "result_url": first.get("result"), "malicious": verdict.get("malicious", False), "score": verdict.get("score"), "visibility": first.get("task", {}).get("visibility")}}


def malwarebazaar_lookup(value):
    if not BAZAAR_KEY: return not_configured("MalwareBazaar")
    data, err = get_json("https://mb-api.abuse.ch/api/v1/", headers={"Auth-Key": BAZAAR_KEY}, data={"query": "get_info", "hash": value})
    if err: return {"name": "MalwareBazaar", "status": "error", "summary": err, "details": {}}
    item = (data.get("data") or [{}])[0] if data.get("query_status") == "ok" else {}
    if not item: return {"name": "MalwareBazaar", "status": "success", "summary": "No matching malware sample in MalwareBazaar", "details": {"malicious": False}}
    return {"name": "MalwareBazaar", "status": "success", "summary": f"Known sample · {item.get('signature', 'signature unavailable')} · {item.get('file_type', 'file type unavailable')}",
            "details": {"malicious": True, "sha256": item.get("sha256_hash"), "signature": item.get("signature"), "file_type": item.get("file_type"), "first_seen": item.get("first_seen"), "tags": item.get("tags", [])}}


def urlhaus_lookup(host):
    if not URLHAUS_KEY: return not_configured("URLhaus")
    data, err = get_json("https://urlhaus-api.abuse.ch/v1/host/", headers={"Auth-Key": URLHAUS_KEY}, data={"host": host})
    if err: return {"name": "URLhaus", "status": "error", "summary": err, "details": {}}
    urls = data.get("urls", [])
    return {"name": "URLhaus", "status": "success", "summary": f"{len(urls)} URLhaus record(s) for host" if urls else "No URLhaus host records found", "details": {"malicious": bool(urls), "records": len(urls), "threats": list({u.get('threat', '') for u in urls if u.get('threat')})}}


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Threat Intelligence Hub API", "configured_providers": {
        "VirusTotal": bool(VT_KEY), "AbuseIPDB": bool(ABUSE_KEY), "urlscan.io": bool(URLSCAN_KEY),
        "MalwareBazaar": bool(BAZAAR_KEY), "AlienVault OTX": bool(OTX_KEY), "NVD": True, "URLhaus": bool(URLHAUS_KEY)}}

@app.post("/api/ip")
def investigate_ip(body: IPRequest):
    try: parsed = ipaddress.ip_address(body.ip.strip())
    except ValueError: raise HTTPException(400, "Enter a valid IPv4 or IPv6 address.")
    ip = str(parsed)
    if not parsed.is_global:
        raise HTTPException(400, "Public threat-intelligence lookups are intended for public IP addresses. Private, loopback and reserved IPs are not queried.")
    return result("IP Intelligence", ip, [vt_lookup("ip_addresses", ip), abuse_lookup(ip), otx_lookup("IPv4" if parsed.version == 4 else "IPv6", ip)])

@app.post("/api/domain")
def investigate_domain(body: DomainRequest):
    domain = body.domain.strip().lower().rstrip(".")
    if len(domain) > 253 or not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+", domain):
        raise HTTPException(400, "Enter a valid domain name, without a URL path.")
    return result("Domain Intelligence", domain, [vt_lookup("domains", domain), rdap_lookup(domain), otx_lookup("domain", domain)])

@app.post("/api/url")
def scan_url(body: URLRequest):
    from urllib.parse import urlparse
    value = body.url.strip()
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or len(value) > 2048:
        raise HTTPException(400, "Enter a valid http:// or https:// URL.")
    # No direct fetch and no automatic submission: submitted URLs may contain private tokens or personal data.
    host = parsed.hostname.lower()
    sources = [vt_lookup("urls", value), urlscan_search(value), urlhaus_lookup(host), otx_lookup("url", value)]
    return result("URL Scanner", value, sources, {"safe_handling": "The application did not open or submit this URL. urlscan.io was queried for existing indexed scans only."})

@app.post("/api/hash")
def analyze_hash(body: HashRequest):
    value = body.value.strip().lower()
    expected = {32: "MD5", 40: "SHA1", 64: "SHA256"}
    if len(value) not in expected or not re.fullmatch(r"[a-f0-9]+", value): raise HTTPException(400, "Enter a valid MD5 (32), SHA1 (40), or SHA256 (64) hexadecimal hash.")
    return result("Hash Analyzer", value, [vt_lookup("files", value), malwarebazaar_lookup(value)], {"hash_type": expected[len(value)]})

async def read_upload(file):
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES: raise HTTPException(413, "File exceeds the 20 MB upload limit.")
    if not content: raise HTTPException(400, "The uploaded file is empty.")
    return content

@app.post("/api/hash/upload")
async def hash_uploaded_file(file: UploadFile = File(...)):
    content = await read_upload(file)
    sha256, md5, sha1 = hashlib.sha256(content).hexdigest(), hashlib.md5(content).hexdigest(), hashlib.sha1(content).hexdigest()
    stored_name = f"{uuid.uuid4().hex}.sample"
    (UPLOAD_DIR / stored_name).write_bytes(content)
    sources = [vt_lookup("files", sha256), malwarebazaar_lookup(sha256)]
    return result("Hash Analyzer", file.filename or "uploaded file", sources, {"file_size": len(content), "md5": md5, "sha1": sha1, "sha256": sha256, "stored_in_quarantine": True, "note": "Only hashes were sent to reputation providers. The file was not uploaded to them or executed."})

@app.post("/api/malware/scan")
async def malware_scan(scan_type: Literal["static", "dynamic"] = Form(...), file: UploadFile = File(...)):
    content = await read_upload(file)
    sha256 = hashlib.sha256(content).hexdigest()
    if scan_type == "dynamic":
        raise HTTPException(400, "Dynamic analysis is not available. Use a separately isolated malware sandbox; this application never executes samples.")
    (UPLOAD_DIR / f"{uuid.uuid4().hex}.sample").write_bytes(content)
    return result("Malware Intelligence", file.filename or "uploaded file", [vt_lookup("files", sha256), malwarebazaar_lookup(sha256)], {"scan_type": "static hash reputation lookup", "file_size": len(content), "sha256": sha256, "executed": False, "note": "Only the SHA256 hash was queried. The sample was not uploaded to third parties or executed."})

@app.post("/api/cve")
def investigate_cve(body: CVERequest):
    cve = body.cve_id.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve): raise HTTPException(400, "CVE ID format should look like CVE-2024-12345.")
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    data, err = get_json("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers, params={"cveId": cve})
    if err: sources = [{"name": "NIST NVD", "status": "error", "summary": err, "details": {}}]
    else:
        vulns = data.get("vulnerabilities", [])
        if not vulns: sources = [{"name": "NIST NVD", "status": "success", "summary": "No CVE record returned", "details": {}}]
        else:
            c = vulns[0].get("cve", {})
            desc = next((x.get("value") for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
            metrics = c.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key): cvss = metrics[key][0].get("cvssData", {}).get("baseScore"); break
            sources = [{"name": "NIST NVD", "status": "success", "summary": f"CVSS {cvss}" if cvss is not None else "CVE record found", "details": {"description": desc, "cvss_base_score": cvss, "published": c.get("published"), "last_modified": c.get("lastModified"), "source_identifier": c.get("sourceIdentifier"), "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}}]
    return result("CVE Intelligence", cve, sources)

@app.post("/api/phishing")
def investigate_phishing(body: PhishingRequest):
    value = body.value.strip()
    if not value: raise HTTPException(400, "Enter a domain or email address.")
    if body.mode == "email":
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value): raise HTTPException(400, "Enter a valid email address.")
        domain = value.rsplit("@", 1)[1].lower()
    else:
        domain = value.lower().rstrip(".")
        if "/" in domain or " " in domain: raise HTTPException(400, "Enter a domain only, not a full URL.")
    sources = [vt_lookup("domains", domain), rdap_lookup(domain), otx_lookup("domain", domain)]
    return result("Phishing Intelligence", value, sources, {"mode": body.mode, "email_header_supplied": bool((body.email_header or "").strip()), "header_note": "Email header text is not yet authenticated or parsed by this version."})

@app.post("/api/feeds/search")
def search_feeds(body: SearchRequest):
    return result("Threat Feeds", body.query or "Latest indicators", [not_configured("Feed aggregation", "Connect TAXII/STIX or curated feeds to enable this module")], {"category": body.category, "timeframe": body.timeframe})

@app.post("/api/mitre/search")
def search_mitre(body: SearchRequest):
    return result("MITRE ATT&CK", body.query, [not_configured("MITRE ATT&CK dataset", "Offline STIX dataset integration is not included in this update")])

@app.post("/api/news/search")
def search_news(body: SearchRequest):
    return result("Cyber Threat News", body.query or "Latest cyber threat news", [not_configured("Cyber news feeds", "RSS feed aggregation is not included in this update")], {"category": body.category, "timeframe": body.timeframe})

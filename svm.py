#!/usr/bin/env python3
import csv, datetime as dt, json, os, re, sys, time
import urllib.request, urllib.error
from pathlib import Path
from urllib.parse import urlencode

# === Globals / Config ===
CSV_PATH = Path(os.getenv("SVM_CSV", "svm_feed.csv"))
NOW = dt.datetime.utcnow()
WINDOW_HOURS = int(os.getenv("SVM_WINDOW_HOURS", "48"))

DEBUG       = os.getenv("SVM_DEBUG", "0") == "1"
SCOPE_ALL   = os.getenv("SVM_SCOPE_ALL", "0") == "1"
SLACK_WEBHOOK = os.getenv("SVM_SLACK_WEBHOOK")

# News
NEWS_ENABLED = os.getenv("SVM_NEWS", "0") == "1"
NEWSAPI_KEY  = os.getenv("SVM_NEWSAPI_KEY")

ESPIONAGE_TERMS = [
    "espionage", "state actor", "spy", "intelligence agency",
    "APT", "foreign interference", "surveillance", "nation-state",
    "Mossad", "FSB", "CIA", "leak", "cyber operation", "covert",
    "sabotage", "military intel", "spying"
]

# === Slack helper with backoff ===
def post_slack(message, blocks=None, max_retries=3):
    """Send a message to Slack via Incoming Webhook with basic 429 backoff."""
    if not SLACK_WEBHOOK:
        return
    payload = {"text": message}
    if blocks:
        payload["blocks"] = blocks
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=15):
                return
        except urllib.error.HTTPError as e:
            if e.code == 429:  # Slack rate limit
                retry_after = int(e.headers.get("Retry-After", "1"))
                time.sleep(retry_after + 1)
                continue
            time.sleep(1 + attempt)
        except Exception:
            time.sleep(1 + attempt)

# === Utility functions ===
KEYWORDS = [
    r"bluetooth", r"\bble\b", r"br/edr", r"zigbee", r"z-?wave",
    r"802\.11", r"\bwi-?fi\b", r"\bhalow\b", r"\b6e\b", r"\blora\b",
    r"broadcom", r"qualcomm", r"realtek", r"mediatek",
    r"nordic", r"nrf52", r"ti", r"cc25\d", r"cc26\d",
    r"bluez", r"bluesdk", r"opensynergy"
]
SCOPE_RE = re.compile("|".join(KEYWORDS), re.I)
def in_scope(text): return bool(SCOPE_RE.search(text or ""))

def family_label(text):
    t = (text or "").lower()
    if "bluetooth" in t or "ble" in t or "br/edr" in t: return "bluetooth"
    if "zigbee"   in t: return "zigbee"
    if "z-wave"   in t or "zwave" in t: return "z-wave"
    if "802.11"   in t or "wifi"  in t or "wi-fi" in t or "halow" in t: return "wifi"
    if "lora"     in t: return "lora"
    return "other"

def http_get_json(url, headers=None, params=None):
    if params: url += ("?" + urlencode(params))
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "Span-SVM/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except Exception as e:
        print(f"[WARN] GET {url} failed: {e}")
        return None

def load_existing():
    if not CSV_PATH.exists(): return set()
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        return {row["cve_id"] for row in csv.DictReader(f)}

def append_rows(rows):
    new_file = not CSV_PATH.exists()
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "ingested_at","source","cve_id","title","published","last_modified",
            "cvss","severity","exploited","family","vendors","products","refs"])
        if new_file: w.writeheader()
        for r in rows: w.writerow(r)

# === Feed pulls ===
def pull_cisa_kev():
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = http_get_json(kev_url)
    if not data: return []
    out = []
    vulns = data.get("vulnerabilities", []) or []
    for item in vulns:
        name = item.get("vulnerabilityName","") or ""
        desc = item.get("shortDescription","") or ""
        vendor = item.get("vendorProject","") or ""
        product = item.get("product","") or ""
        text = f"{name} {desc} {vendor} {product}"
        if not (SCOPE_ALL or in_scope(text)): 
            continue
        out.append({
            "ingested_at": NOW.isoformat(timespec="seconds")+"Z",
            "source": "CISA-KEV",
            "cve_id": item.get("cveID",""),
            "title": name or desc[:120] or "CISA KEV item",
            "published": item.get("dateAdded",""),
            "last_modified": item.get("dateAdded",""),
            "cvss": "",
            "severity": "HIGH",            # KEV implies priority
            "exploited": "true",
            "family": family_label(text),
            "vendors": vendor,
            "products": product,
            "refs": item.get("requiredAction","")
        })
    if DEBUG: print(f"[DEBUG] KEV total={len(vulns)} in_scope={len(out)}")
    return out

def pull_nvd():
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start = (NOW - dt.timedelta(hours=WINDOW_HOURS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end   = NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    params = {"lastModStartDate": start, "lastModEndDate": end, "resultsPerPage": 2000}
    headers = {"User-Agent": "Span-SVM/1.0"}
    api_key = os.getenv("SVM_NVD_API_KEY")
    if api_key: headers["apiKey"] = api_key
    data = http_get_json(base, headers=headers, params=params)
    if not data: return []
    vulns = data.get("vulnerabilities", []) or []
    out = []
    for item in vulns:
        c = item.get("cve", {})
        cve_id = c.get("id","")
        desc = " ".join(d.get("value","") for d in c.get("descriptions",[]) if d.get("lang")=="en")
        if not (SCOPE_ALL or in_scope(desc)): 
            continue
        metrics = c.get("metrics",{}) or {}
        cvss, severity = "", ""
        for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                m = arr[0].get("cvssData", {})
                cvss = str(m.get("baseScore","")) or ""
                severity = (m.get("baseSeverity","") or "").upper()
                break
        refs = ", ".join(r.get("url","") for r in c.get("references",[]) or [])
        out.append({
            "ingested_at": NOW.isoformat(timespec="seconds")+"Z",
            "source": "NVD",
            "cve_id": cve_id,
            "title": (c.get("sourceIdentifier","") + " " + cve_id).strip() or cve_id,
            "published": c.get("published",""),
            "last_modified": c.get("lastModified",""),
            "cvss": cvss,
            "severity": severity,
            "exploited": "false",
            "family": family_label(desc),
            "vendors": "",
            "products": "",
            "refs": refs[:1500]
        })
    if DEBUG: print(f"[DEBUG] NVD total={len(vulns)} in_scope={len(out)}")
    return out

# === Espionage News Pull (merged into digest) ===
def pull_espionage_news(max_results=5):
    if not (NEWS_ENABLED and NEWSAPI_KEY):
        return []
    base = "https://newsapi.org/v2/everything"
    from_dt = (NOW - dt.timedelta(hours=WINDOW_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    query = " OR ".join(f'"{kw}"' for kw in ESPIONAGE_TERMS)
    params = {
        "q": query,
        "language": "en",
        "sortBy": "publishedAt",
        "pageSize": max_results,
        "from": from_dt,
    }
    headers = {"X-Api-Key": NEWSAPI_KEY, "User-Agent": "Span-SVM/1.0"}
    data = http_get_json(base, headers=headers, params=params)
    if not data or not data.get("articles"):
        return []
    articles = []
    for a in data["articles"]:
        title = (a.get("title") or "").strip()
        url = a.get("url") or ""
        source = (a.get("source", {}).get("name") or "").strip()
        if title and url:
            articles.append(f"• *<{url}|{title}>* ({source})")
    return articles

# === Main ===
def main():
    existing = load_existing()
    rows = pull_cisa_kev() + pull_nvd()
    new = [r for r in rows if r.get("cve_id") and r["cve_id"] not in existing]

    # Suppress first-run flood: seed CSV quietly, no Slack
    if not existing and new and os.getenv("SVM_SUPPRESS_SEED","1") == "1":
        append_rows(new)
        print(f"[INFO] Seeded {len(new)} rows without Slack alerts.")
        return 0

    # Persist all new items (historical record)
    if new:
        append_rows(new)

    # Post-filter knobs (for Slack noise control)
    FAMILIES    = set(os.getenv("SVM_FAMILIES","bluetooth,wifi").split(","))
    MIN_SEV     = os.getenv("SVM_MIN_SEVERITY","MEDIUM").upper()
    MAX_ALERTS  = int(os.getenv("SVM_MAX_ALERTS","25"))
    sev_rank    = {"":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    min_rank    = sev_rank.get(MIN_SEV,2)

    # Filter by family/severity for alerting
    new = [r for r in new if r.get("family") in FAMILIES
           and sev_rank.get((r.get("severity") or "").upper(),0) >= min_rank]

    # Cap (prefer exploited + HIGH/CRITICAL)
    if len(new) > MAX_ALERTS:
        new = sorted(new, key=lambda r: (r.get("exploited")!="true",
                                         r.get("severity") not in ("CRITICAL","HIGH")))[:MAX_ALERTS]

    # Heartbeat when nothing to report
    if not new:
        if os.getenv("SVM_HEARTBEAT","0") == "1":
            post_slack("🫀 SVM heartbeat: no new in-scope items this run.")
        print("New items added: 0")
        return 0

    # === DIGEST MODE (one Slack message, CVEs hyperlinked; news merged) ===
    hi = [r for r in new if r["exploited"]=="true" or r["severity"] in ("HIGH","CRITICAL") or r["family"]=="bluetooth"]
    lo = [r for r in new if r not in hi]

    def cve_link(cve): return f"<https://nvd.nist.gov/vuln/detail/{cve}|{cve}>"
    def line(r):
        sev = r.get("severity") or "—"
        return f"• *{cve_link(r['cve_id'])}* ({r['family']}, sev={sev}, exploited={r['exploited']}) — {r['title'][:90]}"

    lines = []
    if hi:
        lines.append(f"*Priority items ({len(hi)})*")
        lines += [line(r) for r in hi[:20]]
        if len(hi) > 20: lines.append(f"…and {len(hi)-20} more")
    if lo:
        lines.append("")
        lines.append(f"*Other in-scope items ({len(lo)})*")
        lines += [line(r) for r in lo[:10]]
        if len(lo) > 10: lines.append(f"…and {len(lo)-10} more")

    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}]

    # Merge News into the same post
    news_items = pull_espionage_news()
    if news_items:
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f":detective: *Espionage-related intelligence headlines* ({len(news_items)}):\n" +
                             "\n".join(news_items)}
        })

    post_slack(
        "📬 SVM digest",
        blocks=blocks
    )

    print(f"New items added (alerted): {len(new)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

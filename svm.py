import csv, datetime as dt, json, os, re, sys
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import urlencode

CSV_PATH = Path(os.getenv("SVM_CSV", "svm_feed.csv"))
NOW = dt.datetime.utcnow()
WINDOW_HOURS = int(os.getenv("SVM_WINDOW_HOURS", "8760"))
#   SELF_TEST = os.getenv("SVM_SELF_TEST", "0") == "1"

DEBUG = os.getenv("SVM_DEBUG", "0") == "1"
SCOPE_ALL = os.getenv("SVM_SCOPE_ALL", "0") == "1"  # bypass filters to test


# --- add near the top ---
import json, os, urllib.request

SLACK_WEBHOOK = os.getenv("SVM_SLACK_WEBHOOK")

def post_slack(message, blocks=None):
    """Send a message to Slack via Incoming Webhook."""
    if not SLACK_WEBHOOK:
        return
    payload = {"text": message}
    if blocks:
        payload["blocks"] = blocks
    req = urllib.request.Request(
        SLACK_WEBHOOK,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as _:
        pass


# ---- Scope filters
KEYWORDS = [
    r"bluetooth", r"\bble\b", r"br/edr", r"bluffs", r"knob",
    r"zigbee", r"z-?wave",
    r"802\.11", r"\bwi-?fi\b", r"\bhalow\b", r"6e\b",
    r"\blora\b",
    # vendor/chip hot-words commonly seen in CVEs/KEV:
    r"\bbroadcom\b", r"\bqualcomm\b", r"\brealtek\b", r"\bmediatek\b",
    r"\bnordic\b", r"\bnrf52\b", r"\bti\b", r"\bcc25\d", r"\bcc26\d",
    r"\bbluez\b", r"\bopensynergy\b", r"\bbluesdk\b", r"\bcsr\b"
]
SCOPE_RE = re.compile("|".join(KEYWORDS), re.I)


def http_get_json(url, headers=None, params=None):
    if params:
        url += ("?" + urlencode(params))
    req = Request(url, headers=headers or {"User-Agent": "Span-SVM/1.0"})
    try:
        with urlopen(req, timeout=60) as r:
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

def family_label(text):
    t = text.lower()
    if "bluetooth" in t or "ble" in t or "br/edr" in t: return "bluetooth"
    if "zigbee" in t: return "zigbee"
    if "z-wave" in t or "zwave" in t: return "z-wave"
    if "802.11" in t or "wifi" in t or "wi-fi" in t or "halow" in t: return "wifi"
    if "lora" in t: return "lora"
    return "other"

def in_scope(text):
    return bool(SCOPE_RE.search(text or ""))

def pull_cisa_kev():
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = http_get_json(kev_url, headers={"User-Agent":"Span-SVM/1.0"})
    if not data:
        print("[WARN] KEV pull failed.")
        return []
    total, kept = 0, 0
    out = []
    for item in data.get("vulnerabilities", []):
        total += 1
        name = item.get("vulnerabilityName","") or ""
        desc = item.get("shortDescription","") or ""
        vendor = item.get("vendorProject","") or ""
        product = item.get("product","") or ""
        text = f"{name}. {desc} {vendor} {product}"
        if not (SCOPE_ALL or in_scope(text)):
            continue
        kept += 1
        out.append({
            "ingested_at": NOW.isoformat(timespec="seconds")+"Z",
            "source": "CISA-KEV",
            "cve_id": item.get("cveID",""),
            "title": name or (desc[:120] if desc else "CISA KEV item"),
            "published": item.get("dateAdded",""),
            "last_modified": item.get("dateAdded",""),
            "cvss": "",
            "severity": "HIGH",
            "exploited": "true",
            "family": family_label(text),
            "vendors": vendor,
            "products": product,
            "refs": item.get("requiredAction","")
        })
    if DEBUG:
        print(f"[DEBUG] KEV total={total} in_scope={kept}")
    return out


def pull_nvd():
    """
    Pull CVEs from NVD v2 within a rolling window and keep only in-scope items.
    Uses broader matching (desc + vendor/product names) and won't crash on API hiccups.
    Requires globals:
      - NOW, WINDOW_HOURS (datetime.utcnow() and hours as int)
      - http_get_json (helper)
      - in_scope(text) (regex-based scope filter)
      - family_label(text) (labels: bluetooth, wifi, zigbee, etc.)
      - DEBUG (bool), SCOPE_ALL (bool)
    Optionally uses env SVM_NVD_API_KEY for higher rate limits.
    """
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # NVD requires *paired* timestamps with Zulu timezone and milliseconds.
    start = (NOW - dt.timedelta(hours=WINDOW_HOURS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end   = NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # KeywordSearch helps reduce noise before our stricter in_scope() filter.
    params = {
        "lastModStartDate": start,
        "lastModEndDate": end,
        "resultsPerPage": 2000,  # NVD caps apply; paginate if you ever need >2000
        "keywordSearch": " OR ".join([
            "bluetooth","zigbee","z-wave","802.11","halow","wifi","wi-fi","6e",
            "lora","bluez","rfcomm","avdtp","gatt",
            "broadcom","qualcomm","realtek","mediatek","nordic","nrf52","ti","cc254","cc264"
        ])
    }

    headers = {"User-Agent": "Span-SVM/1.0"}
    api_key = os.getenv("SVM_NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    data = http_get_json(base, headers=headers, params=params)
    if not data:
        print("[WARN] NVD pull failed or returned no data; continuing without NVD.")
        return []

    # Helper to walk nested configuration nodes safely
    def iter_cpe_matches(configurations):
        # NVD sometimes returns dict with "nodes", sometimes a list already
        nodes = []
        if isinstance(configurations, dict):
            nodes = configurations.get("nodes", []) or []
        elif isinstance(configurations, list):
            nodes = configurations
        else:
            return  # nothing

        stack = list(nodes)
        while stack:
            node = stack.pop()
            # child nodes
            for child in node.get("children", []) or []:
                stack.append(child)
            for child in node.get("nodes", []) or []:
                stack.append(child)
            # cpe matches at this node
            for m in node.get("cpeMatch", []) or []:
                yield m

    total, kept = 0, 0
    out = []

    for item in data.get("vulnerabilities", []):
        total += 1
        c = item.get("cve", {})

        cve_id = c.get("id", "")
        # English description
        desc = ""
        for drec in c.get("descriptions", []) or []:
            if drec.get("lang") == "en":
                desc = drec.get("value", "") or ""
                break

        # Vendors/products from configurations → improves scope matching
        vendors, products = set(), set()
        for m in iter_cpe_matches(c.get("configurations", {})):
            crit = (m.get("criteria") or m.get("cpe23Uri") or "")
            parts = crit.split(":")
            # cpe:2.3:a:vendor:product:version:...
            if len(parts) >= 5:
                vendors.add(parts[3])
                products.add(parts[4])

        scope_text = f"{desc} {' '.join(sorted(vendors))} {' '.join(sorted(products))}"
        if not (SCOPE_ALL or in_scope(scope_text)):
            continue

        # Metrics → cvss + severity (prefer v3.1 → v3.0 → v2)
        cvss, severity = "", ""
        metrics = c.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                m = arr[0].get("cvssData", {})
                cvss = str(m.get("baseScore", "")) if m else ""
                severity = (m.get("baseSeverity", "") or severity).upper()
                break

        # References (first few concatenated)
        refs = ", ".join(r.get("url", "") for r in c.get("references", []) or [])

        out.append({
            "ingested_at": NOW.isoformat(timespec="seconds") + "Z",
            "source": "NVD",
            "cve_id": cve_id,
            "title": (c.get("sourceIdentifier", "") + " " + cve_id).strip() or cve_id,
            "published": c.get("published", ""),
            "last_modified": c.get("lastModified", ""),
            "cvss": cvss,
            "severity": severity,
            "exploited": "false",
            "family": family_label(scope_text),
            "vendors": ";".join(sorted(vendors)),
            "products": ";".join(sorted(products)),
            "refs": refs[:1500]
        })
        kept += 1

    if DEBUG:
        print(f"[DEBUG] NVD total={total} in_scope={kept}")

    return out


def main():
    existing = load_existing()
    rows = []
    rows += pull_cisa_kev()
    rows += pull_nvd()
    
    # de-dupe by CVE id against prior CSV
    new = [r for r in rows if r["cve_id"] and r["cve_id"] not in existing]
    if new:
        append_rows(new)

    # One-time Slack self-test (set SVM_SELF_TEST=1 in workflow to verify wiring)
    if SELF_TEST:
        post_slack("✅ SVM online: Slack webhook connected and script executed.")

    
    # 🔔 Slack + console alerts
    high_impact = [
        r for r in new 
        if r["exploited"] == "true" 
        or r["severity"] in ("HIGH", "CRITICAL") 
        or r["family"] == "bluetooth"
    ]
    for r in high_impact:
        sev = r["severity"] or "—"
        emoji = "🚨" if r["exploited"] == "true" or sev in ("CRITICAL", "HIGH") else "📣"
        title = r["title"][:120]
        txt = (
            f"{emoji} {r['cve_id']} | {r['family'].upper()} | "
            f"sev={sev} | exploited={r['exploited']}\n"
            f"{title}\nPublished: {r['published']}  "
            f"Modified: {r['last_modified']}"
        )
        post_slack(txt)   # 👈 sends alert to Slack webhook

    # 🫀 Optional: heartbeat digest when nothing new matched
    if not new:
        hb = os.getenv("SVM_HEARTBEAT", "0") == "1"
        if hb:
            post_slack("🫀 SVM heartbeat: no new in-scope items this run.")

    
    print(f"New items added: {len(new)}")


if __name__ == "__main__":
    sys.exit(main())


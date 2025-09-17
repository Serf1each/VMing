import csv, datetime as dt, json, os, re, sys
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import urlencode

CSV_PATH = Path(os.getenv("SVM_CSV", "svm_feed.csv"))
NOW = dt.datetime.utcnow()
WINDOW_HOURS = int(os.getenv("SVM_WINDOW_HOURS", "168"))

DEBUG = os.getenv("SVM_DEBUG", "0") == "1"
SCOPE_ALL = os.getenv("SVM_SCOPE_ALL", "0") == "1"  # bypass filters to test
SELF_TEST = os.getenv("SVM_SELF_TEST", "0") == "1"

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
    # ---- pulls + existing set
    existing = load_existing()

    # Optional one-time Slack wiring check
    if os.getenv("SVM_SELF_TEST", "0") == "1":
        post_slack("✅ SVM online: Slack webhook connected and script executed.")

    rows = []
    rows += pull_cisa_kev()
    rows += pull_nvd()

    # De-dupe by CVE id against prior CSV
    new = [r for r in rows if r.get("cve_id") and r["cve_id"] not in existing]

    # Suppress first-run flood: seed CSV silently, no Slack
    SUPPRESS_SEED = os.getenv("SVM_SUPPRESS_SEED", "1") == "1"
    if SUPPRESS_SEED and not existing and new:
        append_rows(new)
        print(f"[INFO] Seeded {len(new)} historical rows (no Slack alerts).")
        print("New items added: 0")
        return 0

    # Persist new items
    if new:
        append_rows(new)

    # ---- post-filtering knobs (safe defaults if envs not set)
    FAMILIES = set(os.getenv("SVM_FAMILIES", "bluetooth,wifi,zigbee,z-wave,lora").split(","))
    MIN_SEV = os.getenv("SVM_MIN_SEVERITY", "MEDIUM").upper()
    MAX_ALERTS = int(os.getenv("SVM_MAX_ALERTS", "25"))

    sev_rank = {"": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_rank = sev_rank.get(MIN_SEV, 2)

    # Keep only selected families + min severity
    new = [
        r for r in new
        if (r.get("family") in FAMILIES) and (sev_rank.get((r.get("severity") or "").upper(), 0) >= min_rank)
    ]

    # Cap volume (prefer exploited/HIGH+)
    if len(new) > MAX_ALERTS:
        def sort_key(r):
            # exploited first, then high severity first
            exploited = 0 if r.get("exploited") == "true" else 1
            sev = 0 if (r.get("severity") in ("CRITICAL", "HIGH")) else 1
            return (exploited, sev)
        new = sorted(new, key=sort_key)[:MAX_ALERTS]

    # === DIGEST MODE (one Slack message per run, CVE IDs hyperlinked) ===
    hi = [r for r in new if r.get("exploited") == "true" or r.get("severity") in ("HIGH", "CRITICAL") or r.get("family") == "bluetooth"]
    lo = [r for r in new if r not in hi]

    def cve_link(cve):
        return f"<https://nvd.nist.gov/vuln/detail/{cve}|{cve}>"

    def line(r):
        sev = (r.get("severity") or "—")
        title = (r.get("title") or "")[:90]
        fam = r.get("family") or "other"
        exp = r.get("exploited") or "false"
        return f"• *{cve_link(r['cve_id'])}* ({fam}, sev={sev}, exploited={exp}) — {title}"

    if hi or lo:
        lines = []
        if hi:
            lines.append(f"*Priority items ({len(hi)})*")
            lines += [line(r) for r in hi[:20]]
            if len(hi) > 20:
                lines.append(f"…and {len(hi) - 20} more")

        if lo:
            lines.append("")
            lines.append(f"*Other in-scope items ({len(lo)})*")
            lines += [line(r) for r in lo[:10]]
            if len(lo) > 10:
                lines.append(f"…and {len(lo) - 10} more")

        post_slack(
            f"📬 SVM digest — new items: {len(new)} (priority {len(hi)})",
            blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}]
        )
    elif os.getenv("SVM_HEARTBEAT", "0") == "1":
        post_slack("🫀 SVM heartbeat: no new in-scope items this run.")

    print(f"New items added: {len(new)}")
    return 0



if __name__ == "__main__":
    sys.exit(main())


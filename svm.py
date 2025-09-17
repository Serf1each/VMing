import csv, datetime as dt, json, os, re, sys
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import urlencode

CSV_PATH = Path(os.getenv("SVM_CSV", "svm_feed.csv"))
NOW = dt.datetime.utcnow()
WINDOW_HOURS = int(os.getenv("SVM_WINDOW_HOURS", "48"))

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
KEYWORDS = [r"bluetooth", r"\bble\b", r"br/edr", r"bluffs", r"knob",
            r"zigbee", r"z-?wave", r"802\.11", r"halow", r"wi-?fi\s?6e",
            r"\blo?ra\b", r"nrf52", r"cc25\d", r"cc26\d", r"blue\s?sdk",
            r"rfcomm", r"avdtp", r"gatt", r"bluez"]
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
    # CISA KEV JSON
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = http_get_json(kev_url)
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cveID")
        name = item.get("vulnerabilityName","")
        desc = item.get("shortDescription","")
        text = f"{name}. {desc}"
        if not in_scope(text): 
            continue
        out.append({
            "ingested_at": NOW.isoformat(timespec="seconds")+"Z",
            "source": "CISA-KEV",
            "cve_id": cve,
            "title": name or desc[:120],
            "published": item.get("dateAdded",""),
            "last_modified": item.get("dateAdded",""),
            "cvss": "",
            "severity": "HIGH",  # KEV implies high priority even if score unknown
            "exploited": "true",
            "family": family_label(text),
            "vendors": item.get("vendorProject",""),
            "products": item.get("product",""),
            "refs": item.get("requiredAction","")
        })
    return out

def pull_nvd():
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # NVD requires paired timestamps and expects Zulu time with milliseconds
    start = (NOW - dt.timedelta(hours=WINDOW_HOURS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end   = NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    params = {
        "lastModStartDate": start,
        "lastModEndDate": end,
        "resultsPerPage": 2000,
        "keywordSearch": " OR ".join([
            "bluetooth","zigbee","z-wave","802.11","halow","wifi",
            "lora","bluez","rfcomm","avdtp","gatt"
        ])
    }

    # Optional API key support (improves quotas)
    headers = {"User-Agent": "Span-SVM/1.0"}
    api_key = os.getenv("SVM_NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    data = http_get_json(base, headers=headers, params=params)
    if not data:
        print("[WARN] NVD pull failed or returned no data; continuing without NVD.")
        return []

    out = []
    for item in data.get("vulnerabilities", []):
        c = item["cve"]
        cve_id = c.get("id","")
        desc = " ".join(d.get("value","") for d in c.get("descriptions",[]) if d.get("lang")=="en")
        if not in_scope(desc):
            continue

        metrics = c.get("metrics",{})
        cvss = ""
        severity = ""
        for k in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if k in metrics and metrics[k]:
                m = metrics[k][0]["cvssData"]
                cvss = str(m.get("baseScore",""))
                severity = (m.get("baseSeverity","") or severity).upper()
                break

        vendors=set(); products=set()
        for node in c.get("configurations",[]):
            for n in node.get("nodes",[]):
                for match in n.get("cpeMatch",[]):
                    parts = match.get("criteria","").split(":")
                    if len(parts) >= 5:
                        vendors.add(parts[3]); products.add(parts[4])

        refs = ", ".join(r.get("url","") for r in c.get("references",[]))
        out.append({
            "ingested_at": NOW.isoformat(timespec="seconds")+"Z",
            "source": "NVD",
            "cve_id": cve_id,
            "title": (c.get("sourceIdentifier","") + " " + cve_id).strip(),
            "published": c.get("published",""),
            "last_modified": c.get("lastModified",""),
            "cvss": cvss,
            "severity": severity,
            "exploited": "false",
            "family": family_label(desc),
            "vendors": ";".join(sorted(vendors)),
            "products": ";".join(sorted(products)),
            "refs": refs[:1500]
        })
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
    
    print(f"New items added: {len(new)}")


if __name__ == "__main__":
    sys.exit(main())


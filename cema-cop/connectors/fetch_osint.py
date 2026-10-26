#!/usr/bin/env python3
"""Pull live public OSINT feeds into data/live/live.js for the CEMA COP.

Every connector is independent: a feed that is down or blocked is skipped and
recorded in the manifest, and the UI falls back to synthetic data for it.

Run from an internet-facing OSINT workstation (never from a military network,
for OPSEC), then copy data/live/live.js across to the COP host.

    python3 connectors/fetch_osint.py            # all feeds
    python3 connectors/fetch_osint.py kev nvd    # selected feeds
"""
import json
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "live" / "live.js"
UA = "CEMA-COP-OSINT/1.0 (research prototype)"
MY_BBOX = dict(lamin=0.5, lomin=99.0, lamax=7.6, lomax=120.0)  # Peninsular + Borneo + Sulu


def get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def get_json(url, timeout=30):
    return json.loads(get(url, timeout))


# --- Cyber OSINT -------------------------------------------------------------

def kev():
    """CISA Known Exploited Vulnerabilities: matched against asset inventory in the UI."""
    d = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    vulns = sorted(d["vulnerabilities"], key=lambda v: v["dateAdded"], reverse=True)
    keep = ("vendorProject", "product", "cveID", "vulnerabilityName", "dateAdded",
            "dueDate", "knownRansomwareCampaignUse", "shortDescription")
    return {"catalogVersion": d.get("catalogVersion"), "count": d.get("count"),
            "items": [{k: v.get(k) for k in keep} for v in vulns[:400]]}


def nvd():
    """NVD CVEs published in the last 7 days with CVSS >= 7."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    q = urllib.parse.urlencode({
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    })
    d = get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?" + q, timeout=60)
    items = []
    for v in d.get("vulnerabilities", []):
        c = v["cve"]
        score, sev = None, None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            m = c.get("metrics", {}).get(key)
            if m:
                score = m[0]["cvssData"]["baseScore"]
                sev = m[0]["cvssData"].get("baseSeverity")
                break
        if score is None or score < 7:
            continue
        desc = next((x["value"] for x in c.get("descriptions", []) if x["lang"] == "en"), "")
        items.append({"id": c["id"], "published": c["published"], "score": score,
                      "severity": sev, "desc": desc[:300]})
    items.sort(key=lambda x: (-x["score"], x["published"]))
    return {"window_days": 7, "items": items[:300]}


def feodo():
    """abuse.ch Feodo Tracker botnet C2 IPs: used as an IOC blocklist and SIEM match list."""
    d = get_json("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    return {"count": len(d), "items": d[:500]}


def ripe():
    """RIPEstat routing visibility for Malaysian address space (internet health)."""
    d = get_json("https://stat.ripe.net/data/country-resource-stats/data.json?resource=MY")
    stats = d.get("data", {}).get("stats", [])
    return {"items": [{"t": s.get("timeline", [{}])[0].get("starttime"),
                       "v4_routed": s.get("v4_prefixes_ris"),
                       "v6_routed": s.get("v6_prefixes_ris"),
                       "asns": s.get("asns_ris")} for s in stats[-60:]]}


# --- EW / space OSINT --------------------------------------------------------

def kp():
    """NOAA planetary K-index: geomagnetic storms degrade HF and GNSS."""
    d = get_json("https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json")
    if d and isinstance(d[0], list):  # older array-of-arrays format
        head, rows = d[0], d[1:]
        d = [dict(zip(head, r)) for r in rows]
    return {"items": [{"t": r["time_tag"], "kp": float(r["Kp"])} for r in d[-40:]]}


def satellites():
    """CelesTrak GP elements: military + earth-observation satellites for overhead passes."""
    out = []
    for group in ("military", "resource", "radar"):
        try:
            for s in get_json(f"https://celestrak.org/NORAD/elements/gp.php?GROUP={group}&FORMAT=json", 40):
                out.append({"group": group, **{k: s.get(k) for k in (
                    "OBJECT_NAME", "NORAD_CAT_ID", "EPOCH", "MEAN_MOTION", "ECCENTRICITY",
                    "INCLINATION", "RA_OF_ASC_NODE", "ARG_OF_PERICENTER", "MEAN_ANOMALY",
                    "BSTAR", "MEAN_MOTION_DOT", "MEAN_MOTION_DDOT")}})
        except Exception as e:  # one group failing should not drop the others
            print(f"  satellites/{group}: {e}", file=sys.stderr)
    if not out:
        raise RuntimeError("no satellite groups reachable")
    return {"items": out[:400]}


# --- Fusion OSINT (air) ------------------------------------------------------

def opensky():
    """OpenSky ADS-B state vectors over Malaysia. NIC/position anomalies hint at GNSS interference."""
    d = get_json("https://opensky-network.org/api/states/all?" + urllib.parse.urlencode(MY_BBOX))
    items = []
    for s in d.get("states") or []:
        if s[5] is None or s[6] is None:
            continue
        items.append({"icao24": s[0], "callsign": (s[1] or "").strip(), "country": s[2],
                      "lon": s[5], "lat": s[6], "alt": s[7] or s[13], "ground": s[8],
                      "vel": s[9], "hdg": s[10], "squawk": s[14]})
    return {"time": d.get("time"), "items": items}


# --- General OSINT (news) ----------------------------------------------------

NEWS_QUERIES = {
    "Sabah security": "Sabah ESSZONE OR ESSCOM OR kidnap OR intrusion",
    "South China Sea": "Luconia OR \"South China Sea\" Malaysia coast guard",
    "Border": "Sarawak Kalimantan border smuggling",
    "Cyber MY": "Malaysia cyber attack OR breach OR ransomware",
    "GNSS": "GPS jamming OR GNSS interference Asia",
}


def news():
    items = []
    for topic, q in NEWS_QUERIES.items():
        url = "https://news.google.com/rss/search?" + urllib.parse.urlencode(
            {"q": q + " when:7d", "hl": "en-MY", "gl": "MY", "ceid": "MY:en"})
        try:
            root = ET.fromstring(get(url))
        except Exception as e:
            print(f"  news/{topic}: {e}", file=sys.stderr)
            continue
        for it in root.iter("item"):
            items.append({"topic": topic, "title": it.findtext("title"),
                          "link": it.findtext("link"), "pub": it.findtext("pubDate"),
                          "source": it.findtext("source")})
            if sum(1 for x in items if x["topic"] == topic) >= 12:
                break
    for name, url in (("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),):
        try:
            root = ET.fromstring(get(url))
            for it in list(root.iter("item"))[:15]:
                items.append({"topic": "Cyber global", "title": it.findtext("title"),
                              "link": it.findtext("link"), "pub": it.findtext("pubDate"),
                              "source": name})
        except Exception as e:
            print(f"  news/{name}: {e}", file=sys.stderr)
    if not items:
        raise RuntimeError("no news feeds reachable")
    return {"items": items}


CONNECTORS = {"kev": kev, "nvd": nvd, "feodo": feodo, "ripe": ripe, "kp": kp,
              "satellites": satellites, "opensky": opensky, "news": news}


def main(argv):
    wanted = argv or list(CONNECTORS)
    live = {}
    if OUT.exists():  # keep earlier pulls of feeds not refreshed this run
        try:
            live = json.loads(OUT.read_text().split("=", 1)[1].rstrip().rstrip(";"))
        except Exception:
            live = {}
    manifest = live.get("_manifest", {})
    for name in wanted:
        t0 = time.time()
        try:
            live[name] = CONNECTORS[name]()
            n = len(live[name].get("items", []))
            manifest[name] = {"ok": True, "items": n,
                              "fetched": datetime.now(timezone.utc).isoformat(timespec="seconds")}
            print(f"[ok]   {name:<11} {n:>5} items  {time.time() - t0:.1f}s")
        except Exception as e:
            manifest[name] = {"ok": False, "error": str(e)[:200],
                              "fetched": datetime.now(timezone.utc).isoformat(timespec="seconds")}
            print(f"[fail] {name:<11} {e}")
    live["_manifest"] = manifest
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("window.CEMA_LIVE = " + json.dumps(live, separators=(",", ":")) + ";\n")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main(sys.argv[1:])

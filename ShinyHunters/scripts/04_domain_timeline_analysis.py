#!/usr/bin/env python3
"""
04_domain_timeline_analysis.py
==============================
Performs WHOIS lookups on all detected domains from the ShinyHunters campaign
to build a registration timeline and identify campaign phases.

Requires: pip install python-whois (see requirements.txt)

Usage:
    source .venv/bin/activate
    python3 scripts/04_domain_timeline_analysis.py
"""

import json
import os
import time
from datetime import datetime
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "scripts", "output")

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    print("[WARN] python-whois not installed")


def get_base_domain(domain):
    """Extract the base registrable domain."""
    parts = domain.split(".")
    cc_slds = ("co", "com", "org", "net", "ac", "edu", "gov")
    if len(parts) >= 3 and parts[-2] in cc_slds:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def main():
    with open(os.path.join(BASE, "Shiny_Hunters_PeopleSoftZeroDay.json")) as f:
        data = json.load(f)

    # Get all detected domains
    detected_domains = [
        n["entity_id"]
        for n in data["nodes"]
        if n["type"] == "domain"
        and n.get("entity_attributes", {}).get("has_detections")
    ]

    # Filter out obvious CDN/legitimate service domains
    legit_patterns = [
        "google", "microsoft", "bing", "azure", "akamai", "gvt1",
        "mozilla", "windows.com", "office.com", "live.com", "msn.com",
        "cloudflare", "fastly", "letsencrypt", "pki.goog", "bodis.com",
        "tripod.com", "free.fr", "t35.com", "ovh.net", "wixdns.net",
        "googlesyndication", "edgekey.net", "edgesuite.net", "msedge.net",
        "searchmagnified", "amazonaws.com", "1e100.net", "nelreports",
    ]

    suspicious = set()
    for d in detected_domains:
        if not any(p in d.lower() for p in legit_patterns):
            suspicious.add(get_base_domain(d))

    # Add key infrastructure domains
    key_infra = [
        "cloaker.buzz", "rockyviewtech.com", "data-ps.org",
        "mgovideo.org", "topgamse.com", "winmanage-me.network",
        "royalinsulationcanada.ca", "myexternalip.com",
    ]
    for d in key_infra:
        suspicious.add(d)

    print(f"Querying WHOIS for {len(suspicious)} domains...")

    results = {}
    for i, domain in enumerate(sorted(suspicious)):
        if domain in results:
            continue

        if HAS_WHOIS:
            try:
                w = whois.whois(domain)
                created = w.creation_date
                if isinstance(created, list):
                    created = created[0]
                results[domain] = {
                    "created": str(created) if created else None,
                    "registrar": w.registrar,
                    "name_servers": list(w.name_servers) if w.name_servers else None,
                }
            except Exception as e:
                results[domain] = {"error": str(e)[:100]}
        else:
            results[domain] = {"error": "python-whois not installed"}

        if i % 20 == 0:
            print(f"  [{i}/{len(suspicious)}]")
        time.sleep(0.3)

    # Build timeline
    timeline = []
    for domain, info in results.items():
        if info.get("created") and info["created"] != "None":
            try:
                dt_str = (
                    info["created"]
                    .replace("+00:00", "")
                    .replace(" ", "T")
                    .split(".")[0]
                )
                dt = datetime.fromisoformat(dt_str)
                timeline.append(
                    {
                        "domain": domain,
                        "date": dt.strftime("%Y-%m-%d"),
                        "registrar": info.get("registrar"),
                        "phase": classify_phase(dt),
                    }
                )
            except Exception:
                pass

    timeline.sort(key=lambda x: x["date"])

    # Phase summary
    phases = defaultdict(list)
    for entry in timeline:
        phases[entry["phase"]].append(entry)

    # Output
    with open(os.path.join(OUT, "domain_timeline.json"), "w") as f:
        json.dump(timeline, f, indent=2)

    with open(os.path.join(OUT, "domain_registration_dates.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)

    # Print report
    print("\n" + "=" * 90)
    print("DOMAIN REGISTRATION TIMELINE")
    print("=" * 90)
    for entry in timeline:
        marker = ""
        if "2026" in entry["date"] and int(entry["date"].split("-")[1]) >= 7:
            marker = " <<< JULY-SEPT 2026"
        elif "2026" in entry["date"]:
            marker = " << 2026"
        elif "2025" in entry["date"] or "2024" in entry["date"]:
            marker = " < recent"
        print(
            f"  {entry['date']} | {entry['domain']:<40} | "
            f"{(entry['registrar'] or '-')[:35]}{marker}"
        )

    print("\n" + "=" * 90)
    print("PHASE SUMMARY")
    print("=" * 90)
    for phase, entries in sorted(phases.items()):
        print(f"\n  {phase}: {len(entries)} domains")
        for e in entries[:5]:
            print(f"    {e['date']} {e['domain']}")
        if len(entries) > 5:
            print(f"    ... +{len(entries) - 5} more")


def classify_phase(dt):
    if dt.year <= 2020:
        return "Phase 0: Legacy/Acquired (pre-2021)"
    elif dt.year <= 2022:
        return "Phase 1: Bulk Registration (2021-2022)"
    elif dt.year == 2023:
        return "Phase 2: Infrastructure Prep (2023)"
    elif dt.year == 2024:
        return "Phase 3: Targeting Prep (2024)"
    elif dt.year == 2025:
        return "Phase 4: Pre-Campaign (2025)"
    elif dt.year == 2026 and dt.month <= 6:
        return "Phase 5: Campaign Buildup (Jan-Jun 2026)"
    elif dt.year == 2026 and dt.month >= 7:
        return "Phase 6: Active Campaign (Jul-Sep 2026)"
    return "Unknown"


if __name__ == "__main__":
    main()

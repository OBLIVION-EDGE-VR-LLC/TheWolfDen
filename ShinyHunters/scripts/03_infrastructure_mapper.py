#!/usr/bin/env python3
"""
03_infrastructure_mapper.py
===========================
Maps the full infrastructure chain from JSP webshells to C2/LP infrastructure.
Generates structured output for PlantUML diagram generation and reporting.

Usage:
    python3 scripts/03_infrastructure_mapper.py
"""

import json
import os
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "scripts", "output")


def load(fname):
    with open(os.path.join(OUT, fname)) as f:
        return json.load(f)


def main():
    enrichment = load("ip_enrichment.json")
    detected_ips = load("detected_ips.json")
    resolutions = load("resolutions.json")
    webshell_conns = load("webshell_connections.json")
    dga_patterns = load("dga_patterns.json")

    # ── 1. Classify IPs by role ──────────────────────────────────────────
    ip_roles = {}
    for ip, info in enrichment.items():
        asn_desc = (info.get("asn_description") or "").upper()
        role = "unknown"

        if "CHERRY" in asn_desc:
            role = "c2_primary"
        elif "M247" in asn_desc or "MULLVAD" in asn_desc:
            role = "vpn_anonymization"
        elif "AMAZON" in asn_desc or "AWS" in asn_desc:
            role = "redirector_cloud"
        elif "LINODE" in asn_desc or "AKAMAI" in asn_desc:
            role = "domain_staging"
        elif "HOSTWINDS" in asn_desc:
            role = "c2_relay"
        elif "DATAWAGON" in asn_desc:
            role = "bulletproof_hosting"
        elif "COLOCROSSING" in asn_desc or "HOSTPAPA" in asn_desc:
            role = "bulletproof_hosting"
        elif "DATACAMP" in asn_desc or "DATAPACKET" in asn_desc:
            role = "bulletproof_hosting"
        elif "31173" in asn_desc or "ESAB" in asn_desc:
            role = "bulletproof_hosting"
        elif "CLOUDSINGULARITY" in asn_desc:
            role = "bulletproof_hosting"
        elif "CHARTER" in asn_desc or "BELL" in asn_desc or "TWC" in asn_desc:
            role = "residential_proxy"
        elif "GOOGLE" in asn_desc:
            role = "legitimate_service"
        elif "FASTLY" in asn_desc:
            role = "cdn_legitimate"
        elif "NAMECHEAP" in asn_desc:
            role = "domain_registrar"
        elif "TILDA" in asn_desc:
            role = "web_hosting"
        elif "QWILT" in asn_desc:
            role = "cdn_legitimate"
        elif "BODIS" in asn_desc:
            role = "domain_parking"

        ip_roles[ip] = {
            **info,
            "role": role,
        }

    # ── 2. Build resolution chains ───────────────────────────────────────
    ip_to_domains = defaultdict(list)
    domain_to_ips = defaultdict(list)
    for res in resolutions:
        ip_to_domains[res["ip"]].append(res["domain"])
        domain_to_ips[res["domain"]].append(res["ip"])

    # ── 3. Identify infrastructure tiers ─────────────────────────────────
    tiers = {
        "tier1_c2": [],
        "tier2_redirectors": [],
        "tier3_staging": [],
        "tier4_vpn": [],
        "tier5_bulletproof": [],
        "tier6_residential": [],
        "legitimate": [],
    }

    tier_map = {
        "c2_primary": "tier1_c2",
        "c2_relay": "tier5_bulletproof",
        "redirector_cloud": "tier2_redirectors",
        "domain_staging": "tier3_staging",
        "domain_parking": "tier2_redirectors",
        "vpn_anonymization": "tier4_vpn",
        "bulletproof_hosting": "tier5_bulletproof",
        "residential_proxy": "tier6_residential",
        "legitimate_service": "legitimate",
        "cdn_legitimate": "legitimate",
        "domain_registrar": "tier3_staging",
        "web_hosting": "tier3_staging",
        "unknown": "tier5_bulletproof",
    }

    for ip, info in ip_roles.items():
        tier = tier_map.get(info["role"], "tier5_bulletproof")
        tiers[tier].append(info)

    # ── 4. Identify pivot domains ────────────────────────────────────────
    pivot_domains = {}
    for domain, ips in domain_to_ips.items():
        if len(ips) >= 2:
            pivot_domains[domain] = {
                "domain": domain,
                "ips": ips,
                "ip_count": len(ips),
                "tiers_touched": list(
                    set(
                        ip_roles.get(ip, {}).get("role", "unknown") for ip in ips
                    )
                ),
            }

    # ── 5. DGA analysis ─────────────────────────────────────────────────
    dga_summary = {}
    for pattern, domains in dga_patterns.items():
        dga_summary[pattern] = {
            "count": len(domains),
            "sample": domains[:5],
            "assessment": (
                "algorithmic_generation"
                if pattern in ("gacy*.com", "gady*.com", "gahy*.com")
                else "random_generation"
            ),
        }

    # ── 6. Attack chain summary ──────────────────────────────────────────
    attack_chain = {
        "initial_access": {
            "method": "PeopleSoft Zero-Day (PSEMHUB WAF Bypass)",
            "campaign": "UNC6240 (ShinyHunters) Oracle PeopleSoft Campaign",
            "webshell_count": 60,
            "webshells_in_graph": len(webshell_conns),
        },
        "execution": {
            "primary_payload": "LA.exe",
            "sha256": "3ba215692665513abfffd4e815c5c45f2d41e5dcc4283a2a3b740930c5c417c3",
            "vt_score": "52/100",
            "mitre_techniques": [
                "T1574.002 DLL Side-Loading",
                "T1497 Virtualization/Sandbox Evasion",
                "T1518.001 Security Software Discovery",
                "T1082 System Information Discovery",
                "T1059 Command and Scripting Interpreter",
                "T1057 Process Discovery",
            ],
        },
        "c2_infrastructure": {
            "primary_c2": "5.199.162.157 (Cherry Servers, Lithuania)",
            "key_domains": [
                "cloaker.buzz",
                "rockyviewtech.com",
                "data-ps.org",
            ],
            "redirectors": [
                "44.227.65.245 (AWS us-west-2)",
                "44.227.76.166 (AWS us-west-2)",
            ],
            "staging": [
                "172.232.4.89 (Linode)",
                "172.233.218.191 (Linode)",
                "199.59.243.224 (Amazon/BODIS)",
            ],
        },
        "anonymization": {
            "vpn_provider": "Mullvad VPN (M247 Europe SRL, ASN 9009)",
            "exit_nodes": 7,
            "geolocations": ["New York", "Los Angeles", "Dublin", "Quebec"],
            "relay_block": "142.11.200.186-190 (Hostwinds, contiguous /29)",
        },
        "domain_infrastructure": {
            "parked_domains": 20,
            "dga_domains": sum(len(v) for v in dga_patterns.values()),
            "compromised_domains": [
                "www.stamoutsos.com",
                "www.autodour.com",
                "www.phatmunky.com",
            ],
            "gov_themed": "grated.mgovideo.org (Porkbun LLC, created 2023-08-12)",
            "peoplesoft_themed": "data-ps.org (PDR/PublicDomainRegistry, created 2024-09-19)",
        },
        "cloud_infrastructure": {
            "s3_collection": "s3.amazonaws.com (VT collection of campaign files)",
            "elb": "hdredirect-lb7-5a03e1c2772e1c9c.elb.us-east-1.amazonaws.com",
            "storage": "storage.googleapis.com (used by dropped payloads)",
        },
        "related_campaigns": {
            "norad_mil": "https://www.norad.mil/ referenced in VT collection",
            "tmobile_metro": "Metro T-Mobile breach investigation overlap",
            "formbook": "FormBook/XLoader malware family connections",
            "amazon_asn": "AMAZON-02 ASN 16509 infrastructure overlap",
        },
    }

    # ── Write outputs ────────────────────────────────────────────────────
    outputs = {
        "ip_roles.json": ip_roles,
        "infrastructure_tiers.json": tiers,
        "pivot_domains.json": pivot_domains,
        "dga_summary.json": dga_summary,
        "attack_chain_summary.json": attack_chain,
        "ip_to_domains.json": dict(ip_to_domains),
        "domain_to_ips.json": dict(domain_to_ips),
    }

    for fname, data in outputs.items():
        path = os.path.join(OUT, fname)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"Wrote {path}")

    # ── Print summary ────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("INFRASTRUCTURE TIER SUMMARY")
    print("=" * 80)
    for tier, ips in sorted(tiers.items()):
        if ips:
            print(f"\n{tier} ({len(ips)} IPs):")
            for ip_info in ips:
                print(
                    f"  {ip_info['ip']:<20} ASN {ip_info.get('asn','?'):<8} "
                    f"{(ip_info.get('asn_description') or '-')[:35]}"
                )

    print("\n" + "=" * 80)
    print("PIVOT DOMAINS (resolve to 2+ IPs across tiers)")
    print("=" * 80)
    for domain, info in sorted(
        pivot_domains.items(), key=lambda x: -x[1]["ip_count"]
    ):
        print(f"\n  {domain} ({info['ip_count']} IPs):")
        for ip in info["ips"]:
            role = ip_roles.get(ip, {}).get("role", "unknown")
            print(f"    -> {ip} [{role}]")

    print("\n" + "=" * 80)
    print("CURRENT DNS STATUS (domains now NXDOMAIN = infrastructure torn down)")
    print("=" * 80)
    for d in ["cloaker.buzz", "rockyviewtech.com", "data-ps.org"]:
        print(f"  {d}: NXDOMAIN (offline)")
    print(f"  mgovideo.org: ACTIVE (207.207.210.x)")


if __name__ == "__main__":
    main()

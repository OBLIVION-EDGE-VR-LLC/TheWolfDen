#!/usr/bin/env python3
"""
02_whois_rdns_analysis.py
=========================
Performs reverse DNS lookups and WHOIS queries against all detected IPs
and key infrastructure IPs from the ShinyHunters PeopleSoft campaign.

Outputs:
    scripts/output/rdns_results.json     — reverse DNS for all detected IPs
    scripts/output/whois_results.json    — WHOIS/RDAP data for detected IPs
    scripts/output/ip_enrichment.json    — combined enrichment per IP

Requires: pip install ipwhois dnspython python-whois

Usage:
    python3 scripts/02_whois_rdns_analysis.py
"""

import json
import os
import socket
import time
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "scripts", "output")
os.makedirs(OUT, exist_ok=True)

# Attempt imports — graceful fallback
try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    print("[WARN] dnspython not installed — using socket for rDNS only")

try:
    from ipwhois import IPWhois
    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False
    print("[WARN] ipwhois not installed — WHOIS/RDAP lookups unavailable")

try:
    import whois as python_whois
    HAS_PYTHON_WHOIS = True
except ImportError:
    HAS_PYTHON_WHOIS = False
    print("[WARN] python-whois not installed — domain WHOIS unavailable")


def reverse_dns(ip):
    """Perform reverse DNS lookup using dnspython or socket fallback."""
    results = []
    # Socket-based rDNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        results.append({"source": "socket", "ptr": hostname})
    except (socket.herror, socket.gaierror, OSError):
        pass

    # dnspython-based rDNS for more detail
    if HAS_DNSPYTHON:
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                ptr = str(rdata).rstrip(".")
                if not any(r["ptr"] == ptr for r in results):
                    results.append({"source": "dnspython", "ptr": ptr})
        except Exception:
            pass

    return results


def whois_ip(ip):
    """Perform RDAP/WHOIS lookup for an IP address."""
    if not HAS_IPWHOIS:
        return None
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        return {
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description"),
            "asn_country_code": result.get("asn_country_code"),
            "network_name": result.get("network", {}).get("name"),
            "network_cidr": result.get("asn_cidr"),
            "network_start": result.get("network", {}).get("start_address"),
            "network_end": result.get("network", {}).get("end_address"),
            "entities": [
                {
                    "handle": e.get("handle"),
                    "name": (e.get("contact", {}) or {}).get("name"),
                    "kind": (e.get("contact", {}) or {}).get("kind"),
                    "address": (e.get("contact", {}) or {}).get("address"),
                }
                for e in (result.get("objects", {}) or {}).values()
                if isinstance(e, dict)
            ][:5],
        }
    except Exception as ex:
        return {"error": str(ex)}


def whois_domain(domain):
    """Perform WHOIS lookup for a domain."""
    if not HAS_PYTHON_WHOIS:
        return None
    try:
        w = python_whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": list(w.name_servers) if w.name_servers else None,
            "org": w.org,
            "country": w.country,
            "registrant": w.get("registrant_name") if hasattr(w, "get") else None,
        }
    except Exception as ex:
        return {"error": str(ex)}


def main():
    # Load detected IPs
    with open(os.path.join(OUT, "detected_ips.json")) as f:
        detected_ips = json.load(f)

    # Also add key infrastructure IPs from resolution analysis
    key_infra_ips = [
        "172.232.4.89",     # Linode — hosts subset.csv domains
        "172.233.218.191",  # Linode — hosts redirector domains
        "199.59.243.224",   # Hosts stamoutsos.com subdomains
        "5.199.162.157",    # Cherry Servers LT — cloaker.buzz
        "44.227.65.245",    # AWS — cloaker.buzz resolution
        "44.227.76.166",    # AWS — cloaker.buzz resolution
        "172.234.25.151",   # Linode — royalinsulationcanada.ca
        "172.234.26.236",   # Linode — royalinsulationcanada.ca
        "172.232.25.17",    # Linode — royalinsulationcanada.ca
        "162.255.119.199",  # royalinsulationcanada.ca
        "5.181.161.10",     # royalinsulationcanada.ca
        "52.211.245.146",   # royalinsulationcanada.ca (AWS)
    ]

    all_ips = list({ip["ip"] for ip in detected_ips} | set(key_infra_ips))
    # Filter out multicast / non-routable
    all_ips = [ip for ip in all_ips if not ip.startswith("239.")]

    print(f"Analyzing {len(all_ips)} IPs...\n")

    rdns_results = {}
    whois_results = {}
    enrichment = {}

    for i, ip in enumerate(sorted(all_ips)):
        print(f"[{i+1}/{len(all_ips)}] {ip}")

        # rDNS
        rdns = reverse_dns(ip)
        rdns_results[ip] = rdns
        ptrs = [r["ptr"] for r in rdns]
        print(f"  rDNS: {ptrs if ptrs else 'NXDOMAIN'}")

        # WHOIS/RDAP
        wh = whois_ip(ip)
        whois_results[ip] = wh
        if wh and "error" not in wh:
            print(f"  ASN: {wh.get('asn')} ({wh.get('asn_description')})")
            print(f"  Network: {wh.get('network_name')} [{wh.get('network_cidr')}]")
        elif wh:
            print(f"  WHOIS error: {wh.get('error', '')[:80]}")

        enrichment[ip] = {
            "ip": ip,
            "rdns": ptrs,
            "asn": wh.get("asn") if wh else None,
            "asn_description": wh.get("asn_description") if wh else None,
            "asn_country": wh.get("asn_country_code") if wh else None,
            "network_name": wh.get("network_name") if wh else None,
            "network_cidr": wh.get("network_cidr") if wh else None,
        }

        # Rate limit to be polite
        time.sleep(0.5)

    # Key domains WHOIS
    key_domains = [
        "cloaker.buzz",
        "rockyviewtech.com",
        "royalinsulationcanada.ca",
        "onlineect.org",
        "topgamse.com",
        "myexternalip.com",
        "crudepurple.xyz",
        "winmanage-me.network",
        "shconstmarket.com",
    ]

    domain_whois = {}
    print(f"\nAnalyzing {len(key_domains)} key domains...\n")
    for domain in key_domains:
        print(f"  WHOIS: {domain}")
        dw = whois_domain(domain)
        domain_whois[domain] = dw
        if dw and "error" not in dw:
            print(f"    Registrar: {dw.get('registrar')}")
            print(f"    Created: {dw.get('creation_date')}")
            print(f"    NS: {dw.get('name_servers')}")
        elif dw:
            print(f"    Error: {dw.get('error', '')[:80]}")
        time.sleep(1)

    # Write outputs
    with open(os.path.join(OUT, "rdns_results.json"), "w") as f:
        json.dump(rdns_results, f, indent=2, default=str)
    with open(os.path.join(OUT, "whois_results.json"), "w") as f:
        json.dump(whois_results, f, indent=2, default=str)
    with open(os.path.join(OUT, "ip_enrichment.json"), "w") as f:
        json.dump(enrichment, f, indent=2, default=str)
    with open(os.path.join(OUT, "domain_whois.json"), "w") as f:
        json.dump(domain_whois, f, indent=2, default=str)

    print(f"\nDone. Results in {OUT}/")

    # ── Summary table ────────────────────────────────────────────────────
    print("\n" + "=" * 90)
    print(f"{'IP':<20} {'ASN':<8} {'Provider':<30} {'rDNS':<30}")
    print("=" * 90)
    for ip in sorted(enrichment.keys()):
        e = enrichment[ip]
        rdns_str = e["rdns"][0] if e["rdns"] else "-"
        if len(rdns_str) > 28:
            rdns_str = rdns_str[:25] + "..."
        desc = (e["asn_description"] or "-")[:28]
        print(f"{ip:<20} {e['asn'] or '-':<8} {desc:<30} {rdns_str:<30}")


if __name__ == "__main__":
    main()

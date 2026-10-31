#!/usr/bin/env python3
"""
Black October 2026 — Weighted Vulnerability/Incident Ranking Engine

A multi-variable weighted scoring system for ranking cybersecurity incidents
and vulnerabilities. Each incident is scored across several dimensions, and
the weights can be tuned to reflect different organizational priorities.

By: Oblivion Edge Vulnerability Research LLC

Usage:
    python3 black_october_ranking.py                  # default weights
    python3 black_october_ranking.py --preset defender # defender-focused weights
    python3 black_october_ranking.py --preset attacker # attacker-focused weights
    python3 black_october_ranking.py --interactive     # tune weights interactively
"""

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Incident:
    name: str
    short_name: str

    # --- Scoring dimensions (each 0.0 to 10.0) ---

    # How many systems/people are in the blast radius?
    # 10 = millions of people or essentially every Linux server
    # 5 = thousands of orgs, tens of thousands of instances
    # 1 = niche product, small install base
    scope: float

    # CVSS-like technical severity. For non-CVE incidents (data leaks),
    # this reflects the sensitivity and completeness of exposed data.
    # 10 = unauthenticated RCE / full PII with SSNs on millions
    # 5 = authenticated RCE or partial data exposure
    # 1 = low-impact DoS or minor info leak
    severity: float

    # Is it being exploited in the wild right now?
    # 10 = mass exploitation confirmed, data already published
    # 7 = targeted exploitation by APT
    # 5 = PoC public, attempts observed
    # 2 = theoretical / lab only
    # 0 = no evidence
    exploitation: float

    # How hard is it to patch/fix RIGHT NOW?
    # 10 = no patch available for major distros, data already public (can't unpublish)
    # 7 = patch exists but major distros haven't shipped it
    # 5 = patch available, deployment is complex
    # 3 = patch available, straightforward
    # 1 = auto-patched by vendor (SaaS)
    patch_difficulty: float

    # Real-world impact beyond technical compromise.
    # 10 = physical safety of people at risk, national security
    # 7 = massive financial loss (>$50M), critical infrastructure
    # 5 = significant org-level damage
    # 3 = contained incident
    # 1 = theoretical risk only
    real_world_impact: float

    # How novel or instructive is this for the security community?
    # 10 = new attack class, paradigm shift (AI exploit generation, identity-layer-as-target)
    # 7 = old class in a critical new context
    # 5 = interesting chain or technique
    # 3 = routine n-day exploitation
    # 1 = nothing new
    novelty: float

    # Does this chain into or amplify other incidents on the list?
    # 10 = root cause of multiple other incidents
    # 7 = directly enables another top-10 entry
    # 5 = shares infrastructure/technique with others
    # 3 = minor connection
    # 0 = standalone
    interconnection: float

    # Metadata (not scored)
    cves: list = field(default_factory=list)
    cisa_kev: bool = False
    notes: str = ""


@dataclass
class WeightProfile:
    name: str
    description: str
    scope: float = 1.0
    severity: float = 1.0
    exploitation: float = 1.0
    patch_difficulty: float = 1.0
    real_world_impact: float = 1.0
    novelty: float = 1.0
    interconnection: float = 1.0


WEIGHT_PRESETS = {
    "default": WeightProfile(
        name="Default (Balanced)",
        description="Equal weight across all dimensions",
        scope=1.0, severity=1.0, exploitation=1.0,
        patch_difficulty=1.0, real_world_impact=1.0,
        novelty=1.0, interconnection=1.0,
    ),
    "defender": WeightProfile(
        name="Defender Priority",
        description="Weights what a SOC/IR team cares about: is it being exploited, can I patch it, how bad is the blast?",
        scope=1.5, severity=1.2, exploitation=2.0,
        patch_difficulty=1.8, real_world_impact=1.3,
        novelty=0.3, interconnection=0.5,
    ),
    "attacker": WeightProfile(
        name="Attacker Perspective",
        description="Weights what makes a bug attractive to exploit: scope, severity, difficulty to fix",
        scope=1.8, severity=1.5, exploitation=0.8,
        patch_difficulty=1.5, real_world_impact=0.5,
        novelty=1.2, interconnection=1.0,
    ),
    "policy": WeightProfile(
        name="Policy / Executive",
        description="Weights real-world impact, scope, and novelty for briefing leadership",
        scope=1.3, severity=0.8, exploitation=1.0,
        patch_difficulty=0.5, real_world_impact=2.0,
        novelty=1.5, interconnection=1.0,
    ),
    "researcher": WeightProfile(
        name="Security Researcher",
        description="Weights novelty, interconnection, and technical severity",
        scope=0.8, severity=1.5, exploitation=0.7,
        patch_difficulty=0.5, real_world_impact=0.8,
        novelty=2.0, interconnection=1.5,
    ),
}


# === THE DATA ===
# Each incident scored 0-10 on each dimension with justification in notes.

INCIDENTS = [
    Incident(
        name="DHS / CBP / ICE Employee Data Leak (41,000+ agents)",
        short_name="DHS/ICE Leak",
        scope=7.0,       # 41K federal agents — not millions, but the *who* matters enormously
        severity=9.0,     # Full PII: names, phones, titles, office locations, operational roles
        exploitation=10.0, # Data is published and searchable on icepick.is RIGHT NOW
        patch_difficulty=10.0, # You cannot unpublish doxxed identities. Damage is irreversible.
        real_world_impact=10.0, # Physical safety of federal law enforcement officers at risk
        novelty=8.0,      # Identity-layer-as-target; SSO directory exfiltration is a paradigm example
        interconnection=8.0, # Directly connected to Okta Access Gateway bugs
        cves=[], cisa_kev=False,
        notes="Not a CVE — a data exposure via Okta SSO. Irreversible harm to 41K+ people.",
    ),
    Incident(
        name="Pentagon / DMDC Breach (3+ million military/civilian records)",
        short_name="Pentagon/DMDC",
        scope=9.5,        # 2.76M-4M people — an order of magnitude larger than DHS
        severity=9.5,     # SSNs, DOBs, military specialties, unencrypted
        exploitation=7.0,  # Data stolen; no evidence of public availability like icepick.is
        patch_difficulty=9.0, # Data already exfiltrated; can't un-steal SSNs. Access ran 9 months.
        real_world_impact=9.5, # Military personnel records, national security implications
        novelty=4.0,      # File-sharing vulnerability, unencrypted data — depressingly routine
        interconnection=3.0, # Standalone incident, different vector from DHS/Okta
        cves=[], cisa_kev=False,
        notes="Disclosed Sept 18, access Oct 2025-Jul 2026. Records NOT encrypted. Not publicly searchable.",
    ),
    Incident(
        name="ShinyHunters vs. FBI / PeopleSoft (CVE-2026-35273)",
        short_name="ShinyHunters",
        scope=8.0,        # PeopleSoft is everywhere: gov, edu, healthcare, enterprise
        severity=9.8,     # CVSS 9.8, unauth RCE, mass exploitation
        exploitation=9.5,  # Active mass exploitation since May; WAF bypass in Sept
        patch_difficulty=5.0, # Patch available since June 10; the problem is orgs not applying it
        real_world_impact=9.0, # FBI breach, $70M+ extortion, 100+ victims, negotiator arrested
        novelty=7.0,      # WAF bypass via percent-encoding is a textbook-quality example
        interconnection=5.0, # Connected to FBI, extortion economy, contractor trust
        cves=["CVE-2026-35273"], cisa_kev=True,
        notes="$70M+ extorted in 2026. WAF bypass (%50SEMHUB) is a teaching example.",
    ),
    Incident(
        name="Linux Kernel TCP UAF (CVE-2026-98432)",
        short_name="Linux TCP UAF",
        scope=10.0,       # Every Linux server, container, VM, IoT device with a TCP socket
        severity=9.8,     # CVSS 9.8, remote, unauthenticated, no user interaction
        exploitation=4.0,  # Anthropic lab claim (unverified); no in-the-wild exploitation confirmed
        patch_difficulty=8.0, # Upstream fixed but RHEL and Ubuntu don't have stable patches yet
        real_world_impact=7.0, # Potential is catastrophic but no confirmed real-world damage yet
        novelty=8.0,      # AI-generated exploit claim; kernel TCP UAF; affects the entire cloud
        interconnection=3.0, # Standalone kernel bug
        cves=["CVE-2026-98432"], cisa_kev=False,
        notes="RHEL/Ubuntu unpatched as of Oct 30. Anthropic AI exploit claim unverified by others.",
    ),
    Incident(
        name="PHP2Shell (CVE-2026-109618, CVE-2026-109619)",
        short_name="PHP2Shell",
        scope=9.5,        # PHP runs ~75% of dynamic websites
        severity=9.2,     # CVSS v4 9.2, RCE + Heartbleed-style memory disclosure
        exploitation=8.0,  # Active exploitation within 19 min of patch; Sophos confirms success
        patch_difficulty=6.0, # Patches available but distro version traps; worker restarts needed
        real_world_impact=7.5, # Memory disclosure can steal secrets; RCE on any PHP site
        novelty=7.0,      # Heartbleed-shaped memory leak + RCE; fires before app code
        interconnection=7.0, # Affects Okta Access Gateway, BeyondTrust (SAWFLY is PHP)
        cves=["CVE-2026-109618", "CVE-2026-109619"], cisa_kev=True,
        notes="Added to KEV Oct 26. 19 minutes from patch to exploitation attempts.",
    ),
    Incident(
        name="Okta Access Gateway (CVE-2026-115547, CVE-2026-115546)",
        short_name="Okta Gateway",
        scope=6.0,        # Large enterprise install base but not as ubiquitous as PHP/Linux
        severity=9.1,     # Command execution + auth bypass chain to full gateway control
        exploitation=3.0,  # No confirmed in-the-wild exploitation yet
        patch_difficulty=4.0, # Patch available (2026.10.2); single update fixes all four CVEs
        real_world_impact=8.0, # Gateway controls access to everything behind it; DHS connection
        novelty=7.0,      # Auth bypass → admin assertion → cmd exec chain; PHP2Shell underneath
        interconnection=9.0, # Connected to DHS leak, PHP2Shell, identity-as-target theme
        cves=["CVE-2026-115547", "CVE-2026-115546"], cisa_kev=False,
        notes="Four CVEs in one advisory including PHP2Shell. DHS Okta SSO is the same vendor.",
    ),
    Incident(
        name="Citrix NetScaler ADC/Gateway (CVE-2026-88771/72/79)",
        short_name="Citrix NetScaler",
        scope=7.0,        # Widely deployed in enterprise; 5th year in a row on a vuln list
        severity=9.5,     # CVSS v4 9.5, unauthenticated command execution
        exploitation=9.0,  # KEV since Sep 27, global exploitation confirmed
        patch_difficulty=5.5, # Patches available but require multiple rounds (Sep + Oct)
        real_world_impact=7.0, # VPN/gateway compromise = full network access
        novelty=4.0,      # NetScaler vulns are a recurring theme; DoS-to-RCE chain is clever
        interconnection=3.0, # Standalone, but part of the edge-device pattern
        cves=["CVE-2026-88771", "CVE-2026-88772", "CVE-2026-88779"], cisa_kev=True,
        notes="DoS (88779) used to activate RCE payload from 88771. Patch twice.",
    ),
    Incident(
        name="BeyondTrust Remote Support (CVE-2026-102764)",
        short_name="BeyondTrust",
        scope=5.0,        # 1,400+ exposed instances; niche product but high-value targets
        severity=9.8,     # CVSS 9.8, auth bypass to full control + downstream systems
        exploitation=8.0,  # PRC-nexus espionage since August; confirmed by Mandiant
        patch_difficulty=6.0, # Patch available but persistence survives config reset; rebuild needed
        real_world_impact=8.0, # Espionage tool; every downstream system the appliance touched
        novelty=6.0,      # SUID abuse for priv esc; persistence surviving reset is notable
        interconnection=5.0, # SAWFLY is PHP (connects to PHP2Shell); part of edge-device pattern
        cves=["CVE-2026-102764"], cisa_kev=True,
        notes="ARMORY CASTLE / Warp Panda (PRC). Persistence survives reboot AND config reset.",
    ),
    Incident(
        name="Fortinet FortiMail (CVE-2026-104286)",
        short_name="FortiMail",
        scope=6.0,        # Widely deployed mail gateway
        severity=9.8,     # CVSS 9.8, unauth arbitrary file write
        exploitation=8.5,  # KEV Oct 1 with 3-day deadline; exploited in the wild
        patch_difficulty=5.0, # Patches available for most branches; 7.2 must upgrade to 7.4+
        real_world_impact=7.0, # Mail gateway = access to all email + pivot point
        novelty=6.0,      # NULL byte + path traversal + ld.so.preload — old techniques, new target
        interconnection=4.0, # Part of the canonicalization-bug pattern
        cves=["CVE-2026-104286"], cisa_kev=True,
        notes="NULL byte bypass (validate-then-canonicalize). ld.so.preload hijack for persistence.",
    ),
    Incident(
        name="PAN-OS Management Interface RCE (CVE-2026-0322)",
        short_name="PAN-OS",
        scope=6.0,        # Major firewall vendor; Cloud NGFW/Prisma unaffected
        severity=7.0,     # Critical, but requires valid credentials
        exploitation=7.0,  # KEV with 3-day deadline; exploited in the wild
        patch_difficulty=4.0, # Patch available; main fix is "don't expose mgmt interface"
        real_world_impact=7.0, # Firewall compromise = full network control
        novelty=3.0,      # Authenticated RCE on a management interface — seen before
        interconnection=3.0, # Part of edge-device pattern
        cves=["CVE-2026-0322"], cisa_kev=True,
        notes="Requires valid credentials. 3 attacker IPs published. Never expose mgmt interface.",
    ),
    Incident(
        name="Atlassian Multi-Product Access Flaw (CVE-2026-21589)",
        short_name="Atlassian",
        scope=7.0,        # Confluence + Jira = most engineering orgs
        severity=6.0,     # Critical per advisory but sparse public details
        exploitation=6.0,  # KEV Oct 15; exploited but few details
        patch_difficulty=4.0, # Patch per Atlassian advisory; straightforward
        real_world_impact=6.0, # Access to eng docs, project plans, stored creds in wikis
        novelty=2.0,      # Access flaw in Atlassian — this is a recurring category
        interconnection=2.0, # Standalone
        cves=["CVE-2026-21589"], cisa_kev=True,
        notes="Sparse public technical details. Audit for new admin accounts and API tokens.",
    ),
    Incident(
        name="Microsoft Windows MotW Bypass (CVE-2026-96951)",
        short_name="Windows MotW",
        scope=8.0,        # Every Windows machine
        severity=8.8,     # CVSS 8.8, security feature bypass
        exploitation=6.0,  # One exploited zero-day in a record 1,413-CVE release
        patch_difficulty=3.0, # October cumulative update; auto-deployed via WSUS/WU
        real_world_impact=5.0, # MotW bypass enables malware delivery but requires user interaction
        novelty=3.0,      # MotW bypasses are a recurring category
        interconnection=2.0, # Standalone
        cves=["CVE-2026-96951"], cisa_kev=False,
        notes="Details from low-quality source. Confirm against MSRC. Record 1,413-CVE Patch Tuesday.",
    ),
    Incident(
        name="Collabora Online RCE (CVE-2026-110447)",
        short_name="Collabora Online",
        scope=4.0,        # Niche: self-hosted LibreOffice in the browser
        severity=9.8,     # CVSS 9.8
        exploitation=5.0,  # In KEV (unverified against primary source)
        patch_difficulty=4.0, # Patch presumably available
        real_world_impact=4.0, # Document editing compromise
        novelty=3.0,      # Routine
        interconnection=1.0, # Standalone
        cves=["CVE-2026-110447"], cisa_kev=True,
        notes="KEV addition unverified against primary source. Treat with caution.",
    ),
    Incident(
        name="JetBrains TeamCity (CVE-2026-63077)",
        short_name="TeamCity",
        scope=5.0,        # CI/CD pipeline — high-value target for supply chain
        severity=7.0,     # Critical but details sparse
        exploitation=6.0,  # Ransomware-linked per KEV roundup
        patch_difficulty=4.0, # Patch available
        real_world_impact=7.0, # CI/CD compromise = supply chain risk
        novelty=4.0,      # TeamCity CVEs are recurring
        interconnection=3.0, # Supply chain connection
        cves=["CVE-2026-63077"], cisa_kev=True,
        notes="Ransomware-linked. CI/CD compromise is a supply chain multiplier.",
    ),
]


def score_incident(incident: Incident, weights: WeightProfile) -> float:
    dimensions = {
        "scope": incident.scope,
        "severity": incident.severity,
        "exploitation": incident.exploitation,
        "patch_difficulty": incident.patch_difficulty,
        "real_world_impact": incident.real_world_impact,
        "novelty": incident.novelty,
        "interconnection": incident.interconnection,
    }
    weight_values = {
        "scope": weights.scope,
        "severity": weights.severity,
        "exploitation": weights.exploitation,
        "patch_difficulty": weights.patch_difficulty,
        "real_world_impact": weights.real_world_impact,
        "novelty": weights.novelty,
        "interconnection": weights.interconnection,
    }
    weighted_sum = sum(dimensions[k] * weight_values[k] for k in dimensions)
    weight_total = sum(weight_values.values())
    return weighted_sum / weight_total if weight_total > 0 else 0.0


def rank_incidents(incidents: list, weights: WeightProfile) -> list:
    scored = [(inc, score_incident(inc, weights)) for inc in incidents]
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored


def print_ranking(scored: list, weights: WeightProfile, top_n: Optional[int] = None):
    print(f"\n{'='*80}")
    print(f"  BLACK OCTOBER 2026 — WEIGHTED RANKING")
    print(f"  Profile: {weights.name}")
    print(f"  {weights.description}")
    print(f"{'='*80}")
    print()

    w = weights
    print(f"  Weights: scope={w.scope:.1f}  severity={w.severity:.1f}  "
          f"exploitation={w.exploitation:.1f}  patch_difficulty={w.patch_difficulty:.1f}")
    print(f"           real_world_impact={w.real_world_impact:.1f}  "
          f"novelty={w.novelty:.1f}  interconnection={w.interconnection:.1f}")
    print()

    display = scored[:top_n] if top_n else scored
    max_name_len = max(len(s[0].short_name) for s in display)

    print(f"  {'Rank':<5} {'Name':<{max_name_len+2}} {'Score':>6}  "
          f"{'Scope':>5} {'Sev':>5} {'Expl':>5} {'Patch':>5} {'Impact':>6} {'Novel':>5} {'Inter':>5}  {'KEV':>3}")
    print(f"  {'─'*4}  {'─'*(max_name_len+1)} {'─'*6}  "
          f"{'─'*5} {'─'*5} {'─'*5} {'─'*5} {'─'*6} {'─'*5} {'─'*5}  {'─'*3}")

    for rank, (inc, score) in enumerate(display, 1):
        kev = "YES" if inc.cisa_kev else " - "
        print(f"  #{rank:<4} {inc.short_name:<{max_name_len+2}} {score:>6.2f}  "
              f"{inc.scope:>5.1f} {inc.severity:>5.1f} {inc.exploitation:>5.1f} "
              f"{inc.patch_difficulty:>5.1f} {inc.real_world_impact:>6.1f} "
              f"{inc.novelty:>5.1f} {inc.interconnection:>5.1f}  {kev:>3}")

    print()


def print_comparison(incidents: list):
    print(f"\n{'='*80}")
    print(f"  RANKING COMPARISON ACROSS ALL PROFILES")
    print(f"{'='*80}\n")

    all_rankings = {}
    for preset_name, weights in WEIGHT_PRESETS.items():
        scored = rank_incidents(incidents, weights)
        all_rankings[preset_name] = {inc.short_name: rank
                                     for rank, (inc, _) in enumerate(scored, 1)}

    header_names = list(WEIGHT_PRESETS.keys())
    max_name_len = max(len(inc.short_name) for inc in incidents)
    col_w = 12

    print(f"  {'Incident':<{max_name_len+2}}", end="")
    for name in header_names:
        label = WEIGHT_PRESETS[name].name.split("(")[0].strip()[:col_w]
        print(f" {label:>{col_w}}", end="")
    print(f" {'  Variance':>10}")

    print(f"  {'─'*(max_name_len+1)}", end="")
    for _ in header_names:
        print(f" {'─'*col_w}", end="")
    print(f" {'─'*10}")

    default_scored = rank_incidents(incidents, WEIGHT_PRESETS["default"])
    for inc, _ in default_scored:
        ranks = [all_rankings[p][inc.short_name] for p in header_names]
        variance = max(ranks) - min(ranks)
        print(f"  {inc.short_name:<{max_name_len+2}}", end="")
        for r in ranks:
            print(f" #{r:<{col_w-1}}", end="")
        indicator = " ◄ VOLATILE" if variance >= 4 else ""
        print(f" {variance:>6}{indicator}")

    print()
    print("  'Volatile' incidents shift 4+ ranks depending on perspective.")
    print("  These are the ones where reasonable people disagree on severity.\n")


def interactive_weights() -> WeightProfile:
    print("\n  INTERACTIVE WEIGHT TUNING")
    print("  Set each weight from 0.0 to 3.0 (1.0 = normal, 2.0 = double importance, 0.0 = ignore)\n")

    dims = [
        ("scope",            "Scope (how many systems/people affected)"),
        ("severity",         "Technical Severity (CVSS-like)"),
        ("exploitation",     "Active Exploitation (is it being used now?)"),
        ("patch_difficulty",  "Patch Difficulty (how hard is it to fix?)"),
        ("real_world_impact", "Real-World Impact (beyond technical compromise)"),
        ("novelty",          "Novelty (how instructive/new is this?)"),
        ("interconnection",  "Interconnection (does it chain into other incidents?)"),
    ]

    values = {}
    for key, desc in dims:
        while True:
            try:
                raw = input(f"  {desc} [1.0]: ").strip()
                val = float(raw) if raw else 1.0
                if 0.0 <= val <= 3.0:
                    values[key] = val
                    break
                print("    Please enter a value between 0.0 and 3.0")
            except ValueError:
                print("    Please enter a number")

    return WeightProfile(name="Custom", description="User-defined weights", **values)


def export_json(scored: list, weights: WeightProfile, path: str):
    data = {
        "profile": asdict(weights),
        "ranking": [
            {
                "rank": rank,
                "name": inc.name,
                "short_name": inc.short_name,
                "score": round(score, 3),
                "dimensions": {
                    "scope": inc.scope,
                    "severity": inc.severity,
                    "exploitation": inc.exploitation,
                    "patch_difficulty": inc.patch_difficulty,
                    "real_world_impact": inc.real_world_impact,
                    "novelty": inc.novelty,
                    "interconnection": inc.interconnection,
                },
                "cves": inc.cves,
                "cisa_kev": inc.cisa_kev,
                "notes": inc.notes,
            }
            for rank, (inc, score) in enumerate(scored, 1)
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n  Exported to {path}")


def main():
    parser = argparse.ArgumentParser(description="Black October 2026 Weighted Ranking Engine")
    parser.add_argument("--preset", choices=list(WEIGHT_PRESETS.keys()),
                        default="default", help="Weight preset to use")
    parser.add_argument("--all", action="store_true",
                        help="Show rankings for all presets")
    parser.add_argument("--compare", action="store_true",
                        help="Show side-by-side ranking comparison across all presets")
    parser.add_argument("--interactive", action="store_true",
                        help="Interactively set custom weights")
    parser.add_argument("--top", type=int, default=None,
                        help="Show only top N incidents")
    parser.add_argument("--export", type=str, default=None,
                        help="Export ranking to JSON file")

    args = parser.parse_args()

    if args.interactive:
        weights = interactive_weights()
        scored = rank_incidents(INCIDENTS, weights)
        print_ranking(scored, weights, args.top)
        if args.export:
            export_json(scored, weights, args.export)
        return

    if args.compare:
        print_comparison(INCIDENTS)
        return

    if args.all:
        for preset_name, weights in WEIGHT_PRESETS.items():
            scored = rank_incidents(INCIDENTS, weights)
            print_ranking(scored, weights, args.top)
        print_comparison(INCIDENTS)
        return

    weights = WEIGHT_PRESETS[args.preset]
    scored = rank_incidents(INCIDENTS, weights)
    print_ranking(scored, weights, args.top)
    if args.export:
        export_json(scored, weights, args.export)


if __name__ == "__main__":
    main()

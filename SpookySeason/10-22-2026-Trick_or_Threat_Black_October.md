# Trick or Threat 🎃: Black October and the Haunted Patch Queue

![Happy Halloween — Black October 2026](./HappyHalloween.png)

## A technical post-mortem of 22 September – 31 October 2026: one extortion crew, one runtime, a kernel zero-day, an identity provider, three edge-device zero-days, 41,000 federal agents exposed, 3 million Pentagon records stolen, and how to stop leaving the porch light on

**By Oblivion Edge Vulnerability Research**

*"Double, double toil and trouble; fire burn and cauldron bubble."*
--- The Witches, *Macbeth*, Act IV, Scene 1

> **Spooky season disclaimer.** "Black October" is the name *we* are using for the 40-day window covered here. It is not a vendor's or government's label. Every CVE, date, and claim below links back to a source in [§17](#17-references). Where the sources disagree, the post says so instead of picking whichever version is scarier.

---

**October is Cybersecurity Awareness Month.** Every year the industry asks people to use strong passwords and enable MFA. This year the internet answered with a live demonstration of what happens when you don't: a federal law-enforcement agency had its workforce doxxed through an SSO directory, the language runtime under half the web got a Heartbleed-shaped memory bug, the Linux kernel shipped a use-after-free reachable over a TCP handshake, and edge appliances from Citrix, Fortinet, BeyondTrust, and Palo Alto all handed out remote shells to anyone who asked politely.

**Cybersecurity Awareness Month 2026 isn't awareness. It's a haunted house, and every room has a new zero-day. Welcome to Black October. Welcome to SPOOKY SEASON.** 🎃🦇👻

---

## Table of Contents

0. [TL;DR — The Black October Scoreboard](#0-tldr--the-black-october-scoreboard)
1. [The 40-Day Timeline](#1-the-40-day-timeline)
2. [How We Ranked These: The Weighted Scoring Engine](#2-how-we-ranked-these-the-weighted-scoring-engine)
3. [#1 — DHS/CBP/ICE: 41,000 Federal Agents Unmasked](#3-1--dhscbpice-41000-federal-agents-unmasked)
4. [#2 — The Pentagon / DMDC: 3 Million Military Records Stolen](#4-2--the-pentagon--dmdc-3-million-military-records-stolen)
5. [#3 — ShinyHunters: The Headless Horseman Rides Into the FBI](#5-3--shinyhunters-the-headless-horseman-rides-into-the-fbi)
6. [#4 — Linux Kernel TCP: The Floor Is Lava (CVE-2026-98432)](#6-4--linux-kernel-tcp-the-floor-is-lava-cve-2026-98432)
7. [#5 — PHP2Shell: The Call Is Coming From Inside the Runtime](#7-5--php2shell-the-call-is-coming-from-inside-the-runtime)
8. [#6 — Okta Access Gateway: The Key Master](#8-6--okta-access-gateway-the-key-master)
9. [#7 — Citrix NetScaler: The Gateway Ghost (Again)](#9-7--citrix-netscaler-the-gateway-ghost-again)
10. [#8 — BeyondTrust Remote Support: The Butler Did It](#10-8--beyondtrust-remote-support-the-butler-did-it)
11. [#9 — Fortinet FortiMail: Something Wicked Through the Mail Slot](#11-9--fortinet-fortimail-something-wicked-through-the-mail-slot)
12. [#10 — PAN-OS: The Firewall That Let You In](#12-10--pan-os-the-firewall-that-let-you-in)
13. [Honorable (Dis)Mentions](#13-honorable-dismentions)
14. [Patterns in the Graveyard: What Black October Teaches](#14-patterns-in-the-graveyard-what-black-october-teaches)
15. [Theme: Modernizing the Haunted House (Nginx, Config, IP Limiting, DoS)](#15-theme-modernizing-the-haunted-house)
16. [Theme: Data at Rest and in Transit — Lessons From the Fortress of Solitude](#16-theme-data-at-rest-and-in-transit--lessons-from-the-fortress-of-solitude)
17. [The Exorcism Checklist](#17-the-exorcism-checklist)
18. [References](#18-references)

---

## 0. TL;DR — The Black October Scoreboard

| Rank | Name | Identifier(s) | Bug class | Severity | Exploited in the wild? | CISA KEV | Real fix |
|---|---|---|---|---|---|---|---|
| **#1** | **DHS / CBP / ICE Employee Leak** | N/A (Okta SSO directory exfiltration) | Identity directory exposure via SSO compromise | **41,000+ federal employees unmasked** | **Yes** — published Oct 28 | N/A | Okta SSO hardening; directory access controls; see §3 |
| **#2** | **Pentagon / DMDC Breach** | N/A (file-sharing system vulnerability) | Personnel records exfiltration; unencrypted data at rest | **3+ million military/civilian records** (SSNs, DOBs, military specialties) | **Yes** — unauthorized access Oct 2025 – Jul 2026 | N/A | Encrypt data at rest; file-sharing access controls; see §4 |
| **#3** | **ShinyHunters** vs. Oracle PeopleSoft (incl. FBI Jobs) | CVE-2026-35273 + a claimed second PeopleSoft 0-day | Unauth flaw in the PSEMHUB servlet chained to RCE; WAF bypass by percent-encoding | CVSS 9.8 | **Yes** — mass exploitation, renewed late Sept | Yes (earlier in 2026) | Oracle's June 10 patch; remove/disable PSEMHUB |
| **#4** | **Linux Kernel TCP UAF** | CVE-2026-98432 | Use-after-free in IPv4 TCP handshake (net/ipv4/tcp) | CVSS **9.8** | **Not yet in KEV** — Anthropic claims lab exploit; not reproduced publicly | Not yet | Upstream fix in mainline; RHEL/Ubuntu patches pending |
| **#5** | **PHP2Shell** | CVE-2026-109618, CVE-2026-109619 | OOM-bailout memory corruption; stale global state → UAF | CVSS v4 9.2 (both) | **Yes** — KEV Oct 26; Sophos confirms successful exploitation | Yes — Oct 26 | PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 |
| **#6** | **Okta Access Gateway** | CVE-2026-115547, CVE-2026-115546 | Command exec via admin console; auth bypass / SAML assertion escalation | CVSS 9.1 / 8.1 | **Not yet confirmed** | Not yet | Okta Access Gateway 2026.10.2 |
| **#7** | **Citrix NetScaler ADC/Gateway** | CVE-2026-88771, -88772, -88779 (+ more) | Input validation → command exec; memory overflow (DTLS); memory overflow (SAML) | 88772 = CVSS v4 9.5 | **Yes** — global | Yes — Sep 27 & Oct 4 | Citrix fixed builds (see §9) |
| **#8** | **BeyondTrust Remote Support** | CVE-2026-102764 (BT26-05) | Auth bypass (CWE-290) → file operations → web shell | CVSS v4 9.3 / NVD v3.1 9.8 | **Yes** — China-nexus espionage since late Aug | Reported Oct 16 | BT26-05 patch |
| **#9** | **Fortinet FortiMail** | CVE-2026-104286 (FG-IR-26-175) | Path traversal + NULL byte → unauth arbitrary file write | CVSS 9.8 | **Yes** | Yes — Oct 1 | 8.0.2 / 7.6.7 / 7.4.9; disable IBE meanwhile |
| **#10** | **PAN-OS** | CVE-2026-0322 | Authenticated RCE on management interface | Critical (3-day KEV deadline) | **Yes** | Yes — Oct 14 | Patch per Palo Alto advisory; restrict mgmt interface |

**The one-sentence version:** Every major incident this month got in through either a web-facing component that sits in front of something valuable, or the identity/personnel infrastructure that tells the web-facing component who you are. In two cases (#1 and #2), the data was *the people themselves* — not their passwords, not their systems, but their identities, their SSNs, their home assignments. Cybersecurity Awareness Month got the awareness it deserved.

---

## 1. The 40-Day Timeline

```mermaid
timeline
    title Black October (22 Sep – 31 Oct 2026) 🎃
    Sep 18 : Pentagon discloses DMDC breach — 3+ million military/civilian records stolen (access Oct 2025 – Jul 2026)
    Sep 15 : Dutch police arrest alleged senior ShinyHunters member
    Sep 22 : ShinyHunters claims FBI Jobs (PeopleSoft) breach
    Late Sep : Mandiant/GTIG - renewed PeopleSoft mass exploitation with /%50SEMHUB/ WAF bypass
    Sep 27 : Citrix NetScaler CVE-2026-88771/88772 added to KEV
    Oct 1 : FortiMail CVE-2026-104286 disclosed and added to KEV
    Oct 3 : "Rey" reportedly detained in Jordan, cooperating
    Oct 4 : Citrix CVE-2026-88779 (SAML DoS) added to KEV
    Oct 6 : FBI blames contractor's missed PeopleSoft patch
    Oct 8 : BeyondTrust patches SaaS for CVE-2026-102764
    Oct 9 : Ransomware negotiator Edward Dubrovsky arrested
    Oct 14 : PAN-OS CVE-2026-0322 disclosed (KEV, 3-day deadline)
    Oct 15 : BeyondTrust BT26-05 public; Atlassian CVE-2026-21589 to KEV; CVE-2026-98432 (Linux TCP) published
    Oct 16 : Shinywire extortion site goes dark; BeyondTrust to KEV (reported)
    Oct 17 : First PHP2Shell attempt in Amazon telemetry (pre-disclosure)
    Oct 20 : PHP2Shell leak + accidental PoC video
    Oct 21 : PHP ships 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; exploitation attempts within ~19 minutes
    Oct 22 : Okta discloses CVE-2026-115547 + CVE-2026-115546 in Access Gateway (also bundles PHP2Shell fixes)
    Oct 24 : CVE-2026-98432 (Linux TCP) re-scored to CVSS 9.8
    Oct 27 : Anthropic claims AI-generated remote-root exploit for CVE-2026-98432
    Oct 28 : DDoSecrets publishes 41,000+ DHS/CBP/ICE employee records ("Icepick")
    Oct 30 : Red Hat publishes RHSB-2026-016 for Linux TCP; AlmaLinux ships patched test kernels
    Oct 31 : 🎃 Happy Halloween — Black October ends, the patch queue does not
```

---

## 2. How We Ranked These: The Weighted Scoring Engine

> *"You can't manage what you can't measure." — But you can sure argue about what to measure.*

With this many simultaneous incidents, a gut-feeling ranking isn't enough. We built a **multi-variable weighted scoring engine** ([`black_october_ranking.py`](./black_october_ranking.py)) that scores each incident across seven dimensions and lets you re-rank based on your perspective.

### The seven dimensions (each scored 0–10)

| Dimension | What it measures |
|---|---|
| **Scope** | How many systems or people are in the blast radius? |
| **Technical Severity** | CVSS-like severity; for data leaks, sensitivity and completeness of exposed data |
| **Active Exploitation** | Is it being used right now? Published data? Mass exploitation? |
| **Patch Difficulty** | How hard is it to fix RIGHT NOW? (Can't unpublish doxxed identities = 10) |
| **Real-World Impact** | Beyond technical compromise — physical safety, national security, financial loss |
| **Novelty** | How new or instructive is this for the security community? |
| **Interconnection** | Does this chain into or amplify other incidents on the list? |

### Rankings shift by perspective

We ran five weight profiles (defender, attacker, policy, researcher, balanced) and found:

- **DHS/ICE Leak is #1 across ALL five perspectives.** Not close. When your data is already published and you can't unpublish doxxed identities, every dimension scores high.
- **Pentagon/DMDC is volatile** — it ranges from #2 (defender priority) to #8 (researcher). Massive scope but low novelty (unencrypted data + file-sharing vuln is depressingly routine).
- **Okta Access Gateway is volatile** — researchers rank it #4 (interconnection story is fascinating) while defenders rank it #9 (no confirmed exploitation yet).
- **ShinyHunters holds steady at #2–#5** across all perspectives. The WAF bypass and extortion economy keep it relevant everywhere.

### The core scoring logic

```python
@dataclass
class Incident:
    name: str
    scope: float          # 0-10: how many systems/people affected
    severity: float       # 0-10: CVSS-like technical severity
    exploitation: float   # 0-10: is it being exploited right now?
    patch_difficulty: float  # 0-10: how hard to fix TODAY?
    real_world_impact: float # 0-10: beyond technical (physical safety, national security)
    novelty: float        # 0-10: how new/instructive for the community?
    interconnection: float   # 0-10: chains into other incidents?

@dataclass
class WeightProfile:
    name: str
    scope: float = 1.0
    severity: float = 1.0
    exploitation: float = 1.0
    patch_difficulty: float = 1.0
    real_world_impact: float = 1.0
    novelty: float = 1.0
    interconnection: float = 1.0

def score_incident(incident: Incident, weights: WeightProfile) -> float:
    dims = ["scope", "severity", "exploitation", "patch_difficulty",
            "real_world_impact", "novelty", "interconnection"]
    weighted_sum = sum(getattr(incident, d) * getattr(weights, d) for d in dims)
    weight_total = sum(getattr(weights, d) for d in dims)
    return weighted_sum / weight_total

# Example: Defender profile (SOC/IR priorities)
defender = WeightProfile(
    name="Defender",
    scope=1.5, severity=1.2, exploitation=2.0,  # "is it being used NOW?"
    patch_difficulty=1.8, real_world_impact=1.3,  # "can I fix it?"
    novelty=0.3, interconnection=0.5,             # less relevant to a SOC
)
```

The full engine includes five preset profiles (balanced, defender, attacker, policy/executive, researcher), 14 incidents with detailed scoring justifications, interactive weight tuning, and a JSON export for piping into dashboards.

Run it yourself:

```bash
python3 black_october_ranking.py --all        # all five perspectives
python3 black_october_ranking.py --compare    # side-by-side ranking comparison
python3 black_october_ranking.py --interactive # tune your own weights
python3 black_october_ranking.py --preset defender --top 10 --export ranking.json
```

---

## 3. #1 — DHS/CBP/ICE: 41,000 Federal Agents Unmasked

> *"The call is coming from inside the directory."*

This is ranked #1 because the blast radius isn't measured in servers or CVSS scores. It's measured in **human lives**. When the identities of 41,000 federal law-enforcement officers — including undercover investigators, border agents, and ICE officers — are published in a searchable database, the threat isn't code execution. It's **physical safety**. Our [weighted ranking engine](#2-how-we-ranked-these-the-weighted-scoring-engine) scored this #1 across **all five perspectives** — defender, attacker, policy, researcher, and balanced. No other incident this month comes close.

### 3.1 What happened

On **October 28, 2026**, the nonprofit Distributed Denial of Secrets (DDoSecrets) published a searchable database of more than **41,000 DHS employees and contractors**. A hacktivist group calling itself the **"Department of Peace"** claimed credit. Their stated motive: a response to ICE operations.

| Component | Approximate count |
|---|---|
| **CBP** (Customs and Border Protection) | ~21,329 |
| **ICE** (Immigration and Customs Enforcement) | ~6,598 |
| **USCIS** (Citizenship and Immigration Services) | ~6,245 |
| **HSI** (Homeland Security Investigations) | ~3,421 |
| **Other DHS agencies** | Remainder |

**What leaked:** Names, phone numbers, job titles, office locations, and assignments. Some entries reportedly reveal associations with surveillance tools or sensitive operational functions. This isn't a credential dump — it's worse. It's a **personnel directory** for the federal government's enforcement arm.

**The attack vector:** Multiple sources report the records were exfiltrated from an **Okta single sign-on (SSO) system** that DHS uses. That makes this a *directory leak* — the attacker didn't need to break into individual systems. They compromised the identity layer, and the identity layer knew where everyone sat.

> **Why this is #1:** ShinyHunters stole files from one agency's jobs portal. This leak exposed the *identities and locations* of officers across the entire Department of Homeland Security — including people whose safety depends on not being publicly identified. A CVE can be patched. A burned cover identity cannot be unburned. The damage here is **irreversible**.

### 3.2 The Okta connection

This incident and [#5 (Okta Access Gateway)](#6-5--okta-access-gateway-the-key-master) are two faces of the same architectural problem: **the identity provider is the crown jewel, and it's being treated like plumbing.**

DHS's Okta instance was the source of this breach. Okta Access Gateway shipped critical CVEs (including command execution and an auth bypass) on the *same week*. The PHP runtime underneath Okta Access Gateway was itself vulnerable to PHP2Shell (#4). Stack the layers:

```text
PHP runtime (PHP2Shell)
  └── Okta Access Gateway (CVE-2026-115547 cmd exec, CVE-2026-115546 auth bypass)
       └── Okta SSO directory (DHS employee records)
            └── 41,000 federal agents' identities → published
```

When your identity layer is built on a gateway that's built on a runtime that's built on C, every layer's bug is the identity layer's bug.

### 3.3 The context: this is the second time

In January 2026, a site called "ICE List" published data on about 4,500 ICE agents. That site was eventually taken down. Eight months later, the same category of data leaked again, at **nine times the scale**, from a different source. The lesson from January wasn't learned. The lesson from October is harder to ignore.

### 3.4 How to prevent (identity infrastructure hardening)

1. **Treat your IdP as a Tier-0 asset.** The Okta/Entra/PingOne tenant deserves the same protection as your domain controllers. Admin access should require FIDO2, be logged in a SIEM, and be reviewed weekly.
2. **Minimize what the directory exposes.** SSO directories often contain far more than authentication requires. Strip office locations, phone numbers, organizational assignments, and especially operational role indicators from any directory an application can query. Principle of least privilege applies to *data attributes*, not just access grants.
3. **Segment directory access by application.** If Application A needs to authenticate users, it doesn't need to enumerate the directory. Scoped OAuth grants, not global read access.
4. **Monitor for bulk enumeration.** A single session pulling thousands of directory records is not normal authentication traffic. Alert on it.
5. **Patch the identity gateway.** See §6. If Okta Access Gateway is in your stack, it needs the Oct 22 update *yesterday*.

### 3.5 For the people affected

This post is technical, but this one isn't a technical problem. If your name is in that database:

- **Assume your home address is derivable.** Public records, social media, and data brokers connect names to addresses. Contact your agency's security office about address suppression programs.
- **Monitor for social engineering.** Someone who knows your name, title, office, and phone number can impersonate your agency to your bank, your landlord, or your family.
- **Brief your household.** Anyone who lives with you should know that calls referencing your employer by name are not automatically trustworthy.

DHS's statement: *"DHS is aware of a potential breach and is actively working to address the situation swiftly and effectively."*

---

## 4. #2 — The Pentagon / DMDC: 3 Million Military Records Stolen

> *"Three million ghosts, and they didn't even need a zero-day."* 💀

If the DHS leak is the scariest because of what was *published*, the Pentagon breach is the scariest because of what was *stolen*. The Defense Manpower Data Center (DMDC) held personnel records for over **3 million military and civilian employees** — and an unauthorized party had access for **nine months**.

### 4.1 What happened

| Detail | Value |
|---|---|
| **Source** | Defense Manpower Data Center (DMDC), a Pentagon system |
| **Access window** | **October 2025 – July 2026** (~9 months) |
| **Disclosed** | September 18, 2026 (notification letter) |
| **Records affected** | **2.76 million living + ~294,000 deceased** = ~3.05 million |
| **Some estimates** | Up to **4 million** (sources disagree) |
| **Data exposed** | Names, Social Security numbers, dates of birth, contact details, sex, race, military occupational specialties |
| **Encryption** | **Records were NOT encrypted** |
| **Attribution** | "Unauthorized users" — no confirmed nation-state or group |
| **Entry vector** | Reported as a file-sharing system vulnerability |
| **Public availability** | **No evidence** of a public searchable database (unlike DHS/icepick.is) |

### 4.2 Why it's #2 (not #1)

The scope here dwarfs the DHS leak: 3+ million records vs. 41,000. The data is more sensitive too — SSNs, DOBs, and military specialties are everything an identity thief or foreign intelligence service needs.

So why #2? Two reasons:

1. **The DHS data is publicly searchable right now.** The Pentagon data was exfiltrated, but there's no evidence of a public database. Stolen data can be held, sold, or destroyed. Published data is permanent.
2. **The DHS leak exposed people whose physical safety depends on anonymity.** Undercover investigators and ICE field officers face a qualitatively different threat than records in a database that hasn't surfaced publicly.

Our ranking engine confirms this: the Pentagon scores higher on *scope* (9.5 vs 7.0) and *severity* (9.5 vs 9.0), but lower on *exploitation* (7.0 vs 10.0 — data stolen but not published) and *novelty* (4.0 vs 8.0 — unencrypted data stolen via a file-sharing vuln is, depressingly, routine).

### 4.3 What makes this instructive

**The records were not encrypted.** This is a direct lesson from §16 (Fortress of Solitude). If 3 million personnel records had been encrypted at rest with proper key management, the attacker would have exfiltrated ciphertext. Instead, they got plaintext SSNs.

**Nine months of access.** The attacker was inside from October 2025 to July 2026. That's three quarters. Most threat hunting frameworks recommend assuming compromise and checking — this is what happens when you don't. DMDC either didn't detect the access or detected it late.

**A file-sharing system vulnerability.** Not a sophisticated zero-day chain. Not a nation-state exploit kit. A file-sharing bug. The largest military personnel breach in recent history came through what sounds like a SharePoint or similar collaboration platform.

### 4.4 The combined federal picture

Put these two together:

| Incident | People affected | Data type | Publicly searchable? |
|---|---|---|---|
| DHS/CBP/ICE Leak | 41,000+ | Names, phones, titles, office locations, operational roles | **YES** (icepick.is) |
| Pentagon/DMDC | 3,000,000+ | Names, SSNs, DOBs, contact info, military specialties | **No** (as of Oct 31) |

In a single month, the identities of **over 3 million US military and federal law-enforcement personnel** were compromised across two separate incidents, through two separate vectors, from two separate systems. This is not a single failure. This is a systemic pattern of unencrypted personnel data sitting behind inadequate access controls.

### 4.5 Recommendations

1. **Encrypt personnel data at rest.** Not "someday." Not "next fiscal year." If the DMDC records had been encrypted with per-record keys (§16.1), the breach would be a key management problem, not an identity theft nightmare.
2. **Monitor for bulk data access.** Nine months of unauthorized access to 3 million records means either nobody was watching access patterns or the alerts were ignored.
3. **File-sharing systems are not vaults.** If your file-sharing platform holds personnel records with SSNs, it needs the same access controls and monitoring as a database. "It's just SharePoint" is not a security posture.
4. **Assume the data will surface.** The fact that the Pentagon data isn't publicly searchable *yet* doesn't mean it won't be. Affected personnel should freeze their credit, enroll in identity monitoring, and treat their SSN as compromised.

---

## 5. #3 — ShinyHunters: The Headless Horseman Rides Into the FBI

We have written about this crew twice already. The [condensed graph-theory post](../ShinyHunters/ShinyHunters_Condensed.md) and the [full write-up](../ShinyHunters/ShinyHunters.md) cover the PeopleSoft infrastructure, SIDEEYE / MeshAgent / LA.exe, and backup-destruction capability. This section covers only what changed inside the Black October window.

### 5.1 What happened

| Date | Event | Source |
|---|---|---|
| Sep 15 | Dutch police arrest convicted hacker and alleged senior member Pepijn van der Stap. His Signal messages reportedly show contacts with ransom negotiators in Canada and the US. | Krebs |
| Sep 22 | ShinyHunters claims a breach of the FBI's jobs platform (`fbijobs.gov`). They threaten to publish employee files, including medical and psychological records and SSNs. Their stated motive is pressuring the FBI to retract a May report on the group. | SecurityWeek, Krebs |
| Late Sep | Google (Mandiant/GTIG, tracking **UNC6240**) warns of **renewed mass exploitation** of CVE-2026-35273, now with a **WAF-bypass** modification. | BleepingComputer, THN, eSecurityPlanet |
| Oct 2 | ShinyHunters says it does *not* plan to release the FBI data. | Hackaday, S-RM |
| Oct 3 | "Rey" (Saif al-Din Khader), who reportedly took over the ShinyHunters brand, is reported detained in Jordan and cooperating. | SecurityWeek, Krebs |
| Oct 6 | The FBI attributes the breach to *"a security failure of a platform managed by a third-party organization"*. Reuters' sources name an Accenture contractor who missed a PeopleSoft patch. The FBI removed the contractor. | SecurityWeek |
| Oct 9 | Canadian cybersecurity executive Edward Dubrovsky is arrested and charged with extortion. Signal messages allegedly show he knew about the FBI theft before the public threat. | Krebs |
| Oct 16 | **Shinywire**, the pay-up-or-else portal (active since ~May 3, ~100 victims), goes dark. Investigators suspect at least one US consulting-firm executive helped run it. | Krebs, Cybernews |

The FBI says the group extorted **more than $70 million in 2026**.

> **The plot twist nobody wanted:** Investigators allege that people paid to *negotiate on behalf of victims* learned of breaches before the victims did. The "trusted third party" here was a contractor who missed a patch, and possibly also the negotiator. Remember that when §14 talks about supply-chain trust.

### 5.2 The technical core: CVE-2026-35273 and the one-character WAF bypass

**The bug.** CVE-2026-35273 (CVSS 9.8) is an unauthenticated flaw in the **PeopleSoft Enterprise PeopleTools 8.61 / 8.62 "Updates Environment Management" component**. That is the **Environment Management Hub servlet at `/PSEMHUB/`**. Our earlier analysis describes it as SSRF chained to remote code execution. Oracle shipped the fix on **June 10, 2026**. Mandiant traced exploitation back to **May 27**, so this was a zero-day for two weeks and has been an n-day for four months.

**The bypass.** Organizations that couldn't or wouldn't patch deployed WAF rules matching the literal string `/PSEMHUB/`. UNC6240 changed one byte:

```text
GET /PSEMHUB/...      ← blocked by the WAF rule
GET /%50SEMHUB/...    ← %50 is 'P'. WAF string-match misses it.
                         The Java servlet container decodes it and routes to PSEMHUB.
```

This is an old class of bug (CWE-180, "validate before canonicalize"). The WAF inspected the URI *as sent*, but the application server routed on the URI *after decoding*. Any time two components parse the same input differently, the attacker can pick the gap.

```mermaid
sequenceDiagram
    participant A as Attacker (UNC6240)
    participant W as WAF (regex on raw URI)
    participant S as PeopleSoft web tier
    participant H as PSEMHUB servlet
    A->>W: GET /%50SEMHUB/...
    W->>W: "/PSEMHUB/" in raw URI? NO
    W->>S: forward unchanged
    S->>S: percent-decode → /PSEMHUB/
    S->>H: dispatch
    H-->>A: vulnerable code path → RCE → JSP web shell
```

**Post-exploitation.** Google reports web shells on dozens of systems across higher education, technology, IT services, healthcare, agriculture, transportation, and government. Our previous posts documented the SIDEEYE / MeshAgent / LA.exe toolkit and the backup-destruction capability.

**The FBI angle.** ShinyHunters claims FBI Jobs was breached through a *different, previously unknown* PeopleSoft vulnerability, not CVE-2026-35273. The FBI's public account (a contractor missed a patch) fits CVE-2026-35273 better. Both could be true. Treat the "second 0-day" as **unverified**, but act as if it exists: if a PeopleSoft instance must face the internet, assume more than one bug is reachable.

### 5.3 How to mitigate (today)

1. **Patch.** Apply Oracle's June 10 fix. After that, the WAF bypass doesn't matter, because the bypass only defeats a *workaround*.
2. **Remove PSEMHUB from the internet.** Disable or remove the Environment Management Hub if you don't use it (most production tenants don't need it public). Otherwise restrict it to an admin network.
3. **If you must keep a WAF rule, match on the normalized path.** Decode first (repeatedly, to catch `%2550` double encoding), uppercase, then match. See §15.2 for the nginx version.

### 5.4 How to hunt (assume you were hit)

Search access logs for **both literal and encoded** forms. Grepping for `PSEMHUB` alone is the same mistake the WAF made:

```bash
# Decode each line twice (catches %50 and %2550), then search case-insensitively.
python3 -I -c '
import sys, urllib.parse as u
for line in sys.stdin:
    d = u.unquote(u.unquote(line))
    if "PSEMHUB" in d.upper():
        print(line, end="")
' < /var/log/peoplesoft/access.log
```

Then:

- **Look for JSP or executable files in PeopleSoft web directories** that aren't in your deployment baseline. Mandiant explicitly recommends this. A quick triage is `find "$PS_CFG_HOME" -type f \( -name '*.jsp' -o -name '*.class' -o -name '*.exe' -o -name '*.sh' \) -newer <known-good-file>`.
- **Look for outbound connections** from the web tier to anything that isn't your database or IdP. Our earlier IOC tables are in [ShinyHunters_Condensed §8](../ShinyHunters/ShinyHunters_Condensed.md#8-indicators-of-compromise).
- **Check backups first.** Our earlier analysis rated backup destruction a *capability* of this toolkit. Verify you have an immutable, offline copy before you start eviction (see §16.4).

### 5.5 How to fix (structurally)

- **Patch SLAs keyed to KEV and CVSS, not to the change calendar.** An unauthenticated 9.8 RCE with a public exploit needs a deadline in days, not "next quarterly window."
- **Make contractors' patch status *your* telemetry.** The FBI's breach came down to "a platform managed by a third-party organization." Put vulnerability-scan results for vendor-managed systems in the contract, with timelines and audit rights.
- **Phishing-resistant MFA everywhere.** Krebs' Intuitive Surgical example (credentials phished from an employee) shows the group doesn't depend on any one CVE.
- **Plan for extortion before it happens.** Decide in advance who talks to the attacker, through which firm, and how that firm is vetted. This month showed that the negotiator can be part of the threat model.

---

## 6. #4 — Linux Kernel TCP: The Floor Is Lava (CVE-2026-98432)

> *"The skeleton was inside you all along."* 🦴

If DHS is the scariest breach and ShinyHunters is the scariest crew, CVE-2026-98432 is the scariest *bug* — because it's in the floor everyone is standing on.

### 7.1 The bug

**CVE-2026-98432** is a **use-after-free** in the Linux kernel's IPv4 TCP handshake code (`net/ipv4/tcp`). The kernel CVE team published it on **October 15** and re-scored it to **CVSS 9.8** on **October 24**.

| | Details |
|---|---|
| **Bug class** | Use-after-free (CWE-416) in TCP connection setup |
| **Trigger** | A specially crafted TCP handshake sequence to an open port. **Remote, unauthenticated, no user interaction.** |
| **Affected** | Essentially every Linux distribution shipping kernels from the affected range. The vulnerable code has been in mainline for years. |
| **CVSS** | **9.8** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Exploited in the wild?** | Not in CISA KEV as of Oct 29. See §4.2 for the Anthropic claim. |

**Why it's terrifying:** This isn't an application bug, or a library bug, or even a runtime bug. It's in the **kernel's TCP stack**. Every Linux server, container, VM, router, NAS, IoT device, and cloud instance with an open TCP port is potentially in scope. You don't need to be running PHP or PeopleSoft or Citrix. You just need to be running Linux and listening on a socket.

### 7.2 The Anthropic claim (and the skepticism)

On **October 27**, Anthropic stated that an unreleased internal AI model produced a working **remote-root exploit** against servers with a Multipath TCP (MPTCP) listener, reportedly achieving root access in **53 minutes** of autonomous work.

**Important caveats:**

- Anthropic's exploit code **is not public**.
- **CloudLinux's kernel team could not reproduce the claim** as of October 30.
- The Anthropic announcement was made alongside a product capability disclosure, which gives it a marketing incentive.
- MPTCP listeners are a **narrower attack surface** than standard TCP — most production servers don't enable MPTCP by default.

Treat this as a **credible but unverified escalation path**. The UAF itself is real and confirmed. Whether it's reliably exploitable for remote root on a standard configuration is an open question. **Do not wait for the answer to start patching.**

### 7.3 Who's affected (distro status as of Oct 30)

| Distribution | Status | Notes |
|---|---|---|
| **Upstream mainline** | ✅ Fixed | Patch merged in mid-October |
| **Debian** | ✅ Fixed | Shipped in stable updates |
| **Oracle Linux** | ✅ Fixed | Shipped mid-October |
| **AlmaLinux** | 🟡 Testing | Patched kernels in testing repo |
| **Red Hat (RHEL)** | 🔴 **Not yet** | RHSB-2026-016 published Oct 30; rated Critical; no fixed kernel as of Oct 29 |
| **Ubuntu** | 🔴 **Not yet** | Tracker still listed kernels as vulnerable Oct 29; Canonical 22.04 fix "in progress" |
| **CloudLinux** | 🟡 In progress | Blog published Oct 30 |

**This means the two most popular server distributions in the world — RHEL and Ubuntu — do not yet have a patched kernel in their stable repos.** If you run either, read §4.4 carefully.

### 7.4 How to mitigate (now, before your distro ships the fix)

**Option 1: Disable MPTCP** (narrows the confirmed exploit path):

```bash
# Check if MPTCP is enabled (if this returns nothing or "0", you're not using it)
sysctl net.mptcp.enabled 2>/dev/null

# Disable it (persists across reboots with sysctl.d)
echo "net.mptcp.enabled = 0" | sudo tee /etc/sysctl.d/99-cve-2026-98432.conf
sudo sysctl -p /etc/sysctl.d/99-cve-2026-98432.conf
```

**Option 2: Network-level filtering.** If you can identify the malformed handshake pattern (check Red Hat's RHSB-2026-016 for specifics), deploy it at your perimeter. This is a speed bump, not a fix.

**Option 3: Livepatch / kpatch.** If your distro supports kernel live patching and a livepatch is available, apply it without rebooting. Check:

```bash
# RHEL/CentOS
sudo yum list available kpatch-patch-\* 2>/dev/null

# Ubuntu
canonical-livepatch status 2>/dev/null
```

**Option 4: Build a patched kernel from upstream.** Only if you have the build infrastructure and testing pipeline for it. The fix is in mainline.

### 7.5 How to check if you're vulnerable

```bash
#!/usr/bin/env bash
# tcp_uaf_check.sh — check if the running kernel is vulnerable to CVE-2026-98432
kernel="$(uname -r)"
echo "Running kernel: $kernel"

# Check distro-specific changelogs for the CVE
if command -v rpm &>/dev/null; then
    echo "--- RPM-based distro ---"
    rpm -q --changelog kernel-"$kernel" 2>/dev/null | grep -i "CVE-2026-98432" && echo "[PATCHED]" || echo "[NOT FOUND in changelog — likely VULNERABLE]"
elif command -v dpkg &>/dev/null; then
    echo "--- Debian-based distro ---"
    pkg="$(dpkg -S /boot/vmlinuz-"$kernel" 2>/dev/null | cut -d: -f1)"
    [ -n "$pkg" ] && apt changelog "$pkg" 2>/dev/null | grep -i "CVE-2026-98432" && echo "[PATCHED]" || echo "[NOT FOUND in changelog — likely VULNERABLE]"
fi

# Check MPTCP status
mptcp="$(sysctl -n net.mptcp.enabled 2>/dev/null)"
if [ "$mptcp" = "1" ]; then
    echo "⚠️  MPTCP is ENABLED — confirmed exploit path is reachable"
elif [ "$mptcp" = "0" ]; then
    echo "MPTCP is disabled — confirmed exploit path is blocked (standard TCP path unconfirmed)"
else
    echo "MPTCP sysctl not found — kernel may not support MPTCP (good)"
fi
```

### 7.6 Why this matters beyond the CVE

This is the third CVSS 9.8 kernel networking bug in recent memory, and the pattern is consistent: **C code in the TCP stack, use-after-free, reachable from the network**. The Linux kernel is the most critical piece of software on the internet. Every container, every cloud VM, every Kubernetes pod runs on it. When the kernel has a remotely exploitable UAF in its TCP handshake, the entire cloud computing model takes a deep breath.

The Anthropic angle adds a new dimension: if AI models can autonomously find and exploit kernel bugs, the time between CVE publication and weaponization compresses from "days" to "hours." Whether or not this specific claim is fully reproducible, the trend line is clear.

---

## 7. #5 — PHP2Shell: The Call Is Coming From Inside the Runtime

PHP2Shell is ranked #4 because of reach, not confirmed body count. PHP runs a huge share of the web, and these bugs are in the **engine**, so they can trigger **before any application code runs**. A perfectly written WordPress or Laravel site is still exposed.

### 6.1 The two bugs

| | **CVE-2026-109618** | **CVE-2026-109619** |
|---|---|---|
| Advisory | GHSA-w8hw-w9fx-j79w | GHSA-6wmf-4rv5-p3rp |
| One-liner | An out-of-memory bailout leaves request data **partially initialized**, and shutdown treats it as valid | **Request-owned global state survives** after its memory is freed, and the next request on the same worker reads it |
| Primitive | Use of uninitialized/invalid memory during request shutdown | Heap use-after-free + memory disclosure |
| Trigger | Attacker-induced OOM. Multipart parsing is the documented path. | Two requests to the same worker. **`session.upload_progress`** is the confirmed path; PHP 8.5 `fatal_error_backtraces` is another. |
| Requests needed | 1 per attempt (mod_php) | 2 on the same worker |
| CVSS v4 | 9.2 (AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H) | 9.2 (same vector) |

**Why AC:H / AT:P?** Reliable exploitation depends on allocator layout, the exact build, and worker scheduling. That makes it *harder*, not *hard*: there is a public PoC, and within hours of the patch attackers were changing payloads to get around Cloudflare's emergency WAF rules.

**The quiet killer: memory disclosure.** Even without code execution, CVE-2026-109619 can read **worker memory left over from other users' requests**. Researchers demonstrated it against applications they didn't control. Passwords, session tokens, API keys, and TLS material that passed through that worker are all exposed. That makes this a Heartbleed-shaped problem on top of an RCE.

**Fun bit of archaeology.** The PHP Foundation says a core developer noticed signs of the OOM flaw during the **2024 external audit**, but no code-execution route was found then. "Unexploitable" memory bugs tend not to stay that way.

### 6.2 Who's exposed (SAPI matrix)

| SAPI | Risk | Notes |
|---|---|---|
| **Apache mod_php** (prefork) | 🔴 **Highest** | RCE demonstrated for **both** CVEs with default limits. Can fire before app code runs. |
| **PHP-FPM** | 🟠 High | FPM kills a worker that fails early in setup, which blocks one OOM path. But **session-lifecycle RCE (109619) was validated** under suitable application conditions. |
| php-cgi, FrankenPHP, LiteSpeed | 🟠 At risk | Listed by PHP. Fewer public specifics. |

**Affected:** essentially every PHP from **5.4 through 8.5**.

### 6.3 Timeline (UTC, Oct 20–21)

| Time | Event |
|---|---|
| Oct 17 | Amazon telemetry records an exploitation attempt **four days before disclosure** |
| Oct 20 | A leak claims disclosure for Oct 22. PHP posts advance notice and moves the release up. |
| ~20:00 Oct 20 | Researcher accidentally publishes a video of a working PoC |
| 03:02 Oct 21 | Cloudflare enables WAF rules by default (attackers reportedly adapt) |
| 07:41 Oct 21 | Chainguard ships patched images *before* the official release |
| 11:26 Oct 21 | watchTowr: no exploitation in the wild yet |
| 14:00 Oct 21 | **PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 released** |
| 14:19 Oct 21 | watchTowr: **active exploitation attempts** against both CVEs |
| Oct 21 | CISA: exploitation not observed, not in KEV. Sophos: successful exploitation in customer environments. |

Nineteen minutes passed between the release and confirmed exploitation attempts. "We'll patch next sprint" stopped being a plan for this one at 14:19.

### 6.4 How to fix: patch, then prove it

| Branch | Fixed in |
|---|---|
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** |
| 7.4 / 8.0 / 8.1 | EOL upstream. Source backports exist in php-src; get vendor/distro builds or upgrade. |

**Trap #1: distro version strings.** Debian, Ubuntu, and RHEL backport fixes without bumping the upstream version number. Check the package changelog for the CVE IDs, not `php -v` alone.

**Trap #2: the PHP you checked isn't the PHP that serves traffic.** Containers, hosting panels, appliance-bundled PHP, and parallel branches all exist. Inventory the *serving* runtime:

```bash
#!/usr/bin/env bash
# php2shell_inventory.sh — report the PHP version inside every running container
# and whether it meets the PHP2Shell fixed version for its branch.
fixed_for() {
  case "$1" in
    8.5) echo 8.5.12 ;; 8.4) echo 8.4.27 ;; 8.3) echo 8.3.36 ;; 8.2) echo 8.2.35 ;;
    *)   echo "EOL" ;;
  esac
}
for c in $(docker ps -q); do
  name="$(docker inspect -f '{{.Name}}' "$c")"
  v="$(docker exec "$c" sh -c 'command -v php >/dev/null && php -r "echo PHP_VERSION;"' 2>/dev/null)" || continue
  [ -z "$v" ] && continue
  branch="${v%.*}"; want="$(fixed_for "$branch")"
  if [ "$want" = "EOL" ]; then
    echo "[EOL ] $name  php $v  (check vendor backport changelog)"
  elif [ "$(printf '%s\n%s\n' "$want" "$v" | sort -V | head -1)" = "$want" ]; then
    echo "[ OK ] $name  php $v  (>= $want)"
  else
    echo "[VULN] $name  php $v  (needs $want)"
  fi
done
```

**Trap #3: you patched the binary but not the workers.** Restart *every* FPM pool and Apache instance. Long-lived workers keep the old code mapped in memory.

**Trap #4: the patch changes OOM behavior.** The fix adds a **hard memory ceiling that kills the process and skips shutdown handlers**. Code that relies on `register_shutdown_function()` to flush queues or release locks under memory pressure can now leave work half-done. Load-test after patching.

### 6.5 How to mitigate (only if you truly can't patch yet)

PHP is explicit: **no configuration fully mitigates this; only updating does.** These measures shrink the attack surface while the change ticket moves. Apply them with `php_admin_value`, **not** `ini_set()` or `.user.ini`. Neither of those works for these settings, and the attacker gets in before your code runs anyway.

```ini
; /etc/php/8.x/fpm/pool.d/www.conf  — INTERIM PHP2Shell hardening
; --- CVE-2026-109619: close the confirmed session paths ---
php_admin_value[session.upload_progress.enabled] = 0
; PHP 8.5 only:
php_admin_value[fatal_error_backtraces] = 0

; --- CVE-2026-109618: make attacker-driven OOM harder ---
; PHP's interim advice is memory_limit=-1, set administratively so apps can't
; lower it. Pair it with a cgroup/container memory limit for availability, and
; RESTORE a finite limit once patched. Do NOT use RLIMIT_AS / RLIMIT_DATA:
; they force the same vulnerable allocation-failure path.
php_admin_value[memory_limit] = -1
php_admin_value[post_max_size] = 8M          ; 32M if you genuinely need uploads
php_admin_value[upload_max_filesize] = 6M    ; keep below post_max_size
php_admin_value[max_file_uploads] = 5
php_admin_value[max_input_vars] = 1000
php_admin_value[max_input_nesting_level] = 32
php_admin_value[max_multipart_body_parts] = 100

; Optional, costly: one request per worker removes the cross-request reuse
; that 109619 needs. Measure before you ship it.
; pm.max_requests = 1
```

Also remove any **invalid or deprecated per-request INI** (`php_value` in Apache config, `.htaccess`, or `PHP_VALUE` set by a front end). Diagnostics emitted before initialization are one of the documented triggers.

And at the edge, before PHP sees the request (full config in §15):

```nginx
# Cap the decoded body. Applies even when Content-Length is absent (chunked).
client_max_body_size 8m;

location ~ \.php$ {
    # If this app never accepts uploads, multipart has no business reaching PHP.
    if ($content_type ~* "multipart/form-data") { return 415; }
    # ... fastcgi_pass etc.
}
```

### 6.6 How to detect

Watch for these **even on already-patched hosts**, in case you were hit before patching:

- Multipart POSTs followed by `Allowed memory size ... exhausted` or other memory-limit errors
- Bursts of HTTP **500** from PHP upstreams
- **Unusually large `PHPSESSID` `Set-Cookie`** values in responses
- Unexplained PHP worker restarts (`child NNNN exited on signal 11 (SIGSEGV)` in the FPM log)

An nginx `log_format` that records these signals:

```nginx
log_format php2shell '$msec $remote_addr "$request" $status '
                     'up=$upstream_status rl=$request_length ct="$content_type" '
                     'rt=$request_time cookie_len=${sent_http_set_cookie}';
```

```bash
# Multipart requests answered with 5xx, grouped by client
awk '/ct="multipart/ && $0 ~ /up=5[0-9][0-9]/ {print $2}' /var/log/nginx/php2shell.log \
  | sort | uniq -c | sort -rn | head
# Worker crashes in FPM
grep -E 'exited on signal (11|6)|Allowed memory size' /var/log/php*-fpm.log | tail -50
```

**After any suspected hit:** rotate every secret that could have been in worker memory, including DB passwords, API keys, session signing keys, and OAuth client secrets. The memory-disclosure primitive leaves no file on disk to find.

---

## 8. #6 — Okta Access Gateway: The Key Master

> *"There is no identity layer. Only Zuul."* 👻

Okta Access Gateway is the reverse proxy / SSO enforcement point that sits between users and on-prem applications. On **October 22**, Okta disclosed four vulnerabilities in a single advisory — including two of its own and the two PHP2Shell CVEs, because **Okta Access Gateway runs on PHP**.

### 8.1 The bugs

| CVE | What | Severity | Precondition |
|---|---|---|---|
| **CVE-2026-115547** | Authenticated administrator can execute **arbitrary system commands** through the Admin Console | CVSS **9.1** | Admin-level access to the gateway |
| **CVE-2026-115546** | Authentication bypass — a signed-in user can obtain a **SAML assertion for the Admin Console** they shouldn't have access to | CVSS **8.1** | Any authenticated user |
| CVE-2026-109618 | PHP2Shell (OOM → uninitialized memory → RCE) | CVSS v4 9.2 | See §5 |
| CVE-2026-109619 | PHP2Shell (UAF → memory disclosure / RCE) | CVSS v4 9.2 | See §5 |

### 8.2 The chain that keeps you up at night

Read these in order:

1. **CVE-2026-115546** (auth bypass): A regular user — not an admin — can escalate to an Admin Console SAML assertion.
2. **CVE-2026-115547** (command exec): An admin can run system commands through the console.
3. **Result:** A regular authenticated user → admin assertion → system command execution on the gateway.

And underneath all of it, **PHP2Shell** means even the *unauthenticated* path is open if the PHP runtime hasn't been patched.

```text
Regular user
  └── CVE-2026-115546 (auth bypass → admin SAML assertion)
       └── CVE-2026-115547 (admin console → system command execution)
            └── Full control of the Okta Access Gateway
                 └── Every application behind it is compromised

Unauthenticated attacker
  └── CVE-2026-109618/109619 (PHP2Shell → RCE on gateway)
       └── Full control of the Okta Access Gateway
            └── Every application behind it is compromised
```

### 8.3 The DHS connection

The DHS employee data leak ([§2](#2-1--dhscbpice-41000-federal-agents-unmasked)) came through an **Okta SSO system**. Okta Access Gateway is the component that enforces SSO for on-prem applications. While we cannot confirm that the DHS breach used these specific CVEs, the timing is notable: the bugs were disclosed on October 22, and the DHS data was published on October 28. Whether or not these CVEs were the entry point, they demonstrate that Okta's gateway layer — the layer that guards directory access — was critically vulnerable during the same window.

### 8.4 How to fix

- **Upgrade to Okta Access Gateway 2026.10.2 or later.** This single release fixes all four CVEs.
- **Audit Admin Console access.** Check who has admin access and whether any unexpected SAML assertions were issued in October.
- **Check the PHP version on the gateway.** Even after the Okta update, confirm the bundled PHP matches the PHP2Shell fix versions (§5.4).
- **Monitor for command execution artifacts.** If the gateway was exposed: look for unexpected processes, new files in the web root, cron entries, and outbound connections from the gateway host.

### 8.5 The architectural lesson

Okta Access Gateway is an **identity enforcement point** that runs on **PHP** and exposes an **admin console** to the network. That's three layers of attack surface stacked on top of the thing that decides who gets in. When your gatekeeper is itself vulnerable, every door it guards is open.

This is why §3.4 recommends treating your IdP as a Tier-0 asset. It's not just policy advice — it's what happens when you don't.

---

## 9. #7 — Citrix NetScaler: The Gateway Ghost (Again)

NetScaler is on this list for what seems like the fifth year running. This round has **ten CVEs** across three Citrix bulletins. Three of them matter most:

| CVE | What | Precondition | Status |
|---|---|---|---|
| **CVE-2026-88771** | Improper input validation → unauthenticated arbitrary command execution *(third-party description; not confirmed in Citrix's bulletin text we could reach)* | All ADC/Gateway on vulnerable builds | **KEV Sep 27**, exploited globally |
| **CVE-2026-88772** | Memory overflow (CWE-119) → RCE, CVSS v4 **9.5** | **DTLS enabled**, which is the default on VPN vServers | **KEV Sep 27**, exploited globally |
| **CVE-2026-88779** | Memory overflow → DoS; on unpatched systems it can **force a reboot that helps execute code injected via 88771** | SAML SP or IdP configured | **KEV Oct 4** |

Others: CVE-2026-88773 through -88778 and CVE-2026-107406 (bulletins CTX697096, CTX697174, CTX697191).

**The chain worth understanding:** 88779 is more than "just a DoS." CISA notes that attackers can use the forced reboot to *activate* a payload staged through 88771. A "low-severity" availability bug ends up completing an RCE chain. Never deprioritize a DoS on an edge device without asking what a reboot does for the attacker.

### How to fix

- Upgrade to **14.1-73.37+ / 13.1-64.23+** (and the FIPS/NDcPP equivalents) for 88771/88772. If you have SAML configured, **upgrade again** to **14.1-73.41 / 13.1-64.28** for 88779. Patching once in late September is not enough. *(Build numbers come from Citrix's bulletins as quoted by secondary sources. Verify in CTX697096 / CTX697174.)*

### How to mitigate and hunt

1. **Check for compromise *before* patching.** CISA warns that updates can reduce forensic visibility. Image or preserve first.
2. **Ship NetScaler logs off the box** to a SIEM. Local logs rotate fast, and attackers wipe them.
3. Use the IOCs in **NetScaler Console** and CISA's **SIGMA rules** (`cisagov/SIGMA_Rules`, added Oct 2).
4. If you're compromised, **restore from a known-good pre-compromise backup**, then rotate **local account passwords, KEKs, and SSL certificates**. Citrix's CTX694799 is the runbook. Patching a backdoored appliance leaves you with a patched backdoored appliance.

---

## 10. #8 — BeyondTrust Remote Support: The Butler Did It

A remote-support appliance holds the keys to every system its technicians touch. Compromising it gives an attacker those keys too.

- **CVE-2026-102764**, advisory **BT26-05**, disclosed Oct 15. CVSS v4 **9.3** (NVD v3.1: **9.8**).
- **Bug class:** authentication bypass (CWE-290) in an internal messaging component. It lets an unauthenticated attacker perform **file operations** (sources also describe arbitrary file upload).
- **Affected:** Remote Support **26.2.3 and earlier**. Privileged Remote Access shares the code; BeyondTrust patched it as a precaution but found no exploit path.
- **Actor:** **ARMORY CASTLE** (Mandiant; formerly **UNC5221**) / **Warp Panda** (CrowdStrike), suspected PRC-nexus espionage. First use **Aug 29**, against one SaaS instance and one self-hosted appliance.
- Shadowserver counted **1,400+** exposed instances.

### The kill chain (Mandiant/GTIG)

```text
auth bypass ──► web shell ──► web-svc account → root (SUID abuse)
            ──► SAWFLY (custom PHP web shell) + BARECLAW tunneler
            ──► log wiping
            ──► stolen admin creds → remote sessions on DOWNSTREAM systems
            ──► persistence that survives reboot AND config reset
```

Note that **SAWFLY is a PHP web shell**, which connects this incident to #4. The appliance's management stack is PHP. A runtime-level bug (PHP2Shell) and an application-level bug (this one) both end with a PHP shell on a device that holds everyone's credentials.

### How to fix and mitigate

- **SaaS:** patched by BeyondTrust on Oct 8 (sources vary between Oct 8 and Oct 15).
- **Self-hosted 24.3.1 → 26.2.3:** apply BT26-05 or confirm auto-update installed it. Older releases must upgrade first.
- **Treat any internet-reachable appliance that was on a vulnerable version since late August as compromised until reviewed.** Look for new SUID binaries, gaps in logs, web-root files outside your baseline, and Administrator sessions to downstream hosts at odd hours.
- **Rotate every credential the appliance stored or brokered.** Because the persistence survives a config reset, a "factory reset and carry on" leaves the attacker in place. Rebuild from known-good media.

---

## 11. #9 — Fortinet FortiMail: Something Wicked Through the Mail Slot

- **CVE-2026-104286**, Fortinet **FG-IR-26-175**, CVSS **9.8**, found internally by Fortinet PSIRT, **exploited in the wild**.
- **Bug class:** path traversal (CWE-22) + improper NULL-byte neutralization (CWE-158) → **unauthenticated arbitrary file write** over HTTP/S.
- **KEV:** added **Oct 1**, federal deadline **Oct 4**.
- **Affected:** 8.0.0–8.0.1, 7.6.0–7.6.6, 7.4.0–7.4.8, 7.2.0–7.2.9 (NVD data reportedly also includes 7.0.x).
- **Fixed:** 8.0.2, 7.6.7, 7.4.9. **7.2 users must move to 7.4+.** At disclosure, fixes weren't yet released and sources still disagree on current status, so check the advisory.

### From file write to code execution

A file-write primitive becomes code execution when the attacker controls *what loads*. One analysis (Wiz, treat with caution) describes a dropped shared library at `/data/lib/liblog.so` plus a modified **`/etc/ld.so.preload`**. After that, every dynamically linked process on the box loads attacker code. It is an old trick that still works.

**Why the NULL byte?** A classic pattern is a check like "filename must end in `.png`" that runs on the full string, while the lower-level C API stops at the first `\0`. So `../../../data/lib/liblog.so\0.png` passes validation and gets written as `.../liblog.so`. This is the same validate-then-canonicalize mismatch as the PeopleSoft WAF bypass, in a different layer.

### How to mitigate (now)

```text
config system encryption ibe
    set status disable
end
```

Then **block internet access to the management interface** or restrict it to a trusted network. Hunt with the files, IPs, and log entries in FG-IR-26-175, and **check `/etc/ld.so.preload`** on any appliance where you can get a shell. On a healthy appliance it should be empty or absent.

---

## 12. #10 — PAN-OS: The Firewall That Let You In

> *"Who watches the watchmen? Apparently, the attackers."* 🔥

- **CVE-2026-0322**, disclosed **Oct 14**, added to **CISA KEV with a 3-day federal deadline**.
- **Bug class:** Authenticated RCE on the **management interface**. Palo Alto published three attacker IPs.
- **Precondition:** Valid credentials on an internet-exposed management interface.
- **Cloud NGFW and Prisma Access:** unaffected.

### Why it's on the Top 10

A firewall's management interface is its brain. If an attacker can run code on it, they don't need to go *through* the firewall — they *are* the firewall. The "requires valid credentials" precondition sounds like a mitigating factor until you remember that:

1. Credentials get phished (see ShinyHunters, §3).
2. Credentials get leaked (see DHS/Okta, §2).
3. Credentials get reused from other breaches.
4. Default credentials exist in the wild.

The 3-day KEV deadline tells you how seriously CISA takes this one.

### How to fix

1. **Patch** per Palo Alto's advisory.
2. **Never expose the management interface to the internet.** This is in Palo Alto's own hardening guide and has been for years. If it's reachable from the internet, fix that before you fix the CVE.
3. **Rotate admin credentials.** Assume they've been tested.
4. **Review Threat Prevention signatures.** Palo Alto published signatures, but two require SSL decryption to work. If you're not decrypting management traffic (you probably aren't), those signatures are blind.

---

## 13. Honorable (Dis)Mentions

| Item | Why it didn't make the Top 10 | What to do |
|---|---|---|
| **Atlassian CVE-2026-21589** (KEV Oct 15) | Multi-product access flaw, exploited. Sparse public details. Confluence + Jira are everywhere, and an access flaw means attackers can read *everything an engineering team knows*. | Patch per Atlassian advisory. Audit for new admin accounts and API tokens. Search Confluence for stored `password`, `api_key`, `secret`, `token` — if an attacker had read access, those are burned. |
| **Windows CVE-2026-96951** (Oct Patch Tuesday) | One actively exploited zero-day (MotW bypass, CVSS 8.8) in a record **1,413-CVE** release. Details from a low-quality source. | Apply October cumulative updates. Confirm against MSRC before quoting the CVE. |
| **Collabora Online CVE-2026-110447** (CVSS 9.8) | In KEV roundups but unverified against primary source. Self-hosted LibreOffice in the browser. | Patch if you run Collabora Online. |
| **JetBrains TeamCity CVE-2026-63077** | Ransomware-linked per KEV roundup. CI/CD compromise is a supply chain multiplier. | Patch per JetBrains advisory. Audit pipeline configurations and build artifacts. |
| **ShinyHunters' "second PeopleSoft 0-day"** | Claimed, not demonstrated. | Assume it exists. Get PeopleSoft off the open internet behind an authenticated proxy. |
| **CVE-2026-63378 (TAKO AI Agent for Okta)** | Third-party product (not Okta's own), but any authenticated user could execute arbitrary Python. CVSS 8.8. | Upgrade to 3.0.1-beta+. Audit for code execution artifacts. |

---

## 14. Patterns in the Graveyard: What Black October Teaches

**14.1 Identity is the new perimeter — and the new target.** The DHS leak didn't come through a buffer overflow or an RCE. It came through the **identity directory**. Okta Access Gateway shipped four CVEs in one advisory. The pattern is clear: attackers aren't just going around your identity layer — they're going *through* it. The SSO system that knows where everyone sits is the most valuable target on your network.

**14.2 The edge is the target.** NetScaler, FortiMail, BeyondTrust, PAN-OS, and a PeopleSoft portal facing the internet: four of the ten headliners are appliances or portals whose *whole job* is to sit on the internet and broker access to something internal. They are hard to monitor (closed OS, limited EDR) and highly privileged. Defenders should stop treating them as trusted infrastructure.

**14.3 The floor is the target.** The Linux kernel TCP UAF (CVE-2026-98432) and PHP2Shell show that the *platforms everything runs on* are themselves vulnerable. You can write perfect application code and still get owned because the kernel or the runtime underneath you has a use-after-free. Defense in depth means defending the layers you didn't write.

**14.4 A WAF rule is a speed bump.** PeopleSoft (`%50SEMHUB`) and PHP2Shell (payloads mutated within hours of Cloudflare's rules) both showed that signature-based filtering buys hours, not months. A WAF is a good bridge to a patch, and it fails as a replacement for one.

**14.5 Canonicalization bugs never die.** `%50` vs `P`. `file.so\0.png` vs `file.so`. Raw `$request_uri` vs normalized `$uri`. Whenever two components interpret the same bytes differently, the attacker gets to choose which interpretation wins. **Normalize once, early, then validate the normalized form, and pass that same form downstream.**

**14.6 Memory-safety bugs in C runtimes keep paying out.** PHP2Shell is a UAF and an uninitialized-memory bug in a 30-year-old C codebase that powers a large fraction of the web. The Linux TCP bug is a UAF in C code that's been in the kernel for years. Citrix 88772/88779 are memory overflows. This is the strongest argument yet for memory-safe rewrites of edge-facing parsers and network stacks.

**14.7 Trust is the vulnerability.** A contractor's missed patch exposed the FBI. Negotiators allegedly knew about breaches before victims did. A remote-support tool became a lateral-movement highway. An SSO directory exposed 41,000 federal agents. The question to ask is "who can reach my systems, and what happens when *they* get owned?", not only "what's my CVSS backlog?"

**14.8 AI is entering the exploit development loop.** Anthropic's claim about CVE-2026-98432 — whether fully reproducible or not — signals that the time from CVE publication to working exploit is compressing. When AI models can autonomously analyze patches, identify the vulnerability, and generate exploit code, the window between "patch available" and "exploit in the wild" shrinks toward zero. Patch faster.

---

## 15. Theme: Modernizing the Haunted House

> *Nginx modernization, securing the configuration, IP limiting, DoS detection and verification.*

For this section we use the **Fortress of Solitude**, our encrypted file vault (Django + Gunicorn + Nginx on Cloud Run), as the worked example of doing it right. The general hardening patterns that follow apply to any web stack, so you can hold your own site up against them. Earlier Fortress posts: [Encryption](../05-03-2025_FortressOfSolitude_Encryption.md), [Kryptonian Cryptography in Django](../05042025_KryptonianCryptographyInDjango.md), [Securing Data at Rest](../11-2-2025_Securing_Data_At_Rest.md).

> **Why the specifics are light here.** The Fortress is a live service. This post describes *which* controls it uses and *why*, but deliberately leaves out exact thresholds, endpoint names, and blocklist contents. Telling attackers how fast they can go before getting banned is not a defensive act.

### 15.1 What the Fortress gets right

**My verdict up front:** after reading the code and deploy scripts and checking the live deployment, the Fortress of Solitude is a **highly secure website**. It is hardened beyond what most commercial websites ship. Most production sites we look at don't have even half of this: per-endpoint rate limits, automatic IP banning built from a real threat hunt, a strict header set, an app server that never faces the internet, ephemeral runtime data, a secret key regenerated on every deploy, and per-object envelope encryption, so a stolen database is ciphertext. What a large enterprise adds on top is mostly *scale* and *process*: DDoS scrubbing, a 24/7 SOC, third-party pentests. Those are a different job from building it right.

| Control | How it's done | Black October relevance |
|---|---|---|
| **App server never faces the internet** | Gunicorn binds to loopback; only Nginx listens externally | The opposite of an exposed PSEMHUB or a management interface |
| **Tiered rate limiting** | Separate `limit_req` zones for authentication, API/upload, and general traffic, plus a slow "hammer" zone | Brute force is throttled before the application ever sees it |
| **Connection limits + slowloris timeouts** | `limit_conn` per IP, short body/header/send timeouts, `reset_timedout_connection on` | Cheap layer-7 DoS defense |
| **Two-tier IP banning** | Nginx throttles in real time; a watcher daemon turns persistent offenders into temporary `deny` rules | Hammers get shown the door automatically |
| **Threat-hunt-driven blocklist** | Datacenter ranges observed in a real hunt are closed with `444` (no response at all) | Defense built from evidence, not guesswork |
| **Strict security headers** | CSP, `Permissions-Policy`, COOP, `nosniff`, frame denial, `no-store` on auth pages, `Secure` CSRF cookie (verified live) | Limits XSS, clickjacking, and cache leakage |
| **Method allowlist; dotfiles denied** | `405` on anything off-list; dot-paths denied | `.env`/`.git` stay private |
| **Nothing advertised** | `server_tokens off`; the only `Server` header is Google Frontend | Version-targeted scanning has nothing to work with |
| **Envelope encryption at rest** | Per-object DEKs wrapped by KEKs, AES-EAX (authenticated) | See §16 |
| **Ephemeral runtime data, by design** | The data directory is a container volume that is wiped on restart; the only durable copy is the off-site backup, and `docker commit` never captures volume contents | Nothing private lingers in a container or an image |
| **Consistent backups with integrity checks** | `sqlite3 .backup` (not `cp`) + `PRAGMA integrity_check` + off-site copy | Recovery from ShinyHunters-style destruction |
| **Fresh secret on every deploy** | The deploy script generates a strong `SECRET_KEY` and injects it at deploy time; the file holding it is excluded from git and from the build | No default key in prod |
| **Cold-start fix shipped** | Deployed with a warm minimum instance and CPU boost | Removes the false-alarm 502s the threat hunt traced to scaling from zero |
| **Cost-DoS ceiling** | Hard cap on autoscaling instances | A flood can't autoscale your bill to the moon |
| **No credentials in env vars** | Admin creation passes credentials through a short-lived file that is deleted on both sides after use | Creds never show up in the service description |
| **Versioned, migrated-before-live images** | Semantic-version validation; migrations run *before* the image is pushed | Clean rollbacks; no half-migrated prod |
| **Public data, public key** | The only key material in configuration protects the *public* research tab (posts anyone can read without logging in); user data is keyed per user | Nothing secret depends on a value in the repo |
| **Verifying before banning** | The Oct 16 threat hunt concluded the 502s were **cold starts, not an attack** | See §14.5 |

### 15.2 Lesson from PeopleSoft: match on the *normalized* URI

The `%50SEMHUB` bypass works against any filter that inspects the URI *as sent* while the backend routes on the URI *after decoding*. In nginx terms, that is the difference between two variables:

- **`$request_uri`**: the raw, undecoded URI **including the query string**.
- **`$uri`**: percent-decoded and normalized (`//` merged, `.` and `..` resolved, requests that climb above root rejected with 400). **`location` matching uses this one.**

A hand-rolled "WAF map" on `$request_uri` is a common pattern, and it inherits the PeopleSoft problem:

| Probe | Rule on raw `$request_uri` | Caught? | Why |
|---|---|---|---|
| `/../etc/passwd` | `~*\.\.` | ✅ | literal match |
| `/%2e%2e/%2e%2e/%65tc/passwd` | `~*\.\.`, `~*/etc/passwd` | ❌ | encoded characters never match the literals |
| `/shell.php?x=1` | `~*\.php$` | ❌ | `$` anchors at the end of the *query string* |
| `/shell.php/` | `~*\.php$` | ❌ | trailing slash |
| `/%50SEMHUB/` | `~*/PSEMHUB` | ❌ | the PeopleSoft bypass itself |

Rules written as `location` blocks inherit nginx's normalization for free:

```nginx
# Match on the normalized path, so encoding tricks don't help.
location ~* \.(php|asp|aspx|jsp|cgi)(/|$)     { return 404; }
location ~* /(wp-admin|wp-login|phpmyadmin)    { return 404; }
location ~* ^/PSEMHUB                           { return 404; }   # /%50SEMHUB/ decodes to this

# Separately reject double-encoding on the raw URI: there's rarely a legitimate
# reason for %25 followed by hex in an application's routes.
map $request_uri $double_encoded {
    default          0;
    ~*%25[0-9a-f]{2} 1;
}
```

**One more subtlety:** `proxy_pass http://127.0.0.1:8000;` (no URI part) forwards the **original raw URI** to the upstream, not the normalized one. The upstream must be safe against encoded input on its own. The Fortress gets this right by design: files are served through authenticated views that look up records in the database, never by mapping a URL onto the filesystem, so there is no path to traverse. Defense in depth means **both** layers validate.

**SQLi/XSS regexes** (`union.*select`, `<script`) at the proxy are useful as tripwires for logging, but treat them as **noise filters, not protection**. The real protection is parameterized queries (the Django ORM) and template auto-escaping. Logged hits are threat intel (§15.5).

### 15.3 Secure-configuration patterns

General patterns worth checking in any nginx + app-server deployment:

**The `add_header` inheritance trap.** In nginx, `add_header` directives are inherited from the enclosing level **only if the current level defines no `add_header` of its own.** Any `location` that sets even one header (say, `Cache-Control` on static files) silently drops every server-level security header on those responses. Put the headers in a snippet and include it wherever a location sets its own:

```nginx
# /etc/nginx/snippets/security-headers.conf
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
# X-XSS-Protection is deprecated and ignored by modern browsers; CSP replaces it.
```

```nginx
location /static/ {
    alias /app/staticfiles/;
    expires 30d;
    add_header Cache-Control "public, immutable";
    include snippets/security-headers.conf;   # ← re-include; otherwise they vanish here
}
```

If both the framework (e.g., Django's `SecurityMiddleware`) and nginx set headers, pick **one layer to own each header**. When duplicates conflict, browsers resolve them in ways you didn't choose.

**Fail closed on secrets.** Production settings should refuse to start without their secrets, rather than falling back to a development default:

```python
import os
from django.core.exceptions import ImproperlyConfigured

def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ImproperlyConfigured(f"{name} must be set in production")
    return value

SECRET_KEY = require_env("DJANGO_SECRET_KEY")
ALLOWED_HOSTS = require_env("APP_ALLOWED_HOSTS").split(",")   # explicit hosts, never "*"
```

On Cloud Run, **Secret Manager** (`--set-secrets=...`) keeps values out of the service description, and **Cloud KMS** keeps root keys out of the application entirely (§16.2).

**Least privilege in the container.** Run as a non-root `USER`, use a read-only root filesystem with `tmpfs` for scratch space, drop capabilities, and use multi-stage builds so compilers don't ship in the runtime image. Every exploit in this post ended with "web service account → something more." Don't start at root.

**Mind the build context.** `.dockerignore` patterns without `**/` only match at the context root, so `*.sqlite3` does not exclude `some/dir/db.sqlite3`. Use `**/*.sqlite3`, `**/*.key`, and explicit directory entries for anything that holds data, logs, or keys. Check with a throwaway build (`COPY . /ctx` + `RUN find /ctx ...`) to see exactly what goes in.

**Never log key material.** Use `logging` at DEBUG level instead of `print()` on crypto error paths. In the cloud, stdout goes to a log service with very different access controls from your key store.

### 15.4 IP limiting done right

**Know who `$remote_addr` really is.** Behind a load balancer or CDN, nginx may see the *proxy's* address instead of the client's. Then every user shares one rate-limit bucket, and an auto-banner can end up **banning your own load balancer**. Verify with one request and check the access log. If the first field isn't your public IP, configure the realip module with *only* your trusted proxy ranges:

```nginx
# http {} — trust X-Forwarded-For ONLY from your proxy tier
set_real_ip_from 10.0.0.0/8;          # ← replace with your LB/proxy ranges
real_ip_header   X-Forwarded-For;
real_ip_recursive on;
```

> Never `set_real_ip_from 0.0.0.0/0`. That lets any client spoof `X-Forwarded-For: 1.2.3.4` to dodge your limits or frame someone else for a ban.

**An allowlist that skips rate limits** (owner, monitoring) without `if`:

```nginx
geo $limit_exempt {
    default 0;
    203.0.113.10/32 1;    # owner
}
map $limit_exempt $limit_key {
    0 $binary_remote_addr;
    1 "";                 # empty key = request not counted by limit_req
}
limit_req_zone $limit_key zone=auth:10m    rate=3r/s;
limit_req_zone $limit_key zone=general:10m rate=10r/s;
```

**Line windows vs. clock windows.** The Fortress's ban daemon uses a **share-of-recent-traffic** detector: it looks at a rolling window of the most recent *logged requests* and flags any address that holds an outsized share of them. That is a deliberate choice, and a smart one:

- **It's pace-independent.** A clock window (N requests per 60 s) can be evaded by an attacker who paces just under the threshold forever: 59 requests a minute is still 85,000 a day. A line window doesn't care how slowly requests arrive. If one address keeps dominating what the server has *recorded*, it gets flagged.
- **It's a second tier.** Nginx's `limit_req` already enforces per-second limits. The daemon catches whoever keeps coming back after being throttled, and it also watches the rate-limited log for repeat offenders.
- **It self-scales on a small site.** On a low-traffic service, one address owning a large slice of recent traffic is anomalous whatever the time span.

| Situation | Line window | Clock window |
|---|---|---|
| Slow, persistent single-IP hammer | ✅ caught | ❌ evades by pacing |
| Single-IP burst | ✅ caught (and `limit_req` throttles first) | ✅ caught |
| Distributed flood (many IPs, few requests each) | ❌ | ❌ |
| Legit heavy user on a quiet site | ⚠ allowlist them | ✅ usually fine |

Distributed floods beat *every* per-IP detector. That's upstream territory: Cloud Armor, a CDN, or per-ASN/prefix aggregation.

**Hygiene for any auto-banner:** validate addresses before writing them into nginx config, use fixed-string matching (`grep -F`) when checking a ban list (a `.` in an IP is a regex wildcard), and run `nginx -t` before every reload. **CrowdSec** (community reputation plus an nginx bouncer) or **fail2ban** can add shared blocklists, persistence, and IPv6 prefix aggregation on top. Banning a single `/128` means little when an attacker holds a `/64`.

**User-agent blocking is a tripwire, not a lock.** It stops lazy `sqlmap` and `curl` runs. Anyone serious sends a Chrome UA string. Keep it for the noise reduction, but don't count it as a control.

### 15.5 DoS detection and verification

**Detection: what to watch.**

| Signal | Source | What it means |
|---|---|---|
| 429 rate climbing | nginx `$status` | Limits are working. *Who* is hitting them? |
| 444 rate | nginx | Blocklist hits (connection dropped) |
| 499 spikes | nginx | Clients giving up, so latency is too high (possibly under load) |
| 502/504 spikes | nginx + upstream | Backend saturation, crash, **or cold start** |
| `$request_time` p95/p99 | custom `log_format` | Slow-path abuse (expensive endpoints, regex DoS) |
| Many open conns, few requests | `stub_status` (`Reading`/`Waiting`) | Slowloris-style connection holding |
| `limiting requests` / `limiting connections` | nginx `error.log` | Which zone fired, for which key |

```nginx
location = /_nginx_status {
    stub_status;
    allow 127.0.0.1;
    deny all;
}
```

**Verification: prove the controls work, and prove it's really an attack.**

1. **Test your limits on staging, with your own traffic.** Never point load tools at systems you don't own.

   ```bash
   # 40 rapid POSTs to a rate-limited login endpoint on YOUR staging host.
   # Expect roughly (rate + burst) to reach the app and the rest to get 429.
   UA='Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0 Safari/537.36'   # if you block curl's UA, as you should
   for i in $(seq 1 40); do
     curl -sk -o /dev/null -w '%{http_code}\n' -A "$UA" -X POST https://staging.example.internal/login/
   done | sort | uniq -c
   ```

   For sustained load, use `k6` or `vegeta` at a fixed rate and confirm `limit_req` holds the upstream at the configured ceiling. For slowloris, run `slowhttptest` against staging and confirm your header timeout drops held connections.

2. **Correlate before you call it an attack.** The Fortress's Oct 16 hunt is the model to copy. It took the IPs active just before each 502, enriched them (ASN, rDNS, netblock), and found that **known-friendly addresses were in the "suspect" list**. The failure pattern (a few requests, then a 502) matched **scaling from zero**. The fix was a warm minimum instance, not more bans. *Verify, then ban.*

3. **Separate the three DoS shapes:**
   - **Volumetric** (Gbps floods): nginx can't help, because the pipe is full before packets arrive. That is the job of your CDN or cloud (Cloud Armor, Cloudflare).
   - **Protocol/connection** (slowloris, SYN, HTTP/2 rapid reset): timeouts, `limit_conn`, an up-to-date nginx, and `http2_max_concurrent_streams`.
   - **Application** (expensive endpoints, login hammering, multipart bombs like PHP2Shell's OOM trigger): `limit_req`, `client_max_body_size`, and fixing the expensive code path.

### 15.6 Putting it together: a modern nginx skeleton

A generic starting point for an app server behind nginx:

```nginx
# /etc/nginx/conf.d/app.conf  (http context)
server_tokens off;

set_real_ip_from 10.0.0.0/8;           # your proxy tier only
real_ip_header   X-Forwarded-For;
real_ip_recursive on;

geo $limit_exempt { default 0; }
map $limit_exempt $limit_key { 0 $binary_remote_addr; 1 ""; }
limit_req_zone  $limit_key zone=auth:10m    rate=3r/s;
limit_req_zone  $limit_key zone=api:10m     rate=5r/s;
limit_req_zone  $limit_key zone=general:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_req_status  429;
limit_conn_status 429;

map $request_uri $double_encoded { default 0; ~*%25[0-9a-f]{2} 1; }
map $request_method $bad_method  { default 1; ~^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$ 0; }

log_format sec '$msec $remote_addr $status "$request" rl=$request_length rt=$request_time '
               'up=$upstream_status ct="$content_type" "$http_user_agent"';

upstream app { server 127.0.0.1:8000; keepalive 16; }

server {
    listen 443 ssl;
    http2 on;
    server_name app.example.com;

    include snippets/tls-modern.conf;          # §16.5
    include snippets/security-headers.conf;    # §15.3

    access_log /var/log/nginx/sec.log sec;

    client_max_body_size        50m;           # size to your uploads; PHP sites usually far lower
    client_body_timeout         10s;
    client_header_timeout       10s;
    send_timeout                10s;
    keepalive_timeout           30s;
    reset_timedout_connection   on;
    http2_max_concurrent_streams 64;
    limit_conn addr 20;

    if ($bad_method)     { return 405; }       # return-only 'if' is safe
    if ($double_encoded) { return 400; }

    # Normalized-path denials ($uri, not $request_uri)
    location ~ /\.                                 { return 404; }
    location ~* \.(php|asp|aspx|jsp|cgi)(/|$)      { return 404; }

    location ~ ^/(login|register)/ {
        limit_req zone=auth burst=5 nodelay;
        include snippets/proxy-app.conf;
    }
    location ~ ^/(upload|api)/ {
        limit_req zone=api burst=10 nodelay;
        include snippets/proxy-app.conf;
    }
    location /static/ {
        alias /app/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
        include snippets/security-headers.conf;
    }
    location / {
        limit_req zone=general burst=20 nodelay;
        include snippets/proxy-app.conf;
    }
}
```

```nginx
# snippets/proxy-app.conf
proxy_pass http://app;
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_connect_timeout 5s;
proxy_read_timeout    60s;     # longer only on upload locations
```

---

## 16. Theme: Data at Rest and in Transit — Lessons From the Fortress of Solitude

Every headliner this month ended with **data leaving the building**: DHS employee identities, FBI employee files, PHP worker memory, credentials brokered by BeyondTrust, mail on FortiMail. You can't make breaches impossible. You can make the stolen data **worthless**, and that is where the Fortress design pays off.

### 16.1 What the Fortress does: envelope encryption

```text
user secret ──► KEK (key-encryption key, per user)
                  │  wraps
                  ▼
                DEK (data-encryption key, per object) ──► AES-EAX(file/note) → ciphertext + 16-byte tag
```

- **Per-object DEKs.** Compromising one object's key exposes one object.
- **DEKs are stored wrapped**, never in plaintext next to the data.
- **AES-EAX is authenticated encryption.** Tampered ciphertext fails tag verification instead of decrypting to garbage, which defeats the bit-flipping and padding-oracle tricks that plain CBC allows.
- **Public and private are separated.** The public research tab, which anyone can read without logging in, has its own key path. Private user data never shares it.
- **A stolen database is ciphertext.** If ShinyHunters walked off with the Fortress database, they'd hold encrypted blobs and wrapped keys, not readable files.

That is the property the FBI's HR records, the DHS employee directory, and every PeopleSoft tenant this month didn't have. The DHS leak is particularly instructive: the directory records were stored in a way that a compromised SSO system could read them in bulk. If those records had been encrypted at rest with scoped access controls, the breach would have yielded ciphertext, not a searchable database of 41,000 federal agents.

### 16.2 Patterns for any encrypted store

If you're building your own vault, these are the patterns to reach for:

**Use a memory-hard KDF for anything derived from a password.** A single fast hash lets an attacker with your database try billions of guesses per second on a GPU. **Argon2id** is the current standard, and the Python `cryptography` package ships it:

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def derive_kek(password: bytes, salt: bytes) -> bytes:
    # 64 MiB, 3 passes, 4 lanes. Tune so a derive takes ~250 ms on your hardware.
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4,
                    memory_cost=64 * 1024).derive(password)

def wrap_dek(kek: bytes, dek: bytes, record_id: bytes) -> bytes:
    nonce = os.urandom(12)
    # AAD binds the wrapped key to its record, so it can't be swapped onto another row.
    return nonce + AESGCM(kek).encrypt(nonce, dek, record_id)

def unwrap_dek(kek: bytes, blob: bytes, record_id: bytes) -> bytes:
    return AESGCM(kek).decrypt(blob[:12], blob[12:], record_id)
```

Store the per-user random salt and the Argon2 parameters alongside the wrapped KEK, so you can raise the cost later and re-wrap on next login.

**Bind ciphertext to context with AAD.** Include the record ID (and owner ID) as associated data, so an attacker with database *write* access can't swap one user's encrypted note into another user's row.

**Keep root keys in KMS.** With **Cloud KMS** (or an HSM), the app sends a wrapped key and gets the unwrapped key back, and the root key never leaves the KMS. A full repo-plus-database leak still lacks the root of the hierarchy, and every unwrap lands in Cloud Audit Logs.

**Plan for post-quantum.** Anything protected by RSA or classic ECDH today is exposed to harvest-now-decrypt-later. Our [RiddlerChat PQC post](../07-14-2026-PostQuantumCryptography-TheRiddlerChatSystem.md) covers hybrid ML-KEM + X25519.

### 16.3 Secrets hygiene (the stuff PHP2Shell would have stolen)

- **Short-lived credentials.** Use workload identity instead of static keys wherever possible. The Fortress backup daemon already does this: it gets its storage access from the metadata server, with no key file.
- **Rotate on suspicion, not on schedule.** After any memory-disclosure bug (PHP2Shell, the next Heartbleed), assume every secret that passed through process memory is burned.
- **Separate what the web tier can read.** The process that parses untrusted HTTP shouldn't hold root key material. Put unwrapping behind a small internal service or a KMS call.

### 16.4 Backups that survive an extortion crew

The Fortress backup daemon gets the hard parts right: a consistent `.backup` snapshot, an integrity check, an off-site copy, and automatic restore when a fresh container starts empty. For the ShinyHunters threat model, any backup design should also have:

1. **Client-side encryption before upload** (`age -r <recipient-pubkey>`), or a **CMEK** default key on the bucket, so metadata and table structure are protected too, not just the encrypted payloads.
2. **Immutability.** If the workload that *writes* backups can also *delete* them, an attacker who controls the workload controls your backups. Enable **Object Versioning + Soft Delete + a retention policy**, and give the writer create-only permissions:

   ```bash
   gcloud storage buckets update gs://YOUR-BACKUP-BUCKET \
       --versioning --soft-delete-duration=30d --retention-period=14d
   # Writer service account: roles/storage.objectCreator (no delete)
   ```

3. **Restore drills.** Restore into a scratch environment on a schedule. A backup you've never restored is only a hope.

### 16.5 Data in transit

**Public edge.** Cloud Run terminates TLS with Google-managed certs, which is good. On the live Fortress endpoint, every byte between the browser and Google's edge is encrypted with **AES-256-GCM** (`TLS_AES_256_GCM_SHA384`) over **TLS 1.3**, on HTTP/2 and HTTP/3. TLS 1.3 key exchange is always ephemeral, so each session gets a fresh AES-256 key and forward secrecy is guaranteed: a key stolen tomorrow can't decrypt traffic recorded today. And because the whole `.app` TLD is on the browser HSTS preload list, browsers refuse to talk to it over plain HTTP at all.

For self-hosted nginx, a modern TLS baseline:

```nginx
# snippets/tls-modern.conf
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;          # let clients pick; all options are strong
ssl_session_timeout 1d;
ssl_session_cache shared:TLS:10m;
ssl_session_tickets off;                # tickets undermine forward secrecy unless keys rotate
# With OpenSSL >= 3.5, add hybrid post-quantum key exchange:
# ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
# With a publicly trusted cert:
# ssl_stapling on; ssl_stapling_verify on;
```

Every suite listed uses ECDHE (forward secrecy) and an AEAD cipher. Static-RSA suites like `AES256-GCM-SHA384` don't provide forward secrecy and should be left out. The ML-KEM hybrid line needs OpenSSL 3.5+ (Ubuntu 24.04 ships 3.0), and it's worth doing for anything harvest-now-decrypt-later matters to.

**Internal hops.** Nginx → app server over `127.0.0.1` inside one container never touches a network, which is exactly how the Fortress does it. Once services split across hosts (app ↔ DB, app ↔ KMS proxy), use **mTLS** with short-lived certs. "It's on the internal network" is the assumption BeyondTrust's downstream victims made.

**Verify it.** `testssl.sh https://your.host` (or `sslscan`) should show no TLS 1.0/1.1, no suites without forward secrecy, and your security headers on *every* response.

---

## 17. The Exorcism Checklist

> *One checklist to rule them all. One checklist to find them. One checklist to bring them all, and in the darkness bind them.* 🧙

**This week (incident-driven)**

- [ ] **DHS/Okta:** If you use Okta Access Gateway, upgrade to 2026.10.2. Audit directory access scopes. Alert on bulk enumeration. Review who has global directory read.
- [ ] **PeopleSoft:** Oracle June 10 patch applied; PSEMHUB disabled or off-internet; logs hunted for `PSEMHUB` **and** encoded variants; web dirs checked for unexpected JSP/executables
- [ ] **Linux TCP (CVE-2026-98432):** Check distro patch status; disable MPTCP if not needed; apply livepatch if available; monitor Red Hat and Ubuntu trackers for stable fixes
- [ ] **PHP:** every *serving* runtime at 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or distro equivalent; workers restarted; secrets rotated if exposed before patching
- [ ] **PHP interim (if blocked):** `session.upload_progress.enabled=0` via `php_admin_value`; body-size limits at the proxy; multipart blocked where unused
- [ ] **Okta Access Gateway:** upgraded to 2026.10.2; Admin Console access audited; SAML assertions reviewed
- [ ] **NetScaler:** IOC check **before** patching; 14.1-73.41 / 13.1-64.28 if SAML is in use; logs off-box; creds/KEKs/certs rotated if compromised
- [ ] **BeyondTrust:** BT26-05 applied; appliances exposed since late Aug reviewed as compromised; brokered creds rotated
- [ ] **FortiMail:** IBE disabled, management interface off-internet, upgrade to fixed build; `/etc/ld.so.preload` checked
- [ ] **PAN-OS:** CVE-2026-0322 patched; management interface not internet-reachable; admin creds rotated
- [ ] **Atlassian:** Patched per advisory; audited for new admin accounts and API tokens; searched Confluence for stored credentials

**This quarter (structural)**

- [ ] Patch SLA tied to KEV/CVSS (e.g., KEV + internet-facing = 72 h)
- [ ] Third-party/contractor patch status visible in *your* vulnerability management
- [ ] **IdP is Tier-0:** Okta/Entra/Ping admin access requires FIDO2, is logged, and is reviewed weekly
- [ ] **Directory data minimized:** SSO directories expose only what authentication requires, not org charts, office locations, or operational roles
- [ ] Phishing-resistant MFA (FIDO2) for every admin and remote-access path
- [ ] Edge appliance logs forwarded to a SIEM with retention beyond on-box rotation
- [ ] WAF rules match on normalized input, and are tracked as temporary with an expiry date
- [ ] Extortion playbook: vetted negotiator, legal, comms, decision authority
- [ ] **Kernel patching plan:** Livepatch or kpatch subscription active for production servers; test pipeline for kernel updates

**Hardening your own web stack (the Fortress playbook)**

- [ ] App server bound to loopback; only the reverse proxy faces the internet
- [ ] Tiered `limit_req` zones (auth / API / general) + `limit_conn` + short timeouts
- [ ] Two-tier banning: real-time throttling plus a share-of-traffic daemon for persistent offenders; owner allowlisted; `nginx -t` before reload
- [ ] `realip` configured for trusted proxies only; confirm `$remote_addr` is the client
- [ ] Path rules on `$uri` / `location`, plus a double-encoding reject
- [ ] Security-header snippet included in every location that sets its own headers; one layer owns each header
- [ ] Secrets generated at deploy time, fail-closed settings, explicit `ALLOWED_HOSTS`; Secret Manager/KMS for anything sensitive
- [ ] Ephemeral runtime data; `**/`-style `.dockerignore`; non-root, read-only container
- [ ] Envelope encryption with authenticated ciphers; memory-hard KDFs; AAD binding
- [ ] Backups consistent, integrity-checked, encrypted, immutable; restore drills
- [ ] TLS 1.3 / ECDHE-only suites; HSTS (or a preloaded TLD); PQ hybrid when OpenSSL allows
- [ ] Rate limits and slowloris timeouts **tested on staging**; alerts on 429/499/5xx/p99 latency; *verify, then ban*

---

## 18. References

**DHS / CBP / ICE Data Leak**

1. Washington Post — [ICE, CBP and other DHS officer identities posted online in data breach](https://www.washingtonpost.com/immigration/2026/10/28/ice-cbp-other-dhs-officer-identities-posted-online-data-breach/)
2. Cybernews — [DHS employee data leak exposes 41,000 staff records](https://cybernews.com/security/massive-breach-hits-dhs-41000-employees-exposed/)
3. Gizmodo — [Data From More Than 41,000 DHS Workers Exposed in Massive Leak](https://gizmodo.com/data-from-more-than-41000-dhs-workers-exposed-in-massive-leak-2000832595)
4. Fox News — [DHS investigates massive data breach exposing 40,000 employees, including ICE and Border Patrol agents](https://www.foxnews.com/us/dhs-investigates-massive-data-breach-exposing-40000-employees-including-ice-border-patrol-agents)
5. TechTimes — [DHS Data Breach Exposes Information on 41,000 Employees, Including ICE and CBP Staff](https://www.techtimes.com/articles/329689/20261029/dhs-data-breach-exposes-information-41000-employees-including-ice-cbp-staff.htm)

**Pentagon / DMDC Breach**

6. TechCrunch — [Hackers stole millions of US military personnel records during months-long data breach](https://techcrunch.com/2026/09/30/hackers-stole-millions-of-us-military-personnel-records-during-months-long-data-breach/)
7. Malwarebytes — [Pentagon breach exposes Social Security numbers and military records of millions](https://www.malwarebytes.com/blog/privacy/2026/10/pentagon-breach-exposes-social-security-numbers-and-military-records-of-millions)
8. Yahoo News — [Pentagon breach exposed sensitive data on nearly 3 million people](https://www.yahoo.com/news/articles/pentagon-breach-exposed-sensitive-data-224957938.html)
9. Cybersecurity News — [Pentagon Data Breach - Hackers Reportedly Accessed 3 Million People's Sensitive Data](https://cybersecuritynews.com/pentagon-data-breach/)

**ShinyHunters / PeopleSoft**

10. S-RM — [ShinyHunters claim FBI breach amid renewed PeopleSoft attacks (2 Oct 2026)](https://www.s-rminform.com/cyber-intelligence-briefing/shinyhunters-claim-fbi-breach-amid-renewed-peoplesoft-attacks-2-october-2026)
7. SecurityWeek — [FBI Blames Contractor's Missed Patch for ShinyHunters Breach](https://www.securityweek.com/fbi-blames-contractors-missed-patch-for-shinyhunters-breach/)
8. KrebsOnSecurity — [Feds Suspect Ransom Negotiator Ran ShinyHunters Extortion Site](https://krebsonsecurity.com/2026/10/feds-suspect-ransom-negotiator-ran-shinyhunters-extortion-site/)
9. Cybernews — [ShinyHunters probe: ransomware negotiators suspected](https://cybernews.com/security/shinyhunters-extortion-site-ransom-negotiators/)
10. BleepingComputer — [ShinyHunters uses WAF bypass trick in Oracle PeopleSoft attacks](https://www.bleepingcomputer.com/news/security/shinyhunters-uses-waf-bypass-trick-in-oracle-peoplesoft-attacks/)
11. The Hacker News — [Attackers bypass WAFs to exploit Oracle](https://thehackernews.com/2026/09/attackers-bypass-wafs-to-exploit-oracle.html)
12. eSecurityPlanet — [ShinyHunters Bypasses PeopleSoft WAF in Renewed Exploitation](https://www.esecurityplanet.com/cybersecurity-threats/news-shinyhunters-peoplesoft-waf-bypass/)
13. Cybernews — [ShinyHunters targeting Oracle zero-day days after FBI attack, Google warns](https://cybernews.com/security/shinyhunters-oracle-zero-day-fbi-attack-google-warning/)
14. Hackaday — [This Week In Security: ShinyHunters Won't Dox The FBI…](https://hackaday.com/2026/10/02/this-week-in-security-shinyhunters-wont-dox-the-fbi-pentagon-data-stolen-and-obs-vulnerable/)

**Linux Kernel TCP (CVE-2026-98432)**

15. The Hacker News — [Linux Kernel TCP Flaw With 9.8 CVSS Score Affects Ubuntu, Red Hat and Other Distributions](https://thehackernews.com/2026/10/linux-kernel-tcp-flaw-with-98-cvss.html)
16. TuxCare — [CVE-2026-98432 Linux Kernel TCP Flaw, Claude's Claimed Root Exploit and Which Distros Are Patched](https://tuxcare.com/blog/cve-2026-98432-linux-tcp-remote-root/)
17. AlmaLinux — [CVE-2026-98432: Patched kernels available in testing](https://almalinux.org/blog/2026-10-30-cve-2026-98432/)
18. Rescana — [Linux Kernel CVE-2026-98432: Critical TCP Use-After-Free, No RHEL or Ubuntu Fix Yet](https://www.rescana.com/post/linux-kernel-tcp-cve-2026-98432-use-after-free-prepare-now)
19. CloudLinux — [CVE-2026-98432 Linux kernel IPv4 TCP flaw: status for CloudLinux](https://blog.cloudlinux.com/cve-2026-98432-linux-kernel-ipv4-tcp-flaw-status-for-cloudlinux)

**PHP2Shell**

20. The Hacker News — [PHP Issues Emergency Patches for Two Critical PHP2Shell RCE Flaws](https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html)
21. Qualys — [PHP announces critical security release for two vulnerabilities](https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities)
22. Sophos — [Proof-of-concept exploit released for PHP vulnerabilities](https://www.sophos.com/en-us/blog/proof-of-concept-exploit-released-for-php-vulnerabilities-109618-109619)
23. Google Cloud — [Responding to core PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619](https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619)
24. Infosecurity Magazine — [Critical PHP Vulnerabilities Leaked Ahead of Scheduled Security Patch](https://www.infosecurity-magazine.com/news/critical-php-vulnerabilities-leaked/)
25. SOCRadar — [PHP2Shell: Affected Versions & Fix](https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/)
26. Aikido — [PHP2Shell: How to fix PHP RCE](https://www.aikido.dev/blog/critical-vulnerabilities-in-php-php2shell)
27. UW-IT — [Critical PHP vulnerabilities (Oct 2026)](https://it.uw.edu/help/servicestatus/php-cves/)

**Okta Access Gateway**

28. Okta — [Command Execution via Admin Console Input in Okta Access Gateway CVE-2026-115547](https://trust.okta.com/security-advisories/command-execution-via-admin-console-input-in-okta-access-gateway-cve-2026-115547/)
29. CyberKendra — [Okta Patches Critical Access Gateway Flaw CVE-2026-115547](https://www.cyberkendra.com/2026/10/cve-2026-115547-okta-access-gateway-command-execution.html)
30. SecurityOnline — [Okta Access Gateway Vulnerabilities Include PHP2Shell](https://securityonline.info/okta-access-gateway-vulnerabilities-php2shell/)
31. Rescana — [Critical Command Execution Vulnerability in Okta Access Gateway Admin Console (CVE-2026-115547)](https://www.rescana.com/post/critical-command-execution-vulnerability-in-okta-access-gateway-admin-console-cve-2026-115547-impact-exploitation-and-mi)

**Zero-days**

32. CISA — [Critical Zero-Day Vulnerabilities Exploited in Citrix NetScaler ADC, Gateway](https://www.cisa.gov/news-events/alerts/2026/09/27/critical-zero-day-vulnerabilities-exploited-citrix-netscaler-adc-gateway)
33. Citrix — [CTX697096](https://support.citrix.com/external/article/CTX697096)
34. CSO Online — [Citrix warns of actively exploited NetScaler flaw days after zero-day patch rush](https://www.csoonline.com/article/4230642/citrix-warns-of-actively-exploited-netscaler-flaw-days-after-zero-day-patch-rush.html)
35. BleepingComputer — [BeyondTrust patches zero-day exploited in attacks since August](https://bleepingcomputer.com/news/security/beyondtrust-patches-zero-day-exploited-in-attacks-since-august)
36. CSO Online — [BeyondTrust zero-day tied to Chinese spies](https://www.csoonline.com/article/4236421/beyondtrust-zero-day-tied-to-chinese-spies-puts-remote-support-users-on-alert.html)
37. eSecurityPlanet — [Google Warns China-Linked Hackers Exploited BeyondTrust Zero-Day](https://www.esecurityplanet.com/threats/news-beyondtrust-zero-day-china-hackers/)
38. Help Net Security — [Critical FortiMail zero-day exploited in the wild (CVE-2026-104286)](https://www.helpnetsecurity.com/2026/10/02/fortinet-fortimail-vulnerability-cve-2026-104286/)
39. Cybersecurity Dive — [Fortinet critical flaw FortiMail exploitation](https://www.cybersecuritydive.com/news/fortinet-critical-flaw-fortimail-exploitation/832017/)
40. Wiz — [CVE-2026-104286](https://www.wiz.io/vulnerability-database/cve/cve-2026-104286)
41. BleepingComputer — [Palo Alto Networks warns of PAN-OS RCE flaw exploited in attacks](https://bleepingcomputer.com/news/security/palo-alto-networks-warns-of-pan-os-rce-flaw-exploited-in-attacks)
42. CISA — [CISA Adds One Known Exploited Vulnerability to Catalog (Oct 15)](https://www.cisa.gov/news-events/alerts/2026/10/15/cisa-adds-one-known-exploited-vulnerability-catalog)

**Background**

43. nginx docs — [`add_header` inheritance](https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header), [`$uri` vs `$request_uri`](https://nginx.org/en/docs/http/ngx_http_core_module.html#var_uri), [`proxy_pass` URI handling](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass), [realip module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
44. MITRE — [CWE-180: Incorrect Behavior Order: Validate Before Canonicalize](https://cwe.mitre.org/data/definitions/180.html)
45. Wolf Den — [ShinyHunters (Condensed)](../ShinyHunters/ShinyHunters_Condensed.md), [ShinyHunters (Full)](../ShinyHunters/ShinyHunters.md), [Securing Data at Rest](../11-2-2025_Securing_Data_At_Rest.md)

---

*Happy Halloween. Patch your stuff. The monsters are real, and they read the same advisories you do. Cybersecurity Awareness Month 2026 didn't raise awareness — it raised the body count. See you in November, when we find out what was already compromised in October but nobody noticed yet.* 🎃👻🦇💀

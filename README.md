# The Wolf Den

> _Field notes from the edge of the network._

The Wolf Den is a security research blog — a running journal of malware
reverse engineering, exploit development, cryptographic engineering, and
threat intelligence. Posts are raw and technical: real payloads pulled apart,
real vulnerabilities chased down, real detection rules written to catch them.

Most work here orbits a few recurring worlds — the **Fortress of Solitude**
key-management system, the **Riddler Chat** post-quantum messenger, the
**Oblivion Edge** zero-trust router, and a rogues' gallery of campaigns
(*Tron*, *OinkNet*, *Trigger Happy*) traced from a single malicious JPEG out
to their command-and-control infrastructure. Each entry is dated in its
filename; the map below groups them by theme instead.

---

## Table of Contents

- [Malware Analysis & Reverse Engineering](#malware-analysis--reverse-engineering)
- [Campaign & Incident Response Reports](#campaign--incident-response-reports)
- [Exploitation & Vulnerability Research](#exploitation--vulnerability-research)
- [Cryptography & Key Management](#cryptography--key-management)
- [Network & Infrastructure Security](#network--infrastructure-security)
- [Cloud Security (AWS Series)](#cloud-security-aws-series)
- [Threat Intelligence & APTs](#threat-intelligence--apts)
- [Detection Engineering & Tooling](#detection-engineering--tooling)
- [Distributed Systems & Predicate Detection](#distributed-systems--predicate-detection)

---

## Malware Analysis & Reverse Engineering

Tearing apart binaries, syscall traces, and injected payloads.

| Date | Post |
|------|------|
| 2024-04-24 | [Malware Futex Analysis via KProbes and Syscall Hooking](./04-24-2024_Malware_Futex_Analysis.md) |
| 2025-06-07 | [Docker Breakout via Raw Syscall Shellcode and Reflective Injection](./06_07_2025_InjectedMalwareFound.md) |
| 2025-10-08 | [JPEG Payload — Preliminary Analysis](./10-08-2025_JPEG-Payload.md) |
| 2025-10-17 | [Font → Firefox Malware Delivery: A Security Researcher's Analysis](./10-17-2025-Font_Firefox_Malware_Report.md) |
| 2026-09-08 | [Camouflaged Octopus: A Tail into Huawei Echo Exploitation](./09-08-2026-Camoflauged-Octopus:_A_Tail_into_Huawei_Echo_Exploitation.md) |

---

## Campaign & Incident Response Reports

Following a single malicious file all the way to its C2 infrastructure.

| Date | Post |
|------|------|
| 2025-10-11 | [It Was Only a JPEG — How Did It End Up Like This?](./10-11-2025-How_did_it_end_up_like_this_it_was_only_a_jpg.md) |
| 2025-10-11 | [Expanding the Tron Map — From Behavioral PCAPs to Sandbox Payloads](./10-11-2025-sandbox_report_and_pcap_analysis.md) |
| 2025-10-15 | [OinkNet Behavioral Network — Ethical Disclosure & IR Report](./OinkNet_Campaign_Analysis_Report.md) |
| 2025-10-15 | [Tron Campaign (IMG_0118.JPG) — Ethical Disclosure & IR Report](./Tron_Campaign_Analysis_Report.md) |
| 2025-10-25 | [A Digital Symphony](./10-25-2025_A_Digital_Symphony.md) |
| 2025-10-28 | [Trigger Happy: Hidden Activation Paths in a Feature Rollout CSV](./10-28-2025-TriggerHappy.md) |

---

## Exploitation & Vulnerability Research

Proof-of-concept exploitation, heap grooming, and CVE deep dives.

| Date | Post |
|------|------|
| 2025-05-15 | [Theoretical Automated Shellcode Generation for Cisco ASR 9010](./05-15-2025_For_My_Fellow_Hackers.md) |
| 2026-07-25 | [Heap Buffer Overflow — Grooming-Focused Exploitation (LINA)](./07-25-2026_HeapBufferOverflow_Lina_Heap_Grooming_writeup.md) |
| 2026-07-25 | [LINA Command Injection #2: SSH Command Execution Injection](./07-25-2026_Lina_ssh_cmd_injection.md) |
| 2026-07-31 | [QNAP Firmware Encryption Key Extraction — CVE Exploitation Guide](./07-31-2026-QNAP_ProofOfConcepts_Implemented_N-Dayz.md) |
| 2026-09-04 | [Netflix Report #3: Insecure Shared Preferences Storage (CWE-922)](./09-04-2026-Netflix_Insecured_SharedPreferences_PhysicalDeviceAccessNeeded.md) |
| 2025-12-05 | [CVE-2025-43300: JPEG & DNG Payload Extractor and Forensic Analyzer](./12-05-2025_CVE-2025-43300_payloadExtraction.md) |

---

## Cryptography & Key Management

Building the Fortress of Solitude — NIST-aligned KEK/DEK, post-quantum crypto,
and encrypting data at rest.

| Date | Post |
|------|------|
| 2025-04-25 | [Beyond Centralization: Server-Independent Peer Networks (Riddler Chat)](./04-25-2025_BeyondCentralization.md) |
| 2025-05-03 | [Building a Django-Based KMS Aligned with NIST: KEK/DEK to FIPS](./05-03-2025_FortressOfSolitude_Encryption.md) |
| 2025-05-04 | [Kryptonian Cryptography in Django: KEK/DEK for Data at Rest](./05042025_KryptonianCryptographyInDjango.md) |
| 2025-11-02 | [Securing Data at Rest for Encrypted Communities](./11-2-2025_Securing_Data_At_Rest.md) |
| 2025-11-02 | [The Cryptographic Renaissance: Safe Havens for Digital Thought](./11-2-2025_The_Cryptographic_Renaissance.md) |
| 2026-07-14 | [RiddlerChat Post-Quantum Crypto Strategy Engine](./07-14-2026-PostQuantumCryptography-TheRiddlerChatSystem.md) |

---

## Network & Infrastructure Security

Zero-trust routers, application-layer monitoring, and verifiable infrastructure.

| Date | Post |
|------|------|
| 2025-05-15 | [Rethinking Router Security: The Case for Oblivion Edge](./05-15-2025_Oblivion_Edge_Router.md) |
| 2025-07-05 | [SMTPGhost: Zero Trust with Email-Aware Application Layer Monitoring](./07-05-2025-SMTP_GHOST.md) |

---

## Cloud Security (AWS Series)

A handbook on securing AWS — from CLI fundamentals to threat detection.

| Date | Post |
|------|------|
| 2026-07-07 | [AWS Security Guides — Partial Handbook (Cookbook / Index)](./07-07-2026-AWS_BLOG_SERIES_COOKBOOK.md) |
| 2026-07-07 | [Guide 0: AWS CLI Fundamentals](./07-07-2026-AWS_Security_Guide_0_AWS_CLI_Fundamentals.md) |
| 2026-07-07 | [Advanced: VPN & Network Architecture](./07-07-2026_AWS_Advanced:F***ItLetsBall.md) |
| 2026-07-11 | [Guide 1: Logging and Visibility (CloudTrail & Config)](./07-11-2026-AWS_BLOG_SERIES_1_Logging_and_Visibility.md) |
| 2026-07-11 | [Guide 2: Threat Detection & Response (GuardDuty & Security Hub)](./07-11-2026-AWS_BLOG_SERIES_2_Threat_Detection.md) |
| 2026-07-11 | [Appendix: Technical Terms & Definitions](./07-11-2026-AWS_Security_Blog_Appendix.md) |

---

## Threat Intelligence & APTs

Attribution, nation-state tradecraft, and the actors behind the campaigns.

| Date | Post |
|------|------|
| 2025-05-11 | [Hua-Wei What? A Brief Look into One Chinese APT](./05-11-2025_Hua-Wei_What:A%20brief%20analysis%20on%20a%20%20Chineese%20APT%20group.md) |

---

## Detection Engineering & Tooling

YARA rules, smarter fuzzers, and the analytical arsenal.

| Date | Post |
|------|------|
| 2025-07-19 | [Rocket Propelled POCs: Smarter Fuzzers with Python & ML](./07-19-2025_Building_Smarter%20Fuzzers_Python_and_Machine_Learning.md) |
| 2025-08-14 | [ICEEVENT Backdoor Busted by a New YARA Rule](./08-14-2025_YaraRule_Ice_Event.md) |
| 2025-11-07 | [BallerShotCaller: A Defender's Journal from DEFCON 33](./11-7-2025_BallerShotCaller-A_Defenders_Journal.md) |
| 2026-08-09 | [Baller's Paradise vs. The Joker: Android Joker Trojan YARA Writeup](./08-09-2026-BallersParadise_vs_TheJoker.md) |

---

## Distributed Systems & Predicate Detection

Vector clocks, happened-before ordering, and lattice-linear crash detection.

| Date | Post |
|------|------|
| 2026-07-13 | [Technical Deep Dive: LLP Predicate Detection System](./07-13-2026_Linear_Predicate_Detection_Deep_Dive.md) |
| 2025-11-08 | [Lattice Linear Predicate Detection in Ghidra Using EmulatorHelper](./11-08-2025_Linear_Lattice_predicate_Detection.md) |

---

## Repository Notes

- `.md` files are the blog posts; matching `.pdf` files are rendered versions where available.
- `.puml / .png` pairs are PlantUML diagram sources and their exports.
- Analysis artifacts (PCAPs, carved blobs, extraction scripts, sandbox reports) live alongside the posts and in folders such as `Email_Analysis_JPEG/`, `CVE_2025_43300_analysis/`, and `carved_analysis/`.

---

**Disclaimer:** All content is published for educational and defensive security research. Exploits and proofs-of-concept are documented for authorized testing, detection engineering, and ethical disclosure only.

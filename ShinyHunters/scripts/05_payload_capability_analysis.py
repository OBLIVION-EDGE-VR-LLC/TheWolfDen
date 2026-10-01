#!/usr/bin/env python3
"""
05_payload_capability_analysis.py
=================================
Analyzes payload capabilities from the ShinyHunters PeopleSoft campaign,
mapping SIDEEYE, LA.exe, MeshAgent, and webshell capabilities to potential
impact on backup infrastructure (Acronis, VSS, cloud backups).

Outputs structured JSON for diagram generation and reporting.

Usage:
    python3 scripts/05_payload_capability_analysis.py
"""

import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "scripts", "output")
os.makedirs(OUT, exist_ok=True)


def main():
    # ── 1. SIDEEYE Backdoor Capability Map ───────────────────────────────
    sideeye = {
        "name": "SIDEEYE",
        "delivery": "Trojanized Ple64.exe (Light Alloy media player installer)",
        "size": "5.2MB",
        "language": "C++",
        "signing": "Valid EV certificate (Sectigo, issued to Tobias Weihmann Software Development OU)",
        "c2_ip": "162.219.30.165",
        "c2_provider": "DataWagon LLC (ASN 27176)",
        "c2_protocol": "Raw TCP",
        "c2_ports": {"control": 3333, "data": 3334},
        "execution_chain": [
            "Ple64.exe (signed installer)",
            "Second-stage launcher (decrypts embedded data)",
            "SIDEEYE C++ backdoor (reflective code loading into memory)",
        ],
        "capabilities": {
            "credential_theft": {
                "description": "Steals credentials from web browsers and desktop applications",
                "mitre": "T1555 - Credentials from Password Stores",
                "backup_impact": "Can steal Acronis console credentials, backup encryption passwords, "
                                 "cloud storage API keys, and admin panel credentials",
            },
            "reverse_shell": {
                "description": "Interactive reverse-shell access for direct command execution",
                "mitre": "T1059.003 - Windows Command Shell",
                "backup_impact": "Enables execution of vssadmin, wbadmin, bcdedit commands "
                                 "to delete shadow copies and disable recovery",
            },
            "reverse_proxy": {
                "description": "Reverse-proxy functionality for tunneling into internal networks",
                "mitre": "T1090 - Proxy",
                "backup_impact": "Can tunnel into backup management networks, access Acronis "
                                 "management console on internal ports",
            },
            "file_management": {
                "description": "File and directory discovery, creation, modification, deletion",
                "mitre": "T1083 - File and Directory Discovery",
                "backup_impact": "Can enumerate backup storage locations, identify .tibx/.tib files, "
                                 "delete or corrupt backup archives directly",
            },
            "process_management": {
                "description": "Process discovery and management (start/stop/kill)",
                "mitre": "T1057 - Process Discovery",
                "backup_impact": "Can kill Acronis agent processes, backup scheduler services, "
                                 "VSS writer services to prevent new backups",
            },
        },
        "mitre_techniques": [
            "T1190 - Exploit Public-Facing Application",
            "T1059.003 - Windows Command Shell",
            "T1027 - Obfuscated Files or Information",
            "T1036 - Masquerading",
            "T1218 - System Binary Proxy Execution",
            "T1620 - Reflective Code Loading",
            "T1553.002 - Code Signing",
            "T1555 - Credentials from Password Stores",
            "T1083 - File and Directory Discovery",
            "T1057 - Process Discovery",
            "T1090 - Proxy",
        ],
    }

    # ── 2. LA.exe Capability Map ─────────────────────────────────────────
    la_exe = {
        "name": "LA.exe",
        "sha256": "3ba215692665513abfffd4e815c5c45f2d41e5dcc4283a2a3b740930c5c417c3",
        "size": "5.02MB",
        "type": "PE32 executable (GUI) Intel 80386",
        "compiled": "2020-11-15 09:48:32",
        "vt_score": "52/100",
        "submission_path": r"C:\Users\user\desktop",
        "imports": [
            "winhttp.dll (WinHttpGetIEProxyConfigForCurrentUser, WinHttpGetTimeouts, "
            "WinHttpGetStatusCallback, WinHttpConnect, WinHttpReceiveResponse, "
            "WinHttpQueryAuthSchemes)",
            "kernel32.dll",
            "comctl32.dll",
            "shell32.dll",
            "oleaut32.dll",
            "user32.dll",
            "version.dll",
            "ole32.dll",
            "advapi32.dll",
            "gdi32.dll",
            "netapi32.dll",
            "mpr.dll",
            "comdig32.dll",
            "msvcrt.dll",
        ],
        "mitre_techniques": [
            "T1574.002 - DLL Side-Loading (HIGH confidence)",
            "T1497 - Virtualization/Sandbox Evasion (MEDIUM confidence)",
            "T1518.001 - Security Software Discovery (HIGH confidence)",
            "T1082 - System Information Discovery (HIGH confidence)",
            "T1059 - Command and Scripting Interpreter (LOW confidence)",
            "T1057 - Process Discovery (LOW confidence)",
        ],
        "backup_impact_capabilities": {
            "security_discovery": "T1518.001 discovers installed security products including "
                                  "Acronis Cyber Protect Agent, backup agents, EDR",
            "dll_sideloading": "T1574.002 can hijack Acronis service DLLs for persistence "
                               "within backup infrastructure",
            "system_discovery": "T1082 enumerates system info including backup configurations, "
                                "volume shadow copy status, backup schedules",
            "sandbox_evasion": "T1497 RDTSC timing checks ensure payload only executes on "
                               "real systems, not analysis environments",
            "winhttp_c2": "WinHTTP API provides HTTP-based C2 that blends with legitimate "
                          "backup agent traffic to cloud consoles",
        },
    }

    # ── 3. MeshAgent / MeshCentral ───────────────────────────────────────
    meshagent = {
        "name": "MeshAgent (MeshCentral)",
        "type": "Legitimate RMM tool abused for persistence",
        "c2_domain": "azurenetfiles.net",
        "c2_protocol": "WSS (WebSocket Secure)",
        "c2_url": "wss://azurenetfiles.net:443/agent.ashx",
        "masquerading": "Disguised as Microsoft Azure binaries",
        "variants": [
            {
                "filename": "meshagent64-azure-ops.exe",
                "sha256": "f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc",
                "arch": "Windows 64-bit",
            },
            {
                "filename": "meshagent64-v2.exe",
                "sha256": "d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f",
                "arch": "Windows 64-bit",
            },
            {
                "filename": "meshagent32-azure-ops.exe",
                "sha256": "c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f",
                "arch": "Windows 32-bit",
            },
            {
                "filename": "meshagent",
                "sha256": "68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309",
                "arch": "Linux",
            },
        ],
        "capabilities": [
            "Remote desktop control",
            "File transfer and management",
            "Command shell execution",
            "Process management",
            "System information gathering",
            "Network scanning",
            "Script execution (PowerShell, Bash)",
        ],
        "backup_impact": "Full remote desktop + shell access enables manual interaction with "
                         "Acronis management console, backup deletion through GUI, "
                         "cloud console credential theft, and backup policy modification",
    }

    # ── 4. Webshell Capabilities ─────────────────────────────────────────
    webshells = {
        "jsp_webshells": {
            "count": 60,
            "deployment_path": "PSEMHUB.war application directory",
            "known_names": ["x.jsp", "u.jsp"],
            "persistence": "XMLDecoder persistence via modified .xml files in "
                           "envmetadata/data/environment/",
            "capabilities": [
                "Arbitrary command execution on PeopleSoft server",
                "File upload/download",
                "Database query execution against PeopleSoft DB",
                "Network reconnaissance (internal host enumeration)",
                "SSH lateral movement to other PeopleSoft instances",
            ],
        },
        "fanout_script": {
            "name": "[victim_abbreviation]_fanout.sh",
            "purpose": "Automated SSH credential spraying across internal hosts",
            "method": "Parses /etc/hosts for hostnames, attempts authentication "
                      "with hardcoded username/password lists",
            "marker": "README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT",
            "backup_impact": "Can spray credentials against backup servers, NAS devices, "
                             "and Acronis management hosts if they share credentials "
                             "or are listed in /etc/hosts",
        },
    }

    # ── 5. CVE-2026-87886 Acronis Vulnerability ─────────────────────────
    acronis_cve = {
        "cve": "CVE-2026-87886",
        "cvss": 7.8,
        "cwe": "CWE-276 (Incorrect Default Permissions)",
        "type": "Local Privilege Escalation",
        "affected_products": [
            "Acronis Backup plugin for cPanel & WHM (before 1.9.3.1021)",
            "Acronis Backup extension for Plesk (before 1.8.11.638)",
        ],
        "exploitation": "Authenticated attacker with low-privileged local access abuses "
                        "insecure default file permissions to elevate privileges and "
                        "execute arbitrary code with system-level access",
        "prerequisites": "Requires existing low-privileged foothold (compromised hosting "
                         "account, stolen credentials, or prior vulnerability exploitation)",
        "timeline": {
            "2026-09-11": "Acronis releases version 1.9.3 HF3 with security fixes",
            "2026-09-15": "Advisory published (SEC-10986)",
            "2026-09-16": "Public CVE disclosure and CISA KEV catalog addition",
            "2026-09-19": "CISA remediation deadline for federal agencies",
        },
        "exploitation_in_wild": "Limited, targeted attacks observed against cPanel & WHM deployments",
        "overlap_with_shinyhunters": "Timeline overlap: CVE-2026-87886 actively exploited in "
                                     "September 2026, concurrent with ShinyHunters' FBI breach "
                                     "(late September 2026) and renewed PeopleSoft campaign. "
                                     "While no direct attribution links ShinyHunters to this CVE, "
                                     "the coincident targeting of backup infrastructure during "
                                     "the same operational window is analytically significant.",
    }

    # ── 6. FBI Breach Analysis ───────────────────────────────────────────
    fbi_breach = {
        "target": "FBI (Federal Bureau of Investigation)",
        "entry_point": "FBIjobs.gov (apply.fbijobs.gov) — Oracle PeopleSoft",
        "vulnerability": "CVE-2026-35273 (PSEMHUB WAF Bypass, CVSS 9.8)",
        "waf_bypass": "URL-encoded POST to /%50SEMHUB/hub bypassed string-matching WAF rules",
        "lateral_movement": [
            "PeopleSoft server -> AWS GovCloud infrastructure",
            "Access to Criminal Justice (CJ) systems",
            "Access to HR systems",
            "Access to MedLink (medical records)",
            "Access to PEGA workflow systems",
            "Access to PHIRE change management",
            "Access to FBI BEAST (background checks)",
            "Access to FBI BICS (investigative information)",
        ],
        "data_exfiltrated": {
            "volume": "2-3 TB (claimed)",
            "types": [
                "FBI agent PII (current and former)",
                "Job applicant data (tens of thousands)",
                "Medical information (drug info, prescriptions, diagnoses)",
                "Career details and roles in sensitive/classified units",
                "Background check data",
            ],
        },
        "defacement": {
            "target": "apply.fbijobs.gov",
            "message": "THIS SITE HAS BEEN SEIZED BY SHINYHUNTERS",
            "logo": "Umbreon Pokemon logo (ShinyHunters trademark)",
        },
        "motivation": "Retaliation for FBI FLASH report (May 2026) detailing "
                      "ShinyHunters activities and discouraging ransom payments",
        "fbi_response": "Immediately took affected systems offline ('pulled the plug on everything')",
        "verified": "404 Media independently verified some phone numbers and DOJ "
                    "personnel associations in a 5,000-record sample",
    }

    # ── 7. D4M (Damage for Motivation) Assessment ────────────────────────
    d4m_assessment = {
        "backup_destruction_vectors": [
            {
                "vector": "VSS Shadow Copy Deletion",
                "command": "vssadmin delete shadows /all /quiet",
                "tool": "SIDEEYE reverse shell or MeshAgent shell",
                "mitre": "T1490 - Inhibit System Recovery",
                "impact": "Eliminates all local restore points, preventing rapid recovery",
                "confidence": "HIGH — SIDEEYE provides interactive shell access capable "
                              "of executing this command with escalated privileges",
            },
            {
                "vector": "Windows Backup Catalog Deletion",
                "command": "wbadmin delete catalog -quiet",
                "tool": "SIDEEYE reverse shell or MeshAgent shell",
                "mitre": "T1490 - Inhibit System Recovery",
                "impact": "Removes Windows Server Backup catalog, preventing restore "
                          "from Windows-native backups",
                "confidence": "HIGH — Standard post-exploitation technique",
            },
            {
                "vector": "Boot Configuration Modification",
                "command": "bcdedit /set {default} recoveryenabled no && "
                           "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
                "tool": "SIDEEYE reverse shell",
                "mitre": "T1490 - Inhibit System Recovery",
                "impact": "Disables Windows Recovery Environment, preventing boot-time recovery",
                "confidence": "HIGH — Standard ransomware pre-encryption step",
            },
            {
                "vector": "Acronis Agent Service Termination",
                "commands": [
                    "net stop AcronisCyberProtectionService",
                    "net stop \"Acronis Managed Machine Service\"",
                    "net stop AcronisAgent",
                    "net stop VSS",
                    "taskkill /f /im AcronisAgent.exe",
                    "taskkill /f /im BackupMonitor.exe",
                ],
                "tool": "SIDEEYE process management or MeshAgent",
                "mitre": "T1489 - Service Stop",
                "impact": "Stops all Acronis backup agents, preventing new backups and "
                          "breaking scheduled backup chains",
                "confidence": "HIGH — SIDEEYE explicitly supports process kill operations",
            },
            {
                "vector": "Acronis Backup Archive Deletion/Corruption",
                "method": "File management capabilities to locate and delete .tibx, .tib, "
                          ".vmdk, .vhd backup files on local/network storage",
                "tool": "SIDEEYE file management or MeshAgent file transfer",
                "mitre": "T1485 - Data Destruction",
                "impact": "Direct deletion or corruption of backup archives renders "
                          "point-in-time recovery impossible",
                "confidence": "HIGH — SIDEEYE provides full file system access",
            },
            {
                "vector": "Acronis Cloud Console Credential Theft",
                "method": "SIDEEYE credential theft from browsers/applications extracts "
                          "saved Acronis Cloud Console passwords, API tokens, and "
                          "management portal credentials",
                "tool": "SIDEEYE T1555 credential theft module",
                "mitre": "T1555 - Credentials from Password Stores",
                "impact": "Enables cloud-side backup deletion, policy modification, "
                          "and tenant-wide backup destruction via Acronis Cloud Console",
                "confidence": "HIGH — Browser credential theft is a confirmed SIDEEYE capability",
            },
            {
                "vector": "Acronis Cloud Backup Deletion via API",
                "method": "Using stolen credentials/API keys to authenticate to Acronis "
                          "Cloud Console and delete backup plans, archives, and retention policies",
                "tool": "Stolen credentials + any HTTP client",
                "mitre": "T1530 - Data from Cloud Storage",
                "impact": "Complete destruction of cloud-hosted backups that would otherwise "
                          "survive local encryption/deletion. Eliminates the 3-2-1 backup "
                          "strategy's off-site copy",
                "confidence": "MEDIUM — Requires Acronis Cloud credentials to be cached in browser",
            },
            {
                "vector": "CVE-2026-87886 Acronis Plugin Privilege Escalation",
                "method": "If target runs cPanel/WHM or Plesk with vulnerable Acronis plugin, "
                          "low-privilege access from webshell can escalate to root via "
                          "insecure default file permissions",
                "tool": "Direct exploitation of Acronis plugin file permissions",
                "mitre": "T1068 - Exploitation for Privilege Escalation",
                "impact": "Root-level access to hosting server, enabling complete control "
                          "over backup agent, storage, and configuration",
                "confidence": "MEDIUM — Requires specific Acronis plugin version on cPanel/Plesk. "
                              "Timeline overlap with ShinyHunters campaign is significant but "
                              "no direct attribution confirmed.",
            },
            {
                "vector": "AWS S3 Backup Bucket Manipulation",
                "method": "Lateral movement into AWS (confirmed in FBI breach) enables "
                          "access to S3 buckets used for backup storage. IAM role assumption "
                          "or stolen credentials enable bucket deletion/encryption",
                "tool": "AWS CLI with stolen credentials or assumed IAM role",
                "mitre": "T1578.002 - Modify Cloud Compute Infrastructure",
                "impact": "Destruction of cloud-native backups stored in S3, including "
                          "Acronis Cloud Storage targets configured to use S3-compatible storage",
                "confidence": "HIGH for FBI breach (AWS GovCloud access confirmed). "
                              "MEDIUM for general PeopleSoft targets.",
            },
        ],
        "backup_copy_exfiltration_vectors": [
            {
                "vector": "Backup Archive Exfiltration",
                "method": "SIDEEYE or MeshAgent file transfer capabilities used to "
                          "exfiltrate .tibx/.tib backup archives containing full system images",
                "impact": "Complete organizational data theft via backup files that contain "
                          "historical data, credentials, certificates, and configuration",
                "confidence": "MEDIUM — Backup files are large (GB-TB), but zstd compression "
                              "was confirmed as an exfiltration technique",
            },
            {
                "vector": "Database Backup Exfiltration",
                "method": "PeopleSoft database exports (confirmed: bulk queries against "
                          "HR, payroll, student records) can include database backup files",
                "impact": "Historical database records spanning years of organizational data",
                "confidence": "HIGH — Mandiant confirmed 2-3TB data exfiltration",
            },
        ],
    }

    # ── 8. Attack Chain: PeopleSoft -> Acronis ───────────────────────────
    attack_chain_acronis = {
        "phase_1_initial_access": {
            "technique": "CVE-2026-35273 PeopleSoft PSEMHUB WAF Bypass",
            "method": "POST /%50SEMHUB/hub (URL-encoded 'P' bypasses WAF)",
            "result": "Unauthenticated RCE on PeopleSoft application server",
        },
        "phase_2_webshell_deployment": {
            "technique": "JSP webshell deployment (x.jsp, u.jsp + 58 variants)",
            "location": "PSEMHUB.war application directory",
            "persistence": "XMLDecoder persistence in envmetadata XML files",
        },
        "phase_3_tool_deployment": {
            "sideeye": "Ple64.exe -> SIDEEYE backdoor (reflective loading)",
            "meshagent": "meshagent64-azure-ops.exe (masquerading as Azure)",
            "neo_regeorg": "Neo-reGeorg tunnel for internal network pivoting",
        },
        "phase_4_credential_harvesting": {
            "browser_theft": "SIDEEYE extracts saved credentials from browsers",
            "ntlm_capture": "Outbound SMB (TCP 445) captures NetNTLM hashes",
            "ssh_spray": "fanout.sh sprays credentials from /etc/hosts",
            "backup_creds": "Acronis console passwords, backup encryption keys, "
                            "and API tokens harvested from credential stores",
        },
        "phase_5_lateral_movement": {
            "ssh": "T1021.004 — SSH to other PeopleSoft instances",
            "meshcentral": "wss://azurenetfiles.net:443 — remote management",
            "cloud": "Pivot into AWS/GovCloud via stolen IAM credentials",
            "backup_network": "Pivot into backup management VLAN via SIDEEYE proxy",
        },
        "phase_6_backup_destruction": {
            "local_shadows": "vssadmin delete shadows /all /quiet",
            "windows_backup": "wbadmin delete catalog -quiet",
            "boot_recovery": "bcdedit /set recoveryenabled no",
            "acronis_agent": "net stop AcronisCyberProtectionService",
            "backup_files": "Delete/corrupt .tibx, .tib archives",
            "cloud_backups": "Authenticate to Acronis Cloud Console, delete backup plans",
            "s3_buckets": "Delete/encrypt S3 backup buckets via stolen IAM roles",
        },
        "phase_7_impact": {
            "data_exfiltration": "2-3 TB via zstd compression + SSH/SimpleHTTP",
            "defacement": "README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT",
            "extortion": "Threaten data release if demands not met",
        },
    }

    # ── Write outputs ────────────────────────────────────────────────────
    outputs = {
        "sideeye_analysis.json": sideeye,
        "la_exe_analysis.json": la_exe,
        "meshagent_analysis.json": meshagent,
        "webshell_analysis.json": webshells,
        "acronis_cve_analysis.json": acronis_cve,
        "fbi_breach_analysis.json": fbi_breach,
        "d4m_assessment.json": d4m_assessment,
        "attack_chain_acronis.json": attack_chain_acronis,
    }

    for fname, obj in outputs.items():
        path = os.path.join(OUT, fname)
        with open(path, "w") as f:
            json.dump(obj, f, indent=2)
        print(f"Wrote {path}")

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("PAYLOAD CAPABILITY SUMMARY")
    print("=" * 80)
    print(f"\nSIDEEYE Capabilities: {len(sideeye['capabilities'])} modules")
    for cap, info in sideeye["capabilities"].items():
        print(f"  {cap}: {info['mitre']}")
        print(f"    Backup Impact: {info['backup_impact'][:80]}...")

    print(f"\nLA.exe MITRE Techniques: {len(la_exe['mitre_techniques'])}")
    for t in la_exe["mitre_techniques"]:
        print(f"  {t}")

    print(f"\nMeshAgent Variants: {len(meshagent['variants'])}")
    for v in meshagent["variants"]:
        print(f"  {v['filename']} ({v['arch']}): {v['sha256'][:20]}...")

    print(f"\nD4M Vectors: {len(d4m_assessment['backup_destruction_vectors'])}")
    for v in d4m_assessment["backup_destruction_vectors"]:
        print(f"  [{v['confidence'][:6]}] {v['vector']}")

    print(f"\nFBI Systems Compromised: {len(fbi_breach['lateral_movement'])}")
    for s in fbi_breach["lateral_movement"]:
        print(f"  {s}")


if __name__ == "__main__":
    main()

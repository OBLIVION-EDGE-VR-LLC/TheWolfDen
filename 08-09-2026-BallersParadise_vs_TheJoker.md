# ICE_Event Backdoor - Technical Analysis & YARA Rule Writeup

## Executive Summary

ICE_Event is a Windows service-based backdoor/RAT (Remote Access Trojan) that provides an attacker with remote command execution, file upload, and file download capabilities over a socket-based C2 channel. It installs itself as a Windows service named "WindowsService" and communicates using a simple semicolon-delimited text protocol with three commands: `CMD;`, `DOWNFILE;`, and `UPFILE;`. The malware logs operational data to `C:\Windows\Temp\servicelog.txt` and contains a notable developer fingerprint: the consistent misspelling of "Service" as "Servcie" across multiple debug strings.

---

## Sample Details

| Field | Value |
|-------|-------|
| **SHA-256** | `9a0b0439e6fd2403f764acf0527f2365a4b9a98e9643cd5d03ccccf3825a732e` |
| **MD5** | `07c291c9cea4430676c303128bbbb8e3` |
| **File Type** | PE32+ executable (console) x86-64, for MS Windows |
| **Compiler** | MSVC 14.10 (Visual Studio 2017+) |
| **Compile Time** | 2024-04-25 05:50:58 UTC |
| **File Size** | 149,504 bytes (146 KB) |
| **Sections** | `.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc` (6 total) |
| **Subsystem** | Windows CUI (Console) |
| **Entry Point** | `0x5c58` (RVA) |

---

## Static Analysis Findings

### C2 Protocol

The core of ICE_Event's functionality is a simple text-based C2 protocol using semicolon-delimited command markers. These three strings appear adjacent to each other in the `.rdata` section at offset `0x1EBE0`:

| Command | Purpose |
|---------|---------|
| `UPFILE;` | Exfiltrate a file from the victim to the attacker |
| `DOWNFILE;` | Download a file from the attacker to the victim |
| `CMD;` | Execute a system command and return output |

The adjacency of these strings in the binary is itself a detection opportunity -- the `$c2_block` hex pattern in the YARA rule leverages this positional relationship.

### Windows Service Registration

The malware registers itself as a persistent Windows service using three ADVAPI32.dll APIs:

- `RegisterServiceCtrlHandlerW` - registers the service control handler
- `StartServiceCtrlDispatcherW` - connects the service to the SCM
- `SetServiceStatus` - updates the service state

The service name is stored as a **wide (UTF-16)** string: `WindowsService`.

### Logging

ICE_Event writes operational logs to a hardcoded path stored as a wide string:

```
C:\Windows\Temp\servicelog.txt
```

This is notable for two reasons: it provides forensic evidence on compromised hosts, and the hardcoded path is a strong static indicator.

### Network Communication

The malware imports `WS2_32.dll` (Windows Sockets) **by ordinal** rather than by name -- a minor obfuscation technique. The presence of `bind error:` and `listen error:` strings indicates the malware can operate as a **listener** (bind shell pattern), waiting for incoming connections rather than initiating outbound connections.

Key network-related strings:
- `bind error: ` - socket bind failure
- `listen error: ` - socket listen failure
- `INVALID_SOCKET` - socket creation failure handling
- `, send length` - data transmission logging
- `Time out!` (wide string) - connection timeout handling

### Process Execution via Pipes

For the `CMD;` command, ICE_Event spawns child processes and captures their output using a pipe-based I/O mechanism:

- `CreateProcessW` - creates the process to execute commands
- `CreatePipe` - creates anonymous pipes for stdin/stdout redirection
- `PeekNamedPipe` - non-blocking check for available output data
- `SetHandleInformation` - configures pipe handle inheritance
- `WaitForSingleObject` - waits for process completion
- `TerminateProcess` - kills hung processes
- `CreateThread` - likely used for async I/O handling

Debug strings confirm this:
- `"Created a process"` - successful process creation
- `"CreateProcess failed: %d"` - process creation failure with error code
- `"Error creating pip: %d"` - pipe creation failure (note: "pip" not "pipe" -- another developer typo)

### File Transfer Operations

The file transfer functionality has extensive debug/log strings:

- `"Write File path:"` - logs the target path for downloaded files
- `"Write file "` - file write operation
- `",Write length: "` - bytes written
- `", Received file length: "` - expected file size from C2
- `"Read file "` - file read operation for exfiltration

### Developer Fingerprint: "Servcie" Misspelling

Three debug strings consistently misspell "Service" as **"Servcie"**:

1. `[Servcie Error] Receive len error`
2. `Servcie receive error: `
3. `Servcie receive end, length: `

This is contrasted with correctly-spelled strings elsewhere:
- `[Service Info] Receive data len:`
- `[Service Error] Invalid cmd`
- `Service Response: Data length:`

This inconsistency suggests the misspelled strings were written by a different developer or at a different time, but regardless, the typo is a **strong unique indicator** -- it persists across builds and is highly unlikely to appear in legitimate software.

### Manifest

The embedded XML manifest requests `asInvoker` execution level, meaning the malware does **not** attempt UAC elevation. It relies on the privileges of the user/context that installs it as a service.

---

## YARA Rule Design

### Philosophy

The rule (`ICE_Event_Backdoor`) was designed with two priorities:

1. **Zero false positives** -- critical in a competition scanning 5,255 files
2. **Variant coverage** -- multiple detection paths so different builds can still be caught

### Detection Paths (6 total)

#### Path 1: C2 Commands + Typo (Behavioral, High Confidence)
```
2 of ($c2_*) and 1 of ($typo*)
```
**Rationale:** The semicolon-delimited C2 commands (`DOWNFILE;`, `UPFILE;`, `CMD;`) are functionally unique strings -- no legitimate software uses this exact protocol. Combined with the "Servcie" typo, this creates an extremely high-confidence detection with near-zero false positive risk. This path catches variants even if the compiler, entry point, or other structural elements change.

#### Path 2: Entry Point + Rich Header (Structural, Build-Specific)
```
$ep_bytes and $rich
```
**Rationale:** The exact entry point byte sequence `{48 83 EC 28 E8 0F 06 00 00 48 83 C4 28 E9 76 FE}` and Rich header `{62 2C 99 FD 26 4D F7 AE ...}` fingerprint the specific compiler toolchain and build. High precision for this exact build but won't match recompiled variants.

#### Path 3: C2 Block Pattern (Positional)
```
$c2_block
```
**Rationale:** A hex pattern matching `UPFILE;` followed by `DOWNFILE;` followed by `CMD;` within a constrained byte range. This leverages the fact that string literals from the same code region are placed adjacently in the `.rdata` section by the compiler. Even if individual command strings might theoretically appear in other software, their adjacency is unique to this malware.

#### Path 4: Service + Network + C2 (Behavioral Combo)
```
$svc_name_wide and $svc_logpath and 2 of ($api_reg_svc, ...) and $dll_ws2_32 and 2 of ($c2_*)
```
**Rationale:** A Windows service named "WindowsService" that logs to `C:\Windows\Temp\servicelog.txt`, imports service registration APIs AND Winsock, AND has C2 command strings. Each element alone is insufficient, but the combination is unique.

#### Path 5: Pipe Execution + Socket (Behavioral Combo)
```
$api_create_pipe and $api_create_process and $api_peek_pipe and $dll_ws2_32 and 2 of ($net_*) and 1 of ($c2_*)
```
**Rationale:** Targets the core RAT functionality -- pipe-based process execution combined with socket networking. Programs that use both CreatePipe+PeekNamedPipe AND Winsock with bind/listen errors AND C2 commands are almost certainly RATs.

#### Path 6: File Transfer + Typo + Service (Behavioral Combo)
```
2 of ($file_*) and 1 of ($typo*) and 1 of ($svc_info, $svc_err_cmd, $svc_response)
```
**Rationale:** Catches variants where the C2 protocol might change but the file transfer debug strings and "Servcie" typo remain.

### Breadth-of-Indicators (AND Block)

After the primary detection paths (OR block), an AND block requires additional corroborating evidence:

```
and 1 of ($proc_*)        // process creation strings
and $pipe_error            // "Error creating pip: %d"
and $manifest              // embedded manifest
and $conout                // CONOUT$ handle
and $svc_timeout           // "Time out!" wide string
and 2 of ($dll_*)          // at least 2 of KERNEL32/ADVAPI32/WS2_32
and 3 of ($api_*)          // at least 3 API imports
```

**Rationale:** This block prevents false positives by ensuring the match isn't triggered by a file that happens to contain one or two of the C2 strings coincidentally. Every matched file must also exhibit the broader structural characteristics of a Windows service RAT.

### Constraints

- **PE file check:** `uint16(0) == 0x5A4D` and PE signature validation
- **File size:** `filesize < 500KB` -- legitimate applications with similar import profiles would typically be much larger

---

## Competition Results

| Metric | Value |
|--------|-------|
| **Final Score** | **95.00** |
| **Files Scanned** | 5,255 |
| **Matches** | 3 |
| **False Positives** | 0 |
| **False Negatives** | 1 |
| **Accuracy** | 99.98% |
| **Precision** | 100.00% |
| **Recall** | 75.00% |

The single false negative (75% recall) is likely a variant of ICE_Event with:
- Different entry point bytes (different compiler version or build settings)
- Possibly corrected "Servcie" typo in newer versions
- Different debug string formatting
- Or a sufficiently different build that the breadth-of-indicators AND block filtered it out

To improve recall, the AND block could be relaxed (e.g., removing `$pipe_error` or `$conout` requirements), but this risks introducing false positives. Given the competition scoring, the 95-point result with 100% precision was the optimal trade-off.

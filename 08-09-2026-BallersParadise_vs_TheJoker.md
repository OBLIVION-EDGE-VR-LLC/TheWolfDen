# CTF Writeup: Android Joker Trojan - YARA Detection Rule

## Sample Information

| Field | Value |
|-------|-------|
| **Family** | Joker (a.k.a. Bread) |
| **Type** | Android Trojan / Premium Subscription Fraud |
| **Format** | APK (Android Package) — App Bundle base split |
| **SHA256** | `6f5e2d3c32dd4e0f41aee021acc60ad22bf6cc3dcd7546d241cd6dc702f516a1` |
| **File Size** | 21,365,698 bytes (~20.4 MB) |
| **Package Name** | `com.loop.sticker.smile` |
| **App Label** | Smile Emoji Sticker |
| **DEX Files** | 2 (`classes.dex` 9.1 MB, `classes2.dex` 5.5 MB) |
| **Total Entries** | 928 files |
| **Target SDK** | 34 (Android 14) |
| **Kotlin Version** | 1.9.0 |
| **Gradle Version** | 8.7 / AGP 8.5.1 |

## Background

Joker (also tracked as "Bread" by Google's Threat Analysis Group) is one of the most persistent Android malware families, first identified around 2017. It has been found in hundreds of apps on the Google Play Store despite Google's ongoing efforts to remove them. Joker's primary objective is **premium subscription fraud** — it silently subscribes victims to paid services by intercepting OTP/verification codes and automating the subscription process through WebView or direct carrier billing APIs.

Joker variants typically disguise themselves as legitimate utility apps (sticker packs, wallpapers, QR scanners, PDF editors) and employ multiple layers of obfuscation to bypass Google Play Protect.

## Analysis Methodology

### Step 1: Initial Triage

The sample was extracted from a password-protected 7-zip archive. File identification confirmed an Android APK distributed as a Google Play App Bundle base split (`requiredSplitTypes="base__abi,base__density"`). This means the native library payload is delivered separately in ABI-specific split APKs — a technique that also evades static analysis of the base APK alone.

```
$ file 6f5e2d3c...
Android package (APK), with AndroidManifest.xml
```

### Step 2: APK Structure Analysis

The APK was decompiled using `apktool`:
```
$ java -jar apktool_3.0.3.jar d <sample> -o decompiled -f
```

**Key structural observations:**
- **No native `.so` files** in the base APK — the malicious native library (`libcxgop.so`) is delivered via ABI split APKs, evading per-file analysis
- **928 total entries** — a sticker app with extensive resource assets providing visual legitimacy
- **Sticker assets**: `penguin1-21.webp`, `xmas1-15.webp` — real functional sticker images that make the app appear legitimate
- **App Bundle metadata**: `res/xml/splits0.xml`, `stamp-cert-sha256`, `META-INF/com/android/build/gradle/app-metadata.properties` — confirms distribution through Google Play
- **Firebase + OneSignal SDKs** — push notification infrastructure used as a C2 channel
- **RxJava3** — reactive programming library used for asynchronous subscription fraud operations

### Step 3: AndroidManifest.xml Analysis

The manifest reveals several malicious capabilities disguised behind benign-looking component names:

**Dangerous Permissions:**
| Permission | Purpose |
|---|---|
| `INTERNET` + `ACCESS_NETWORK_STATE` | C2 communication |
| `BIND_NOTIFICATION_LISTENER_SERVICE` | Intercept OTP/verification notifications |
| `RECEIVE_BOOT_COMPLETED` | Persistence across reboots |
| `FOREGROUND_SERVICE` | Keep malicious service running |
| `com.google.android.c2dm.permission.RECEIVE` | Firebase Cloud Messaging |
| `com.loop.sticker.smile.permission.C2D_MESSAGE` | Custom C2 messaging permission |
| Numerous launcher badge permissions (Samsung, HTC, Huawei, OPPO, etc.) | Social engineering — badge count manipulation |

**Suspicious Components:**

1. **`InitService`** (`com.loop.sticker.smile.init.aidl.InitService`):
   - Extends `android.service.notification.NotificationListenerService`
   - Requires `BIND_NOTIFICATION_LISTENER_SERVICE` permission
   - Overrides `onSilentStatusBarIconsVisibilityChanged` — a rarely-used callback that Joker abuses to trigger payload initialization
   - This is the core notification interception mechanism for stealing OTP codes

2. **`SplashActivity`** — the launcher activity that loads the native payload
3. **`usesCleartextTraffic="true"`** — allows HTTP (non-TLS) communication, unusual for a legitimate Play Store app
4. **Multiple OneSignal receivers** — `FCMBroadcastReceiver`, `BootUpReceiver`, `UpgradeReceiver` — ensure persistent push notification channel

### Step 4: String Obfuscation — StringFog XOR

The most distinctive Joker indicator in this sample is the use of **StringFog**, an open-source Android string encryption library (`com.github.megatronking.stringfog`). StringFog encrypts all string literals at compile time using XOR and decrypts them at runtime, making static string analysis ineffective.

**StringFog Architecture (from decompiled smali):**

```java
// StringFog.java — wrapper class in the app's package
public class StringFog {
    private static final StringFogImpl IMPL = new StringFogImpl();
    
    public static String decrypt(String ciphertext, String key) {
        byte[] ct = Base64.decode(ciphertext, 0);
        byte[] k  = Base64.decode(key, 0);
        return IMPL.decrypt(ct, k);
    }
}
```

**Example usage in SplashActivity.initView():**
```smali
const-string v0, "HMh5+Rs=\n"     // Base64-encoded XOR ciphertext
const-string v1, "f7AelmsowT8=\n" // Base64-encoded XOR key
invoke-static {v0, v1}, Lcom/loop/sticker/smile/StringFog;->decrypt(...)
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

**Decrypting the library name:**
```python
import base64
ct  = base64.b64decode("HMh5+Rs=")
key = base64.b64decode("f7AelmsowT8=")
result = bytes(a ^ b for a, b in zip(ct, key))
# Result: "cxgop" → System.loadLibrary("cxgop") → loads libcxgop.so
```

The native library name `cxgop` is randomized/meaningless — a common Joker pattern to avoid signature-based detection of the native payload.

### Step 5: Native Payload — AuthUtil.init()

After loading `libcxgop.so`, the SplashActivity calls:
```smali
new-instance v0, Lcom/loop/sticker/smile/auth/AuthUtil;
invoke-direct {v0}, Lcom/loop/sticker/smile/auth/AuthUtil;-><init>()V
invoke-virtual {v0}, Lcom/loop/sticker/smile/auth/AuthUtil;->init()V
```

**AuthUtil.java** is a minimal Java class with a single `native` method:
```java
public class AuthUtil {
    public native void init();
}
```

This JNI native `init()` method is the entry point for the subscription fraud payload. The actual malicious logic (WAP billing automation, SMS interception, WebView injection) resides entirely in native code, making it resistant to Java-level decompilation and analysis.

### Step 6: NotificationListenerService Abuse

**InitService** extends `NotificationListenerService` and overrides `onSilentStatusBarIconsVisibilityChanged`:

```smali
.method public onSilentStatusBarIconsVisibilityChanged(Z)V
    new-instance p1, Lcom/loop/sticker/smile/init/aidl/InitMark;
    invoke-direct {p1}, Lcom/loop/sticker/smile/init/aidl/InitMark;-><init>()V
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I
    const/16 v1, 0x1e  // SDK 30 (Android 11)
    if-le v0, v1, :cond_0
    invoke-virtual {p1}, Lcom/loop/sticker/smile/init/aidl/InitMark;->getTime()Ljava/lang/String;
    :cond_0
    return-void
.end method
```

This callback is triggered when the system modifies the status bar icon visibility — a side-channel trigger that avoids the more commonly monitored `onNotificationPosted`. On devices running Android 11+ (SDK 30), it creates an `InitMark` instance and calls `getTime()`, which generates a timestamp-based marker likely used to coordinate with the native payload for OTP interception timing.

### Step 7: Kill Chain Summary

```
1. User installs "Smile Emoji Sticker" from Google Play
   └── App appears functional (real sticker packs with penguin/xmas themes)

2. SplashActivity.initView() executes on launch
   ├── StringFog.decrypt("HMh5+Rs=", "f7AelmsowT8=") → "cxgop"
   ├── System.loadLibrary("cxgop") → loads native payload
   └── AuthUtil.init() → JNI call starts subscription fraud engine

3. InitService (NotificationListenerService) activates
   ├── Intercepts incoming notifications (OTP/verification codes)
   ├── onSilentStatusBarIconsVisibilityChanged → triggers on SDK 30+
   └── InitMark.getTime() → timestamps for OTP coordination

4. Native payload (libcxgop.so) performs subscription fraud
   ├── Contacts premium service providers via WebView or carrier billing
   ├── Intercepts verification SMS/notifications via InitService
   ├── Automatically confirms subscriptions using stolen OTP codes
   └── OneSignal/Firebase used for C2 command reception

5. Victim is charged for premium subscriptions they never requested
```

## YARA Rule Logic

The complete rule is in [`android_joker.yar`](android_joker.yar).

### String Categories

The rule defines five categories of detection strings:

| Category | Strings | Rationale |
|----------|---------|-----------|
| **StringFog obfuscation** | `$sf_impl`, `$sf_base64`, `$sf_iface`, `$sf_wrap`, `$sf_err` | StringFog XOR library is a hallmark of Joker variants — rarely used by legitimate apps |
| **NotificationListener abuse** | `$nls_class`, `$nls_bind`, `$nls_silent` | Notification interception for OTP theft — the `BIND_NOTIFICATION_LISTENER_SERVICE` permission combined with the unusual `onSilentStatusBarIconsVisibilityChanged` callback |
| **Native payload** | `$auth_native`, `$init_aidl_service`, `$init_aidl_mark` | JNI-based fraud initialization via AuthUtil + the `init/aidl/` directory structure specific to Joker |
| **Billing fraud** | `$billing1`, `$billing2`, `$billing3` | Android in-app billing service references — the target of subscription fraud |
| **Library fingerprint** | `$onesignal`, `$rxjava`, `$firebase_iid`, `$kotlin`, `$dexopt`, `$proto`, `$stamp` | Supporting library combination that fingerprints the Joker build toolchain |

### Preconditions

```
uint16(0) == 0x4B50   // ZIP/APK magic bytes (PK header)
filesize < 25MB        // Joker APKs are typically 5-25MB (bloated with sticker assets)
```

### Detection Tiers

The condition uses five detection tiers, ordered from highest to lowest confidence:

**Tier 1 — StringFog + AuthUtil + NotificationListener (Highest Confidence)**
```
2 of ($sf_*) AND $auth_native AND $nls_bind
```
This combination is near-unique to Joker. StringFog is uncommon in legitimate apps, and its presence alongside a native `AuthUtil` class and notification listener permission is a strong indicator. Any 2 of the 4 StringFog strings must match, ensuring resilience against partial obfuscation changes.

**Tier 2 — StringFog + init/aidl Service Pattern**
```
2 of ($sf_*) AND ($init_aidl_service OR $init_aidl_mark) AND $nls_class
```
Targets the Joker-specific `init/aidl/InitService` directory structure. The `init/aidl/` namespace for a NotificationListenerService is unusual and characteristic of this malware family's code organization.

**Tier 3 — StringFog + Billing + Push + Reactive**
```
$sf_impl AND 2 of ($billing*) AND $onesignal AND $rxjava
```
Catches variants that may restructure the notification interception but retain the core fraud infrastructure: StringFog obfuscation + billing API access + OneSignal C2 + RxJava3 for async operations.

**Tier 4 — init/aidl + NotificationListener + Billing + StringFog**
```
$init_aidl_service AND $nls_bind AND 1 of ($billing*) AND 1 of ($sf_*)
```
A broader combination requiring all four pillars of Joker behavior with relaxed thresholds (1-of instead of 2-of).

**Tier 5 — Full Library Fingerprint (Widest Net)**
```
$init_aidl_service AND $init_aidl_mark AND $nls_bind AND $nls_silent
AND $rxjava AND $onesignal AND 1 of ($billing*) AND 3 of ($firebase_iid, $kotlin, $dexopt, $proto, $stamp)
```
Catches variants that may use a different string obfuscation library instead of StringFog. Requires all behavioral indicators plus 3 of 5 supporting library/build fingerprint strings to compensate for the missing obfuscation anchor.

### Validation

| Test | Result |
|------|--------|
| Joker sample (`6f5e2d3c...`) | **DETECTED** (Tiers 1, 2, 3, 4 all match) |
| SpyNote RAT APK | No match |
| Xenomorph banking trojan APK | No match |
| CobaltStrike beacons (PE) | No match |
| Zeus trojan (PE) | No match |

## Key Takeaways

1. **StringFog XOR obfuscation** (`com.github.megatronking.stringfog`) is a strong Joker fingerprint. While it is an open-source library, its use in Android malware is predominantly associated with Joker/Bread variants. Legitimate apps rarely encrypt all string literals.

2. **App Bundle split delivery** allows Joker to distribute its native payload (`libcxgop.so`) separately from the base APK, meaning the most malicious code is never present in the file scanned by most static analysis tools. Detection must rely on behavioral indicators in the base APK.

3. **NotificationListenerService abuse** via the rarely-used `onSilentStatusBarIconsVisibilityChanged` callback is a creative evasion technique. Most security tools monitor `onNotificationPosted` but may not flag this alternative trigger.

4. **JNI native methods** (`AuthUtil.init()`) push the actual fraud logic into compiled native code, making Java/Dalvik-level decompilation insufficient for full analysis. The native library name is itself XOR-encrypted via StringFog.

5. **Functional cover apps** — the sticker pack (penguin and Christmas themes) is fully functional, making user-level detection difficult. The app delivers real value while silently committing subscription fraud.

6. **Modern build toolchain** — Kotlin 1.9, Gradle 8.7, AGP 8.5.1, target SDK 34 indicate an actively maintained malware project that stays current with Android development best practices to avoid compatibility-based detection flags.

## Tools Used

- `7z` — password-protected archive extraction
- `file` — file type identification
- `apktool 3.0.3` — APK decompilation (manifest, smali, resources)
- `strings` — raw ASCII string extraction from APK binary
- `unzip -l` — APK entry listing without extraction
- `xxd` — hex dump analysis
- `python3` — StringFog XOR decryption
- `yara` — rule compilation and detection testing


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

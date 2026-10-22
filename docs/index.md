---
title: Getting Started with twagentneo
layout: default
---

[日本語マニュアルはこちら (Japanese)](./index_ja.html)

# Getting Started with twagentneo
Next-Generation Pure Go Cross-Platform Monitoring & AI Security Agent for TWSNMP NEO

![](./images/appicon.png){: width="200"}

---

## 1. Introduction

**twagentneo** is a lightweight, high-performance, cross-platform monitoring and AI security agent designed for **TWSNMP NEO** (as well as FC/FK), running natively on Linux, macOS, and Windows.

Beyond traditional monitoring of host resources (CPU, Memory, Disk, Load Average) and network telemetry (network interfaces, ARP tables, outbound TCP connections), twagentneo autonomously performs File Integrity Monitoring (FIM) and local security log auditing.

For log auditing, twagentneo integrates a Pure Go **Sigma evaluation engine** ported from production implementations in TWSLA. Furthermore, suspicious events trigger an intelligent **LLM-as-a-Judge local triage** powered by the embedded Go-native LLM package **`tensai`**, running entirely on-device without external cloud dependencies.

### Core Highlights
- **Pure Go Single Binary (`CGO_ENABLED=0`)**: Zero external C library dependencies. Runs instantly across Linux, macOS, and Windows with static linking.
- **Two-Tier Hybrid Threat Auditing (Sigma × tensai)**:
  - **Tier 1 (Sub-millisecond / Ultra-low Footprint)**: Built-in curated Sigma rules filter high-volume incoming log streams down to candidate suspicious events within milliseconds.
  - **Tier 2 (Intelligent Local Triage)**: Evaluates candidate events locally using the embedded LLM engine `tensai` to assess real threats, eliminate false positives, score risk (0-100), and generate actionable remediation advisories.
- **Zero-Configuration Operation**: Curated Sigma rules for Linux, macOS, and Windows are directly embedded into the binary via `embed.FS`. No external rule management required.
- **OS-Adaptive Selective Loading**: Automatically inspects `runtime.GOOS` on boot to index only relevant platform rules, keeping idle CPU usage below 1% and resident memory footprint within 30–50MB.
- **Multi-Protocol Telemetry Exporters**: Delivers metrics and rich security alerts to TWSNMP NEO via **MQTT** (real-time stream), **Syslog** (RFC 5424 / RFC 3164), and **SNMP TRAP** (dedicated enterprise MIB).
- **Self-Updating CLI**: Integrated updater (`twagentneo update`) supporting GitHub Releases, Homebrew, and container environment detection.

---

## 2. System Architecture

twagentneo is organized into modular collectors, a high-throughput event pipeline, a two-tier auditing engine, and multi-protocol exporters:

```text
+-------------------------------------------------------------------------+
|                              twagentneo                                 |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 Collectors (Pure Go / Native OS)                  |  |
|  |  [Host Resource]   [ARP / Interface]   [TCP Connections]          |  |
|  |  [FIM (fsnotify)]  [Log Tailer (auth, secure, install, EventLog)] |  |
|  +-------------------------------------------------------------------+  |
|                                  |                                      |
|                                  v (Raw Logs / Events)                  |
|  +-------------------------------------------------------------------+  |
|  |                 Tier-1: OS-Adaptive Sigma Engine                  |  |
|  |  - Built-in Curated Rules (Linux / Windows / macOS)               |  |
|  |  - Boot-time OS Indexing & Ultra-Fast String Matching             |  |
|  |  - High / Critical Suspicious Event Candidate Filtering           |  |
|  +-------------------------------------------------------------------+  |
|                                  | (Suspicious Candidate Events)        |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |             Tier-2: Local LLM Judge (via tensai pkg)              |  |
|  |  - Contextual Log Sliding Window (up to 20 lines)                 |  |
|  |  - Threat Assessment & False Positive Suppression (0-100 Score)   |  |
|  |  - MITRE ATT&CK Mapping & Actionable Remediation Advisory         |  |
|  +-------------------------------------------------------------------+  |
|                                  | (Enriched Alerts & Metrics)          |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |               Internal Non-blocking Bus (Pipeline Bus)            |  |
|  +-------------------------------------------------------------------+  |
|                                  |                                      |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |                    Exporters (Multi-Protocol)                     |  |
|  |   [MQTT Exporter]      [Syslog Exporter]    [SNMP Trap Exporter]  |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
           |                         |                    |
           v                         v                    v
      TWSNMP NEO                 SIEM / Syslog       TWSNMP NEO /
    (MQTT Broker)                  Receiver          Trap Receiver
```

---

## 3. Installation & Startup

twagentneo is distributed as cross-platform native binaries for Linux, macOS, and Windows.

### 3.1 macOS (Homebrew)

Install directly via the official Homebrew Tap:

```bash
brew install twsnmp/tap/twagentneo
```

### 3.2 Linux / macOS (One-Liner Script)

Download and install the correct architecture binary automatically:

```bash
curl -fsSL https://raw.githubusercontent.com/twsnmp/twagentneo/main/install/install.sh | sh
```

### 3.3 Manual Download from GitHub Releases

Pre-compiled binary archives are available on [GitHub Releases](https://github.com/twsnmp/twagentneo/releases):

| OS | Architecture | Package Archive |
|:---|:---|:---|
| Linux | amd64 / x86_64 | `twagentneo_linux_amd64.tar.gz` |
| Linux | arm64 / aarch64 | `twagentneo_linux_arm64.tar.gz` |
| macOS | Apple Silicon (arm64) | `twagentneo_darwin_arm64.tar.gz` |
| macOS | Intel (amd64) | `twagentneo_darwin_amd64.tar.gz` |
| Windows | 64-bit (x64) | `twagentneo_windows_amd64.zip` |
| Windows | ARM64 | `twagentneo_windows_arm64.zip` |

### 3.4 Building from Source

Build using [`mise`](https://mise.jdx.dev/) or standard `make`:

```bash
# Using mise
mise run build

# Using make
make build
```

---

## 4. Configuration Guide (`config.yaml`)

Configuration is managed via a single YAML file. By default, `twagentneo` looks for `./config.yaml`:

```yaml
agent:
  id: "twagentneo-server-01"    # Unique agent identifier
  name: "Web-App-Host-01"       # Human-readable host display name
  log_level: "info"             # debug | info | warn | error

collectors:
  resource:
    enabled: true
    interval: 60s               # Resource collection interval
    cpu_threshold: 90.0         # CPU usage alert threshold (%)
    mem_threshold: 85.0         # Memory usage alert threshold (%)
    disk_threshold: 90.0        # Disk usage alert threshold (%)
    load_threshold: 10.0        # 1-minute load average threshold
  network:
    enabled: true
    interval: 180s              # Network state poll interval
    arp_watch: true             # Collect local ARP cache
    tcp_watch: true             # Track active outbound TCP connections
  fim:
    enabled: true
    paths:                      # Directories to monitor recursively
      - /etc
      - /usr/bin
      - /usr/sbin
  logs:
    enabled: true
    paths:                      # Optional custom log files (empty = OS defaults)
      # - /var/log/my-custom-app.log

# Two-tier Threat Auditing
audit:
  sigma:
    enabled: true              # Built-in Sigma rule evaluation
  ai_judge:
    enabled: true              # tensai local LLM triage
    model_path: ""             # Optional model path (empty = default tensai model)
    timeout: 5s                # Inference timeout

# Telemetry Delivery Exporters
exporters:
  mqtt:
    enabled: true
    broker: "tls://twsnmp-neo-server:8883"
    client_id: "twagentneo-01"
    topic_prefix: "twsnmpneo/agent"
    username: "twagentneo"
    password: "${MQTT_PASSWORD}"

  syslog:
    enabled: false
    endpoint: "udp://twsnmp-neo-server:514"
    format: "rfc5424"          # rfc5424 or rfc3164

  snmp_trap:
    enabled: true
    target: "twsnmp-neo-server:162"
    version: "v3"              # v2c or v3
    community: "public"
    v3:
      user: "twsnmpUser"
      auth_protocol: "SHA256"
      auth_password: "${TRAP_AUTH_PASS}"
      priv_protocol: "AES128"
      priv_password: "${TRAP_PRIV_PASS}"
```

> **Environment Variable Substitution**: Secrets such as passwords can be supplied as `${ENV_VAR_NAME}` and will be dynamically substituted at boot time.

---

## 5. Collectors & Monitoring Details

### 5.1 Host Resource Monitoring (`resource`)
Acquires host metrics via native system calls and `/proc` without external CLI invocations:
- **CPU**: System and per-core utilization percentages.
- **Memory**: Total, used, free, and memory utilization percentage.
- **Disk**: Root and per-mount filesystem utilization percentages.
- **Load Average**: 1m, 5m, and 15m load metrics.
- **Threshold Alerts**: Triggers immediate resource alerts if values exceed configured limits.

### 5.2 Network State Monitoring (`network`)
- **Interfaces**: MAC address, IP assignments, MTU, and interface link status (UP/DOWN).
- **ARP Table (`arp_watch`)**: Collects local ARP cache mappings to detect IP conflict or rogue device introduction.
- **TCP Connections (`tcp_watch`)**: Discovers active `ESTABLISHED` outbound connections, identifying remote IP and port destinations (e.g. C2 or abnormal exfiltration channels).

### 5.3 File Integrity Monitoring (`fim`)
Watches target paths recursively using `fsnotify` and OS-native kernel notification facilities:
- Tracks file creation (`CREATE`), modification (`WRITE`), deletion (`REMOVE`), and rename (`RENAME`).
- Computes SHA-256 hashes on modification to record cryptographic file diffs.
- Safeguards critical system binaries and configuration paths (`/etc`, `/usr/bin`, Windows `System32`).

### 5.4 OS Log Tailer (`logs`)
Follows OS security event logs automatically:
- **Linux**: `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`
- **macOS**: `/var/log/install.log`, `/var/log/system.log`
- **Windows**: Windows Security Event Log via syscall APIs
- Additional custom application logs can be specified under `paths`.

---

## 6. Built-in Sigma Engine & Local LLM Triage

### 6.1 Built-in Curated Sigma Rules (Tier 1)
twagentneo packages proven Sigma rules inside `embed.FS`. At startup, rules matching the host OS are compiled into memory:

| Platform | Category | Primary Detections |
|:---|:---|:---|
| **Linux** | Auth & Privilege Escalation | Sudo brute force, unauthorized crontab additions, bash history truncation, suspicious binaries |
| **macOS** | Persistence & Tampering | Sudo misuse, LaunchDaemon persistence, Gatekeeper bypass, SIP status alterations |
| **Windows** | Credential Theft & Execution | Mimikatz execution signatures, PowerShell download cradles, rogue local account creation, suspicious service installations |

### 6.2 Local AI Judge Triage (Tier 2: `tensai`)

When a Tier-1 rule triggers, candidate events are dispatched to the local `tensai` LLM engine:

1. **Sliding Context Window**:
   Retrieves up to 20 recent adjacent log lines to evaluate environmental context.
2. **False Positive Suppression**:
   Distinguishes normal system maintenance or legitimate admin scripts from genuine security breaches, drastically reducing alert fatigue.
3. **Quantitative Threat Score (0–100)**:
   Calculates an objective risk severity score.
4. **Actionable Remediation Guidance**:
   Maps the incident to MITRE ATT&CK tactics/techniques and delivers actionable remediation steps (e.g., isolate host, terminate PID, rotate credentials).

---

## 7. Exporters & TWSNMP NEO Integration

### 7.1 MQTT Telemetry Topics
Telemetry is streamed across dedicated MQTT topics tailored for TWSNMP NEO's ingestion engine:

```text
{topic_prefix}/{agent_id}/metrics     # Host resource metrics (CPU, Memory, Disk) [alias: resource]
{topic_prefix}/{agent_id}/interface   # Network interface status [alias: network]
{topic_prefix}/{agent_id}/arp         # ARP table snapshots
{topic_prefix}/{agent_id}/tcp         # Active TCP connection destinations
{topic_prefix}/{agent_id}/alert       # Enriched Sigma + AI Judge security alerts [alias: fim]
{topic_prefix}/{agent_id}/status      # Agent status / heartbeat / LWT [alias: heartbeat]
```

### 7.2 Syslog (RFC 5424 / RFC 3164)
Exports RFC-compliant structured syslog datagrams to enterprise SIEM collectors or TWSNMP NEO's syslog receiver via UDP/TCP.

### 7.3 SNMP TRAP (`TWAGENT-NEO-MIB.txt`)
Emits SNMPv2c / SNMPv3 traps using the enterprise MIB tree (OID: `.1.3.6.1.4.1.17862.3`):

- `twagentNeoAlertTrap` (`.1.3.6.1.4.1.17862.3.2.1`): Security alerts
- `twagentNeoResourceTrap` (`.1.3.6.1.4.1.17862.3.2.2`): Resource threshold events
- `twagentNeoFimTrap` (`.1.3.6.1.4.1.17862.3.2.3`): File integrity modifications

---

## 8. Operations & Self-Update

### 8.1 Checking Agent Version

```bash
twagentneo -version
# Sample output:
# twagentneo v0.1.0 (commit: 068f493, built: 2026-10-22T15:35:00Z, darwin/arm64)
```

### 8.2 Self-Updating CLI

Manage releases directly from the agent binary:

```bash
# Check if a new release is available
twagentneo update -check

# Apply update interactively
twagentneo update

# Update without confirmation prompt
twagentneo update -y

# Update to a specific release version
twagentneo update -version v0.2.0
```

> **Smart Environment Detection**: If installed via Homebrew, `twagentneo` advises running `brew upgrade`. Inside Docker containers, it suggests pulling the latest image tag.

---

## 9. Verification & Testing

Verify detection pipelines without administrative privileges on test hosts.

### 9.1 File Integrity Monitoring (FIM) Test
```bash
mkdir -p /tmp/fim_test
# Add /tmp/fim_test to collectors.fim.paths in config.yaml and start twagentneo

echo "initial data" > /tmp/fim_test/sample.txt
echo "modified payload" >> /tmp/fim_test/sample.txt
rm /tmp/fim_test/sample.txt
```
Observe real-time `FIM CREATE / MODIFY / DELETE` events in logs and telemetry topics.

### 9.2 Sigma & AI Judge Test
```bash
touch /tmp/test_audit.log
# Set collectors.logs.paths: ["/tmp/test_audit.log"] in config.yaml

# Simulate failed sudo attempts:
echo "Oct 22 10:00:00 server sudo[1234]: pam_unix(sudo:auth): authentication failure; logname=test uid=1000 euid=0 tty=/dev/pts/0 ruser=test rhost= user=root" >> /tmp/test_audit.log
```
The internal Sigma rule triggers, `tensai` evaluates the candidate alert, and an enriched alert with risk score and advisory is published.

---

## 10. Conclusion

twagentneo delivers an autonomous, high-speed security monitoring agent without runtime dependencies. By combining **instant Sigma rule matching** with **embedded LLM triage**, it protects servers and edge devices while providing seamless integration with TWSNMP NEO.

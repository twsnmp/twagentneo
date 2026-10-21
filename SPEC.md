# SPEC.md: twagentneo

## 1. Project Overview

### 1.1 Purpose
Implement `twagentneo`, a lightweight, high-performance, cross-platform monitoring and AI security agent written in Go for Windows, Linux, and macOS.
The agent collects host resources, network states (e.g., ARP tables), and security events/logs comparable to Wazuh Agent. For log auditing, it incorporates a built-in Sigma evaluation engine ported from proven implementations in TWSLA, executing intelligent triage (LLM-as-a-Judge) via the local LLM package **`tensai`** on suspicious detected events. The enriched metrics and alerts (including threat assessment, compliance verification, and actionable advisories) are transmitted to TWSNMP NEO (as well as FC/FK) via MQTT, syslog, and SNMP TRAP using a newly defined MIB tree.

### 1.2 Core Design Principles
- **Pure Go (`CGO_ENABLED=0`)**: Zero dependency on external C libraries, enabling 100% statically linked single-binary distribution with seamless cross-compilation.
- **Two-Tier Hybrid Threat Auditing (Sigma × tensai)**:
  1. **Tier 1 (Sub-millisecond / Ultra-low Footprint)**: Built-in Sigma rules filter massive incoming log streams down to candidate suspicious events within milliseconds.
  2. **Tier 2 (Intelligent Local Triage)**: Evaluates candidate events locally using the Go-native LLM package `tensai` to assess actual threats, check compliance violations, and generate remediation advisories.
- **Zero-Configuration Operation**: Eliminates external rule file maintenance. Curated essential rules are embedded into the binary via `embed.FS`, working out of the box upon deployment.
- **OS-Adaptive Selective Loading**: Detects `runtime.GOOS` at boot time to parse and index rules relevant only to the host platform, keeping idle CPU usage below 1% and resident memory footprint within 30–50MB.

---

## 2. System Architecture

```text
+-------------------------------------------------------------------------+
|                              twagentneo                                 |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 Collectors (Pure Go / Native OS)                  |  |
|  |  [Host Resource]   [ARP / Interface]   [FIM (Syscall/fsnotify)]   |  |
|  |  [Process State]   [Log Stream / Event Collector]                 |  |
|  +-------------------------------------------------------------------+  |
|                                  |                                      |
|                                  v (Raw Logs / Events)                  |
|  +-------------------------------------------------------------------+  |
|  |                 Tier-1: OS-Adaptive Sigma Engine                  |  |
|  |             (Ported from TWSLA / Pure Go Sigma)                   |  |
|  |  - Built-in Curated Rules (Sigma Primary + Wazuh Mapped)          |  |
|  |  - OS Selective Load on Boot (Linux / Windows / macOS)           |  |
|  |  - High / Critical Suspicious Event Filter                        |  |
|  +-------------------------------------------------------------------+  |
|                                  | (Suspicious Candidate Events)        |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |             Tier-2: Local LLM Judge (via tensai pkg)              |  |
|  |  - Threat Assessment & False Positive Filtering                  |  |
|  |  - Compliance Violation Evaluation (Privilege, Exfiltration, etc) |  |
|  |  - Summary & Actionable Remediation Advisory Generation           |  |
|  +-------------------------------------------------------------------+  |
|                                  | (Enriched Alerts & Metrics)          |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |                     Internal Event Bus                            |  |
|  |            (Buffered Channels / Non-blocking Queue)               |  |
|  +-------------------------------------------------------------------+  |
|                                  |                                      |
|                                  v                                      |
|  +-------------------------------------------------------------------+  |
|  |                    Exporters (Multi-Protocol)                     |  |
|  |   [MQTT Exporter]      [Syslog Exporter]    [SNMP Trap Exporter]  |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
           |                         |                    |
           v (MQTT/TLS)              v (UDP/TCP/TLS)      v (SNMPv2c/v3 Trap)
+-------------------------------------------------------------------------+
|                           TWSNMP NEO / FC / FK                          |
+-------------------------------------------------------------------------+
```

---

## 3. Collector Specifications

All collectors are implemented strictly in Pure Go without CGO, utilizing OS native syscalls and pseudo-filesystems.

### 3.1 Host Resources (`collector/resource`)
- **Linux**: Parsed directly from `/proc/stat`, `/proc/meminfo`, `/proc/diskstats`, `/proc/net/dev`, and `syscall.Statfs`.
- **Windows**: Invokes Win32 APIs (`GetSystemTimes`, `GlobalMemoryStatusEx`, `GetDiskFreeSpaceExW`) via `golang.org/x/sys/windows`.
- **macOS**: Invokes `sysctl` and `syscall.Statfs` via `golang.org/x/sys/unix`.
- **Collected Metrics**:
  - CPU utilization (Total and per-core %), load averages (1/5/15 min on Unix)
  - Memory: total, used, free, usage %, swap used
  - Disk: usage per mount point, I/O rates (bytes read/written, IOPS)
  - Network Traffic: interface-level RX/TX bytes, packet counts, drop/error rates

### 3.2 Network & ARP Cache (`collector/network`)
- **ARP / Neighbor Cache Acquisition**:
  - **Linux**: Parsing `/proc/net/arp` or Netlink socket (RTM_GETNEIGH) in Pure Go.
  - **Windows**: Direct syscall invocation of `iphlpapi.dll`'s `GetIpNetTable2`.
  - **macOS**: Routing socket inspection via `sysctl` (`NET_RT_FLAGS` + `RTF_LLINFO`).
- **Network State**:
  - Network interface states, IP/MAC addresses, and MTU via `net.Interfaces()`.
  - Listening sockets and port bindings (`/proc/net/tcp`, `/proc/net/udp`, Windows `GetExtendedTcpTable`).

### 3.3 Security & Integrity Auditing (`collector/security`)
#### A. File Integrity Monitoring (FIM)
- Detects unauthorized file creation, modification, deletion, and permission changes across critical system paths.
- Engine: OS native event watchers (Linux: `inotify`, Windows: `ReadDirectoryChangesW`, macOS: `kqueue`).
- Checksum: Pure Go `crypto/sha256`.

#### B. Log Stream Follower (Log Tailer)
- Real-time tailing of OS security logs with automatic log rotation tracking.
  - **Linux**: `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`
  - **Windows**: Windows Event Log API (`EvtSubscribe` / `EvtQuery`) via syscall
  - **macOS**: `/var/log/system.log` or Apple Unified Log (OSLog) API
- Raw lines/records are normalized into structured events and immediately forwarded to the Sigma evaluation pipeline.

---

## 4. Audit & AI Judge Engine (`engine/audit`)

### 4.1 Tier 1: Sigma Rule Evaluation (Ported from TWSLA)
- **Proven Pure Go Engine**: Leverages high-performance parsing and AST condition matching algorithms proven in TWSLA.
- **Embedded Rule Set (`embed.FS`)**:
  - Bundles curated High and Critical level rules from official Sigma and Wazuh repositories (brute-force login, privilege escalation, suspicious process trees, ransomware heuristics).
- **OS-Adaptive Loading**:
  - Evaluates `runtime.GOOS` during agent bootstrap and loads only matching rules (`rules/linux/*`, `rules/windows/*`, or `rules/darwin/*`) into memory.

### 4.2 Tier 2: Local LLM Judge (`tensai` Package Integration)
When Tier 1 flags an event as suspicious, the agent executes contextual evaluation locally via the `tensai` package.

- **Evaluation Pipeline**:
  1. Compiles target event data, surrounding context logs, associated process details, and executing user info into a structured prompt.
  2. Dispatches prompt to the `tensai` engine for local inference:
     - **Threat Assessment**: Verifies whether the alert is an actual attack or a benign false positive (e.g., admin maintenance, automated cron jobs).
     - **Compliance Audit**: Detects potential internal policy violations (unauthorized privilege escalation, data exfiltration risks).
     - **Actionable Advice**: Synthesizes concise situational explanations and recommended immediate countermeasures.
- **Graceful Fallback**:
  - If `tensai` local inference times out or fails, the event is immediately emitted using the Tier-1 Sigma alert metadata.

### 4.3 Alert Data Model
```go
type SecurityAlert struct {
    Timestamp   time.Time              `json:"timestamp"`
    RuleID      string                 `json:"rule_id"`
    RuleTitle   string                 `json:"rule_title"`
    Level       string                 `json:"level"` // low, medium, high, critical
    Category    string                 `json:"category"`
    SourceLog   string                 `json:"source_log"`
    MatchedData map[string]interface{} `json:"matched_data"`
    
    // Evaluated by the tensai package
    AIJudge *AIJudgeResult             `json:"ai_judge,omitempty"`
}

type AIJudgeResult struct {
    IsThreat           bool     `json:"is_threat"`
    ComplianceViolated bool     `json:"compliance_violated"`
    ComplianceTypes    []string `json:"compliance_types"` // e.g., ["Privilege_Abuse", "Unauthorized_Access"]
    Confidence         float64  `json:"confidence"`       // 0.0 - 1.0
    SummaryJa          string   `json:"summary_ja"`       // Human-readable summary
    ActionJa           string   `json:"action_ja"`        // Recommended mitigation
}
```

---

## 5. TWSNMP NEO / Twise MIB Specification

Defined under the Twise Labo Enterprise OID (`.1.3.6.1.4.1.17862`) at node `twagentNeo(3)`.

### 5.1 OID Tree Structure
```text
iso(1).org(3).dod(6).internet(1).private(4).enterprises(1).twise(17862)
 └── twagentNeo(3)
      ├── twagentNeoObjects(1)
      │    ├── twagentNeoInfo(1)
      │    │    ├── twagentNeoVersion(1)       : DisplayString
      │    │    ├── twagentNeoHostname(2)      : DisplayString
      │    │    └── twagentNeoOS(3)            : DisplayString
      │    └── twagentNeoTrapObjects(2)
      │         ├── twagentNeoTrapSeverity(1)  : INTEGER { info(1), warn(2), high(3), critical(4) }
      │         ├── twagentNeoTrapCategory(2)  : DisplayString
      │         ├── twagentNeoTrapRuleTitle(3) : DisplayString
      │         ├── twagentNeoTrapAIJudge(4)   : DisplayString (e.g. "Threat:YES, CompViolation:YES")
      │         ├── twagentNeoTrapAISummary(5) : DisplayString (Summary)
      │         └── twagentNeoTrapAIAction(6)  : DisplayString (Recommended Action)
      └── twagentNeoTraps(2)
           ├── twagentNeoTrapsPrefix(0)
           │    ├── twagentNeoResourceAlert(1) : Resource threshold exceeded
           │    ├── twagentNeoSecurityAlert(2) : Sigma + tensai AI security alert
           │    ├── twagentNeoFIMAlert(3)      : File integrity alert
           │    └── twagentNeoHeartbeat(4)     : Periodic keep-alive
```

### 5.2 SNMP Trap Varbind Layout (`twagentNeoSecurityAlert`)
1. `sysUpTimeInstance` (`.1.3.6.1.2.1.1.3.0`)
2. `snmpTrapOID.0` (`.1.3.6.1.6.3.1.1.4.1.0`) = `.1.3.6.1.4.1.17862.3.2.0.2`
3. `twagentNeoHostname` (`.1.3.6.1.4.1.17862.3.1.1.2`)
4. `twagentNeoTrapSeverity` (`.1.3.6.1.4.1.17862.3.1.2.1`)
5. `twagentNeoTrapCategory` (`.1.3.6.1.4.1.17862.3.1.2.2`)
6. `twagentNeoTrapRuleTitle` (`.1.3.6.1.4.1.17862.3.1.2.3`)
7. `twagentNeoTrapAIJudge` (`.1.3.6.1.4.1.17862.3.1.2.4`)
8. `twagentNeoTrapAISummary` (`.1.3.6.1.4.1.17862.3.1.2.5`)
9. `twagentNeoTrapAIAction` (`.1.3.6.1.4.1.17862.3.1.2.6`)

---

## 6. Exporter Specifications

All exporters are built using Pure Go packages with zero CGO dependencies.

### 6.1 MQTT (`exporter/mqtt`)
- Pure Go MQTT client (`paho.mqtt.golang`).
- Topic Hierarchy:
  - Metrics: `twsnmpneo/agent/{agent_id}/metrics`
  - Network: `twsnmpneo/agent/{agent_id}/network`
  - ARP Watch: `twsnmpneo/agent/{agent_id}/arp`
  - Security Alerts: `twsnmpneo/agent/{agent_id}/alert`
  - Health/LWT: `twsnmpneo/agent/{agent_id}/status`
- Alert payloads include the complete structured `ai_judge` field.

### 6.2 Syslog (`exporter/syslog`)
- Pure Go implementation over standard `net` package (UDP, TCP, TLS).
- Complies with RFC 5424 using Structured Data: `[twsnmpneo@17862 rule="..." threat="..." comp="..."]`.

### 6.3 SNMP TRAP (`exporter/snmp_trap`)
- Pure Go SNMP library (`gosnmp`).
- Supports SNMPv2c and SNMPv3 (AuthPriv: SHA256 / AES128).
- Transmits alerts formatted to the `twagentNeo` MIB schema.

---

## 7. Directory Structure

```text
twagentneo/
├── cmd/
│   └── twagentneo/
│       └── main.go                  # Entry point & daemon service lifecycle
├── embed/
│   ├── rules/
│   │   ├── linux/                   # Curated Linux Sigma/Wazuh rules (YAML)
│   │   ├── windows/                 # Curated Windows Sigma/Wazuh rules (YAML)
│   │   └── darwin/                  # Curated macOS Sigma/Wazuh rules (YAML)
│   └── mibs/
│       └── TWAGENT-NEO-MIB.txt      # MIB definition file
├── internal/
│   ├── collector/                   # OS-specific collectors (Pure Go)
│   │   ├── resource/
│   │   ├── network/
│   │   ├── fim/
│   │   └── logtail/
│   ├── audit/                       # Two-tier auditing engine
│   │   ├── sigma/                   # Ported Pure Go Sigma matcher
│   │   └── aijudge/                 # tensai package local LLM judge layer
│   │       ├── judge.go
│   │       └── prompt.go
│   ├── exporter/                    # Multi-protocol delivery
│   │   ├── mqtt.go
│   │   ├── syslog.go
│   │   └── snmptrap.go
│   ├── config/
│   │   └── config.go
│   └── pipeline/
│       └── bus.go                   # Non-blocking internal event dispatch
├── config.example.yaml
├── go.mod
├── go.sum
└── Makefile
```

---

## 8. Configuration Specification (`twagentneo.yaml`)

Designed for zero-maintenance: collectors and internal rule definitions work out of the box without requiring manual file path configurations.

```yaml
agent:
  id: "twagentneo-server-01"
  name: "Host-01"
  log_level: "info"

collectors:
  resource:
    enabled: true
    interval: 60s
  network:
    enabled: true
    interval: 180s
    arp_watch: true
  fim:
    enabled: true
  logs:
    enabled: true

audit:
  sigma:
    enabled: true              # Automatically runs embedded OS-specific Sigma rules
  ai_judge:
    enabled: true              # Local LLM triage powered by tensai package
    model_path: ""             # Optional path to custom model (uses tensai default if empty)
    timeout: 5s                # Inference timeout threshold

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
    format: "rfc5424"

  snmp_trap:
    enabled: true
    target: "twsnmp-neo-server:162"
    version: "v3"
    community: "public"
    v3:
      user: "twsnmpUser"
      auth_protocol: "SHA256"
      auth_password: "${TRAP_AUTH_PASS}"
      priv_protocol: "AES128"
      priv_password: "${TRAP_PRIV_PASS}"
```

---

## 9. Build, Packaging & Release Specification

### 9.1 Build System & Toolchain
- **Build with mise (`mise.toml`)**:
  - Toolchain: `go = "1.27"`
  - Tasks:
    - `mise run build`: Compile release binary with embedded version (`-X main.version`), commit hash (`-X main.commit`), and build timestamp (`-X main.date`).
    - `mise run build-debug`: Compile debug binary with symbol tables.
    - `mise run test`: Execute unit tests with race detection (`go test -race -v ./...`).
- **Pure Go Single Binary (`CGO_ENABLED=0`)**:
  - Statically linked single binary without external C dependencies across Linux, Windows, and macOS (amd64 and arm64).

### 9.2 Release & Distribution Pipeline
- **GitHub Actions & GoReleaser (`.goreleaser.yaml`)**:
  - Automated cross-compilation on tag push (`v*`) or manual workflow dispatch.
  - Multi-platform packaging: `.tar.gz` for Linux/macOS, `.zip` for Windows.
- **Homebrew Formula (macOS / Linux)**:
  - Automatically publishes and updates `Formula/twagentneo.rb` in `twsnmp/homebrew-tap` via GoReleaser.
- **One-Liner Installation Script (`install/install.sh`)**:
  - Fetches the latest compatible release asset and installs to `/usr/local/bin`:
    ```bash
    curl -fsSL https://raw.githubusercontent.com/twsnmp/twagentneo/main/install/install.sh | sh
    ```

### 9.3 Self-Update & CLI Operations
- **CLI Commands & Flags**:
  - `twagentneo -version` / `twagentneo version`: Displays semantic version, git commit hash, build timestamp, and runtime architecture.
  - `twagentneo update`: Automatically checks GitHub Releases and safely replaces the running executable.
  - `twagentneo update -check` (or `-check-update`): Checks for available updates without applying.
  - `twagentneo update -yes`: Applies the update without interactive confirmation prompts.
  - `twagentneo update -version <tag>`: Updates or rollbacks to a specific release tag.
- **Environment-Aware Update Safety (`internal/updater`)**:
  - **Homebrew**: Detects Homebrew installation path and prompts the user to run `brew upgrade twagentneo`.
  - **Containers**: Detects container environments and prompts image pulling.
  - **Standalone Binaries**: Atomic executable replacement (`os.Rename` with rollback backup on Unix/macOS and Windows `.bak` rotation).

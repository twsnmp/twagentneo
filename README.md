# twagentneo

[日本語のREADMEはこちら (Japanese README)](./README_ja.md) | [Documentation (GitHub Pages)](https://twsnmp.github.io/twagentneo/)

Pure Go, cross-platform security & monitoring agent for TWSNMP NEO with built-in Sigma rules and local LLM triage (tensai).

## Features

- **Pure Go Single Binary (`CGO_ENABLED=0`)**: Zero external dependencies, runs out of the box across Linux, macOS, and Windows with hardened dependencies (including MQTT security update for CVE-2025-10543).
- **Embedded Sigma Engine**: Curated security rules embedded via `embed.FS` with zero-maintenance startup.
- **Local AI Triage**: Built-in LLM judge powered by `tensai` for contextual false-positive suppression and actionable alert enrichment.
- **Security Configuration Assessment (SCA)**: Pure Go security auditing engine for CIS benchmark compliance (world-writable permissions, private keys/.env exposure, leftover backup files, cleartext secrets, sshd/sysctl) with baseline startup and FIM event-driven triggers.
- **Windows Service & Linux systemd Integration**: Native background daemon installation and management via simple CLI (`twagentneo service install/start/stop/restart/status/remove`).
- **Network Traffic & System Telemetry**: Real-time traffic rate calculation (Bytes/Packets in/out rates), ARP inspection, TCP connection tracking, and CPU/memory/disk monitoring with smart filesystem exclusion and deduplication.
- **Self-Updating**: Built-in CLI updater (`twagentneo update`) with Homebrew and container awareness.
- **Multi-Protocol Telemetry**: Seamless delivery to TWSNMP NEO via MQTT, Syslog, and SNMP TRAP.

---

## Documentation

Full manuals and architectural guides are published on GitHub Pages:
- 📖 [Getting Started with twagentneo (English)](https://twsnmp.github.io/twagentneo/)
- 📖 [はじめての twagentneo (日本語マニュアル)](https://twsnmp.github.io/twagentneo/index_ja.html)

---

## Installation

### macOS (Homebrew)

```bash
brew install twsnmp/tap/twagentneo
```

### Linux / macOS (One-Liner Script)

```bash
curl -fsSL https://raw.githubusercontent.com/twsnmp/twagentneo/main/install/install.sh | sh
```

### Manual Download

Download pre-built binary archives directly from [GitHub Releases](https://github.com/twsnmp/twagentneo/releases).

---

## Building from Source

Using [`mise`](https://mise.jdx.dev/):

```bash
mise run build
```

Or using `make`:

```bash
make build
```

---

## Usage & Operations

### Start Agent

```bash
# Normal start
twagentneo -config config.yaml

# Start with console debug logging enabled (-debug or -d)
twagentneo -config config.yaml -debug
```

### Check Version

```bash
twagentneo -version
# twagentneo v0.3.0 (commit: abc1234, built: 2026-10-27T05:00:00Z, darwin/arm64)
```

### Self-Update

```bash
# Check for updates
twagentneo update -check

# Apply update
twagentneo update
```

### Service Management (Windows Service & Linux systemd)

Just like `twsnmpneo`, you can install and manage `twagentneo` as a background service.

#### Windows Service
Run in an elevated Administrator PowerShell or Command Prompt:

```powershell
# Install as a Windows service (automatic start on boot)
.\twagentneo.exe service install -service-auto -config C:\twagentneo\config.yaml

# Start service
.\twagentneo.exe service start

# Restart service
.\twagentneo.exe service restart

# Query status
.\twagentneo.exe service status

# Stop service
.\twagentneo.exe service stop

# Remove service
.\twagentneo.exe service remove
```

#### Linux systemd Service
Run with root / sudo privileges:

```bash
# Install as a systemd service (automatic start on boot)
sudo /usr/local/bin/twagentneo service install -auto -config /etc/twagentneo/config.yaml

# Start service
sudo /usr/local/bin/twagentneo service start

# Restart service
sudo /usr/local/bin/twagentneo service restart

# Query status
sudo /usr/local/bin/twagentneo service status

# Stop service
sudo /usr/local/bin/twagentneo service stop

# Remove service
sudo /usr/local/bin/twagentneo service remove
```

---

## Testing & Verification

For instructions on how to test **Sigma rules** and **File Integrity Monitoring (FIM)** alerts locally without administrator privileges, see [TESTING.md](TESTING.md).

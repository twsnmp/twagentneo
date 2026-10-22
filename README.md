# twagentneo

[日本語のREADMEはこちら (Japanese README)](./README_ja.md) | [Documentation (GitHub Pages)](https://twsnmp.github.io/twagentneo/)

Pure Go, cross-platform security & monitoring agent for TWSNMP NEO with built-in Sigma rules and local LLM triage (tensai).

## Features

- **Pure Go Single Binary (`CGO_ENABLED=0`)**: Zero external dependencies, runs out of the box across Linux, macOS, and Windows.
- **Embedded Sigma Engine**: Curated security rules embedded via `embed.FS` with zero-maintenance startup.
- **Local AI Triage**: Built-in LLM judge powered by `tensai` for contextual false-positive suppression and actionable alert enrichment.
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
# twagentneo v0.1.0 (commit: abc1234, built: 2026-10-22T08:00:00Z, darwin/arm64)
```

### Self-Update

```bash
# Check for updates
twagentneo update -check

# Apply update
twagentneo update
```

---

## Testing & Verification

For instructions on how to test **Sigma rules** and **File Integrity Monitoring (FIM)** alerts locally without administrator privileges, see [TESTING.md](TESTING.md).

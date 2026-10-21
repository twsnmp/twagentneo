# twagentneo

Pure Go, cross-platform security & monitoring agent for TWSNMP NEO with built-in Sigma rules and local LLM triage (tensai).

## Features

- **Pure Go Single Binary (`CGO_ENABLED=0`)**: Zero external dependencies, runs out of the box across Linux, macOS, and Windows.
- **Embedded Sigma Engine**: Curated security rules embedded via `embed.FS` with zero-maintenance startup.
- **Local AI Triage**: Built-in LLM judge powered by `tensai` for contextual false-positive suppression and actionable alert enrichment.
- **Self-Updating**: Built-in CLI updater (`twagentneo update`) with Homebrew and container awareness.

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
twagentneo -config twagentneo.yaml
```

### Check Version

```bash
twagentneo -version
# twagentneo v0.1.0 (commit: abc1234, built: 2026-10-21T08:00:00Z, darwin/arm64)
```

### Self-Update

```bash
# Check for updates
twagentneo update -check

# Apply update
twagentneo update
```


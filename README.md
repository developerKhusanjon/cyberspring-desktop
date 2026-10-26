# 🌿 CyberSpring
### Ultra-Lightweight Detection Engineering Automation, SAST Vulnerability Scanner & Glassmorphic SOAR Controlling Center

CyberSpring is an enterprise-grade desktop security suite crafted specifically for **Detection Engineers**, **SOC Analysts**, and **Security Architects**. It works natively and cross-platform across **Windows**, **macOS**, and **Linux**, bridging the full spectrum of modern defensive engineering:
- **Glassmorphic SOC Controlling Center**: Real-time perimeter radar, satellite cloud telemetry nodes, incident investigation, and machine-speed SOAR playbooks.
- **Dual-Mode Terminal Studio**: Real interactive command-line shell with ANSI rendering directly on the UI alongside an AI Detection Engineering Agent studio.
- **Deep SAST Vulnerability Scanner**: Multi-language static code analysis with **1-click automated remediation (file patching)**, backup reversion, custom rule registration, and SARIF 2.1.0 export.

---

## ✨ Key Features & User Interface Experience

### 1. Glassmorphic SOC Controlling Center (Dashboard)
- **Radial Threat Defense Radar HUD**: Concentric luminous arcs with real-time `68% Threats Blocked` defense readout.
- **Interactive Cloud & Perimeter Telemetry Nodes**: Clickable nodes for **AWS** (32 events), **Microsoft Azure** (18 events), **Google Cloud** (14 events), **Okta** (12 events), **GitHub** (9 events), **Fortinet** (7 events, warning), and **Cisco** (6 events, warning) that open a live telemetry stream inspector drawer.
- **Incident Investigation & Response Dialog**: Click on any active incident to inspect affected assets, threat actor IPs, and trigger one-click containment (EDR host isolation or edge firewall IP drops).
- **SOAR Automation & Playbooks**: Status cards and execution logs for *Malware Containment*, *Suspicious IP Blocking*, *Okta Session Revocation*, and *AWS Key Quarantine*.
- **Fleet Health & Alert Velocity**: Live metrics for servers and workstations with 24-hour velocity meters.

### 2. Dual-Mode Terminal Studio
- **Tab A: Interactive CLI Shell**:
  - Full Unix/Windows-style interactive terminal directly within the browser UI.
  - Command line prompt (`cyberspring@soc-hub:~$ `) with command history (Up/Down arrows) and quick action chips.
  - Direct execution of scanning and SOC commands:
    ```bash
    scan test_samples/vulnerable_app    # Run SAST scan and format findings
    test rules/vpn_password_spray.yml   # Run detection replay fixtures and backtest
    agent "Detect AWS root login"       # Run detection engineering AI workflow
    report test_samples/vulnerable_app  # Export SARIF and Markdown reports
    remediate SEC-001 <file>            # Apply automated security patch
    revert <file>                       # Restore file from .bak backup
    status                              # View SOC telemetry metrics
    incidents                           # List active security incidents
    soar list | soar run <id>           # Inspect or trigger SOAR playbooks
    rules list | rules view <file>      # Inspect Sigma detection rules
    help                                # Command manual and syntax
    ```
- **Tab B: Detection Engineering Agent Studio**:
  - Natural language prompt studio supporting any security requirement (VPN Spray, AWS Root without MFA, Kubernetes Privileged Pods, SSH Brute Force, GitHub Token Leaks).
  - Dual-pane live syntax editor synchronized with `rules/vpn_password_spray.yml` and `tests/vpn_password_spray_test.yml`.
  - Two-stage replay & 30-day historical backtest engine (412,806 events) with false-positive budgeting.

### 3. Source Code Weak-Point & Vulnerability Scanner (SAST)
- **Multi-Language AST & Pattern Engine**: Audits Go, Python, JavaScript/TypeScript, Java, PHP, Shell, and configuration files in milliseconds.
- **Comprehensive Weakness Detection**:
  - Hardcoded AWS keys, GitHub tokens, Slack webhooks, Stripe keys, JWT secrets (`CWE-798`, `CWE-321`)
  - SQL Injection via string formatting/concatenation (`CWE-89`)
  - Command Injection & Shell Execution (`CWE-78`)
  - Insecure Deserialization (`CWE-502`)
  - Server-Side Request Forgery / Metadata Access (`CWE-918`)
  - Path Traversal Vulnerabilities (`CWE-22`)
  - Weak Cryptographic Hashes (`MD5`, `SHA-1`) (`CWE-328`)
  - Disabled TLS verification (`InsecureSkipVerify: true`) (`CWE-295`)
  - Overly permissive CORS policies (`CWE-942`)
  - Debug mode active in production (`CWE-489`)
- **1-Click Auto-Remediation (Live File Patching)**: Click **"⚡ Apply Auto-Fix"** to automatically patch the source file with safe replacement code, save a `.bak` backup, and immediately verify the fix. Click **"↩️ Revert"** anytime to restore the original code.
- **Custom Rule Manager**: Create and register custom regex rules directly through the UI.
- **Multi-Format Export**: One-click SARIF 2.1.0, Executive HTML, Markdown, and JSON report downloads.

---

## ⚡ Architecture & Cross-Platform Performance

- **Language**: Native Go (`1.27.3`) with zero runtime dependencies.
- **Cross-Platform**: Standalone binaries for macOS (ARM64/AMD64), Linux (AMD64/ARM64), and Windows (AMD64 `.exe`).
- **Memory Footprint**: `<25 MB RAM` cold start.
- **Startup Latency**: `<5 ms`.
- **Embedded Assets**: UI, glassmorphic styles, rules, and engines embedded directly in binary via `//go:embed`.

---

## 🚀 Quick Start Guide

### 1. Server Control Commands (macOS & Linux)
```bash
# Bring the server UP (starts in foreground or browser):
make up
# OR: ./up.sh
# OR background daemon mode: ./up.sh -d

# Check server status:
make status

# Bring the server DOWN (stops running instance):
make down
# OR: ./down.sh

# Restart server:
make restart
```

### 2. Server Control Commands (Windows)
```cmd
REM Command Prompt (CMD):
up.bat      REM Bring server UP
down.bat    REM Bring server DOWN

REM PowerShell:
.\up.ps1    REM Bring server UP
.\down.ps1  REM Bring server DOWN
```

### 3. Desktop UI Access & 1-Click Shutdown
- **Web Dashboard**: Open [http://127.0.0.1:8787](http://127.0.0.1:8787)
- **1-Click Down from UI**: Click the red **"🛑 Down Server"** button in the top navigation bar.
- **Terminal CLI Down**: Type `down` or `shutdown` in the UI terminal shell.

### 3. Build Standalone Cross-Platform Binaries
```bash
# Build native binary:
make build

# Build all 5 cross-platform binaries (macOS, Linux, Windows):
make build-all
```
Compiled standalone executables are placed in `bin/`:
- `bin/cyberspring-darwin-arm64` (macOS Apple Silicon)
- `bin/cyberspring-darwin-amd64` (macOS Intel)
- `bin/cyberspring-linux-amd64` (Linux x86_64)
- `bin/cyberspring-linux-arm64` (Linux AArch64)
- `bin/cyberspring-windows-amd64.exe` (Windows 64-bit executable)

---

## 📦 Standalone Installation & New Device Deployment

CyberSpring is designed to run on **any fresh device** with **zero external dependencies** (no Go runtime, no Python, no Node.js, no Docker required on the target machine). Everything—the user interface, radar canvas, glassmorphic stylesheets, default Sigma rules, and detection engines—is compiled directly into a single self-contained native binary.

When launched on a new device where no local rule repository exists, CyberSpring automatically provisions its configuration directory at `~/.cyberspring/rules/` and `~/.cyberspring/tests/` seamlessly.

### 🍏 macOS Installation
```bash
# Option 1: Automatic 1-Click Installer
./install.sh
# OR via Makefile:
make install

# What it does:
# 1. Detects Apple Silicon (ARM64) or Intel (AMD64) architecture.
# 2. Installs CyberSpring.app into /Applications/ with native high-res AppIcon.
# 3. Installs CLI executable into /usr/local/bin/cyberspring (or ~/.local/bin/).
# 4. Enables instant launch from Launchpad, Spotlight, or Terminal ('cyberspring').

# Option 2: Manual Drag & Drop
# Copy bin/CyberSpring.app into your /Applications/ folder.
```

### 🐧 Linux Installation (Ubuntu, Debian, Fedora, Arch, Alpine, RHEL)
```bash
# Run the universal installer:
./install.sh
# OR via Makefile:
make install

# What it does:
# 1. Detects x86_64 or ARM64 architecture.
# 2. Copies standalone binary to /usr/local/bin/cyberspring (or ~/.local/bin/cyberspring).
# 3. Installs desktop icon to ~/.local/share/icons/hicolor/512x512/apps/cyberspring.png.
# 4. Registers ~/.local/share/applications/cyberspring.desktop for GNOME/KDE/XFCE menus.
# 5. Automatically updates desktop application cache.
```

### 🪟 Windows Installation (Windows 10, 11, Server)
```cmd
REM Option 1: Double-click install.bat in Windows File Explorer
install.bat

REM Option 2: PowerShell
.\install.ps1

REM What it does:
REM 1. Installs cyberspring.exe to %LOCALAPPDATA%\Programs\CyberSpring\ (no Admin rights required).
REM 2. Copies application icon (assets\icon.ico).
REM 3. Creates a Desktop Shortcut: "CyberSpring.lnk".
REM 4. Creates a Start Menu Shortcut: "CyberSpring.lnk".
REM 5. Permanently registers CyberSpring in the User's PATH so typing 'cyberspring' works anywhere.
```

### 🗑️ Uninstallation
```bash
# macOS & Linux:
./uninstall.sh
# OR: make uninstall

# Windows:
uninstall.bat
# OR: .\uninstall.ps1
```

### 🎁 Standalone Release Distribution Archives
To generate ready-to-distribute release packages for users or cloud deployment:
```bash
make dist
```
This builds standalone archives inside `dist/`:
- `dist/cyberspring-v1.0.0-macos-arm64.tar.gz` (Apple Silicon `.app` + CLI + installer)
- `dist/cyberspring-v1.0.0-macos-amd64.tar.gz` (Intel Mac `.app` + CLI + installer)
- `dist/cyberspring-v1.0.0-linux-amd64.tar.gz` (Linux 64-bit + `.desktop` + icon + installer)
- `dist/cyberspring-v1.0.0-linux-arm64.tar.gz` (Linux ARM64 + `.desktop` + icon + installer)
- `dist/cyberspring-v1.0.0-windows-amd64.zip` (Windows 64-bit `.exe` + `.bat` / `.ps1` installers + icon)


## 📁 Repository Structure

```
cyberspring/
├── cmd/cyberspring/main.go        # Unified CLI and Desktop launcher
├── pkg/
│   ├── detection/                 # Sigma engine, correlation rules, agent synthesis & backtesting
│   │   ├── agent.go               # Natural language detection plan synthesizer
│   │   ├── backtest.go            # 30-day historical log streamer
│   │   ├── engine.go              # Sliding-window correlation engine
│   │   ├── replay.go              # Replay fixture runner
│   │   └── rules.go               # Sigma rule data structures
│   ├── sast/                      # Multi-language code scanner & remediation engine
│   │   ├── scanner.go             # Concurrent file tree scanner
│   │   ├── rules.go               # Comprehensive CWE vulnerability rules
│   │   ├── remediation.go         # 1-click auto-patching & backup engine
│   │   └── reporter.go            # SARIF 2.1.0 & Markdown report generators
│   ├── soar/                      # Incident playbooks & perimeter telemetry
│   │   ├── playbooks.go           # Orchestrated response playbooks
│   │   └── integrations.go        # Cloud/perimeter telemetry feeds & incidents
│   └── web/                       # Embedded HTTP/REST server & interactive terminal CLI
│       ├── server.go              # REST control API endpoints
│       ├── terminal_cmd.go        # Web terminal command executor & ANSI formatter
│       └── static/
│           ├── index.html         # Main controlling center shell & modal system
│           ├── css/glass.css      # Glassmorphism 2.0 design tokens & modal styles
│           ├── css/terminal.css   # Dual-mode macOS terminal & CLI console styles
│           └── js/
│               ├── app.js         # Navigation, telemetry modal & state manager
│               ├── radar.js       # Animated Radial Threat Radar (Canvas)
│               ├── terminal.js    # Interactive CLI terminal & agent session runner
│               └── sast.js        # Vulnerability inspector, auto-patching & filters
├── rules/                         # Production Sigma detection rules
├── tests/                         # Unit attack and benign replay fixtures
├── test_samples/vulnerable_app/   # Sample vulnerable codebase for instant testing
├── bin/                           # Compiled cross-platform binaries
├── Makefile                       # Cross-platform build automation
├── run.sh                         # macOS/Linux launcher
├── run.bat                        # Windows CMD launcher
├── run.ps1                        # Windows PowerShell launcher
└── README.md                      # Documentation
```

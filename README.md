# 🦀🐹 ai-server-audit

> AI-powered server audit tool written in **Rust** (core) + **Go** (CLI).
> Health checks, port scanning, security analysis, and update detection — all in one binary.

---

## Architecture

```
ai-server-audit/
├── core/          # Rust — all network & system checks (compiled to .so)
│   └── src/lib.rs #   port scan · health · security · updates · FFI exports
├── cli/           # Go  — CLI wrapper, calls Rust via cgo
│   └── main.go    #   arg parsing · output · config · webhook
├── config/        # Example config files
└── scripts/       # install.sh — one-line installer
```

**Why Rust + Go?**
- Rust handles the unsafe, performance-critical network I/O with zero-cost abstractions and memory safety guarantees
- Go provides a clean, ergonomic CLI surface with fast compile times and easy cross-compilation
- Rust core is compiled as a shared library (`cdylib`), called from Go via `cgo` FFI

---

## Features

| Check            | Description                                           |
|------------------|-------------------------------------------------------|
| ✅ Health Check   | Ping Anthropic Claude & OpenAI API endpoints          |
| 🔍 Port Scan     | Parallel TCP scan with service detection & risk rating |
| 🔒 Security      | Telnet, FTP, Redis, MongoDB, ES, MySQL, PostgreSQL exposure checks |
| 📦 Updates       | APT (Debian/Ubuntu) and Homebrew (macOS) update detection |

---

## Install

**One-liner:**
```bash
curl -sSf https://raw.githubusercontent.com/YOUR_USER/ai-server-audit/main/scripts/install.sh | bash
```

**Or build manually:**
```bash
git clone https://github.com/YOUR_USER/ai-server-audit
cd ai-server-audit

# 1. Build Rust core
cd core && cargo build --release

# 2. Build Go CLI (links against Rust .so)
cd ../cli
CGO_ENABLED=1 \
  CGO_LDFLAGS="-L../core/target/release -laudit_core -ldl -lpthread -lm" \
  go build -o ../dist/ai-server-audit .
```

**Requirements:**
- Rust 1.70+ (`rustup` recommended)
- Go 1.21+
- Linux or macOS (Windows: WSL2)

---

## Usage

```bash
# 1. Create config
ai-server-audit init

# 2. Edit audit.json — set your server IP and (optionally) API keys
nano audit.json

# 3. Run full audit
ai-server-audit run

# 4. Run specific checks
ai-server-audit health
ai-server-audit ports  --host 10.0.0.1
ai-server-audit security
ai-server-audit updates

# 5. JSON output + save report
ai-server-audit run --output json --report report.json

# 6. Override host inline
ai-server-audit run --host 192.168.1.100
```

---

## Configuration (`audit.json`)

```json
{
  "server": {
    "host": "YOUR_SERVER_IP",
    "timeout_ms": 1500,
    "scan_threads": 50
  },
  "ports": {
    "scan": [22, 80, 443, 3306, 5432, 6379, 8080, 27017],
    "forbidden": [23, 21]
  },
  "checks": {
    "health_check": true,
    "port_scan": true,
    "security": true,
    "updates": true
  },
  "ai": {
    "anthropic": true,
    "openai": true,
    "anthropic_api_key": "sk-ant-...",
    "openai_api_key": "sk-..."
  },
  "output": {
    "format": "pretty",
    "report_file": "/var/log/audit.json"
  },
  "notify": {
    "webhook_url": "https://hooks.slack.com/services/..."
  }
}
```

---

## Exit Codes

| Code | Meaning               |
|------|-----------------------|
| `0`  | All checks passed     |
| `1`  | One or more CRITICAL  |

---

## License

MIT — see [LICENSE](LICENSE)

---

## Contributing

PRs welcome! The Rust core and Go CLI are intentionally decoupled — you can improve checks in `core/src/lib.rs` without touching the CLI, and vice versa.

---

## Author

Created by **Turac** — [github.com/mturac](https://github.com/mturac)

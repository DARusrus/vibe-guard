# vibe-guard

**AI-generated code ships fast. It also ships SQL injection, hardcoded API keys, and SSRF at scale.** vibe-guard detects AI-written code, then scans it harder.

[![PyPI version](https://img.shields.io/pypi/v/vibe-guard?color=blue)](https://pypi.org/project/vibe-guard/)
[![CI](https://img.shields.io/github/actions/workflow/status/ahmbt/vibe-guard/ci.yml?branch=main&label=CI)](https://github.com/ahmbt/vibe-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://pypi.org/project/vibe-guard/)

---

<!-- Demo GIF coming soon. To record: vhs docs/demo.vhs
     Script: scan tests/fixtures/vulnerable_app, show findings,
     show GitHub Security tab with SARIF annotations.
     Tool: https://github.com/charmbracelet/vhs -->

*Coming soon: demo showing AI-generated Flask app with 8 findings
annotated inline on a pull request via GitHub Security tab.*

*Scanning a Flask app built with Claude Code — 13 findings, multiple critical, inline PR annotations via GitHub Security tab.*

---

## Why vibe-guard?

AI coding tools generate code fast. They also generate SQL injection, hardcoded API keys, and SSRF — at scale. Every `cursor.execute(f"SELECT ...")` that Claude writes is one more SQL injection waiting for production. Generic SAST tools weren't built for this pattern. They scan everything equally, miss AI-specific idioms, and produce false positive rates that make developers turn them off entirely.

AI models produce statistically fingerprinted code. Uniform function lengths. Google-style docstrings on everything. Textbook variable names. Bare exception swallows. vibe-guard's detector identifies these patterns using three offline heuristic signals — comment patterns, structural regularity, and token fingerprints — then applies stricter scanning exactly where the risk is highest.

The result: fewer false positives on your legacy code, aggressive scanning on new AI-generated code, and findings that explain *why* AI specifically produces each vulnerability pattern — not just that a pattern was found. Each finding includes an `ai_context` field explaining the training data bias or generation shortcut that caused the issue.

## Install

```bash
pip install vibe-guard
```

## Quick start

**1. Scan your project:**

```bash
vibe-guard scan .
```

**2. Set up GitHub Actions, pre-commit, and config in one command:**

```bash
vibe-guard init
```

**3. Or add the GitHub Action manually:**

```yaml
name: vibe-guard security scan
on:
  push:
    branches: [main]
  pull_request:
permissions:
  security-events: write
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: ahmbt/vibe-guard@v1
        with:
          severity: MEDIUM
          fail-on-findings: true
```

## How it works

```
  [ Your code ]
       │
       ▼
  ┌─────────────────────────┐
  │    AI Code Detector     │   ← scores each file 0.0–1.0
  │  comments · structure · tokens  │     using offline heuristics
  └─────────────────────────┘
       │
       ├── score ≥ 0.6 → FULL scan        (all 18 vulnerability rules)
       ├── score 0.3–0.6 → MEDIUM scan    (Tier 1: SQLi, SSRF, secrets)
       └── score < 0.3 → CRITICAL only    (secrets and SQL injection only)
       │
       ▼
  ┌─────────────────────────┐
  │  Semgrep CE + detect-   │   ← 18 rules targeting AI-specific
  │      secrets            │     vulnerability patterns
  └─────────────────────────┘
       │
       ▼
  Terminal · SARIF · JSON
```

Files that look like AI wrote them get the full 18-rule scan. Files that look human-written get only the critical checks. This is how vibe-guard keeps false positives low while catching the vulnerabilities that matter.

## Security rules

18 rules across Python, JavaScript, and TypeScript — each with an `ai_context` explaining why AI produces that vulnerability.

| Rule | Lang | Sev | What it catches |
|------|------|-----|-----------------|
| `python-sqli-fstring` | Python | 🔴 CRITICAL | SQL injection via f-strings and `%` formatting in `execute()` |
| `python-hardcoded-secret` | Python | 🔴 CRITICAL | Hardcoded API keys, passwords, and tokens in assignments |
| `python-deserial-*` | Python | 🔴 CRITICAL | `pickle.loads()`, `yaml.load()`, `eval()` on untrusted data |
| `python-auth-jwt-verify` | Python | 🔴 CRITICAL | JWT decode with verification disabled |
| `python-cmdi-shell-true` | Python | 🟠 HIGH | `subprocess.run(shell=True)` with user input |
| `python-ssrf-user-url` | Python | 🟠 HIGH | `requests.get()` with user-controlled URLs |
| `python-path-traversal` | Python | 🟠 HIGH | `open()` with unsanitized user paths |
| `python-auth-timing` | Python | 🟠 HIGH | `==` comparison for password/token verification |
| `python-mass-assignment` | Python | 🟠 HIGH | ORM `.create(**request.data)` without field allowlists |
| `python-cors-wildcard` | Python | 🟡 MEDIUM | `Access-Control-Allow-Origin: *` in responses |
| `python-error-exposure` | Python | 🟡 MEDIUM | Stack traces and exception details in API responses |
| `js-sqli-template-literal` | JS | 🔴 CRITICAL | SQL injection via template literals in `query()` |
| `js-hardcoded-secret` | JS | 🔴 CRITICAL | Hardcoded secrets in variable assignments |
| `js-eval-user-input` | JS | 🔴 CRITICAL | `eval()`, `Function()`, `setTimeout(string)` with user input |
| `js-xss-innerHTML` | JS | 🟠 HIGH | `innerHTML` and `dangerouslySetInnerHTML` with dynamic content |
| `js-prototype-pollution` | JS | 🟠 HIGH | `__proto__` assignment and recursive merge without safeguards |
| `js-csrf-missing-token` | JS | 🟡 MEDIUM | `fetch()` and `axios.post()` without CSRF token headers |
| `ts-sqli-template-literal` | TS | 🔴 CRITICAL | Raw SQL in TypeORM, Prisma, and Drizzle query builders |
| `ts-type-assertion-bypass` | TS | 🟡 MEDIUM | `as any` cast passed into security-sensitive functions |

> **Full rule IDs** use the `vibeguard-` prefix (e.g., `vibeguard-python-sqli-fstring`). The table abbreviates for readability.

## GitHub Action

### Minimal setup

```yaml
- uses: ahmbt/vibe-guard@v1
```

That's it. Installs vibe-guard, scans `.`, uploads SARIF to the Security tab, and fails if findings are present.

### Full configuration

```yaml
- uses: ahmbt/vibe-guard@v1
  with:
    path: '.'              # Directory or file to scan
    severity: 'MEDIUM'     # Minimum severity: CRITICAL, HIGH, MEDIUM, LOW
    ai-threshold: '0.6'    # AI confidence threshold 0.0–1.0
    fail-on-findings: true # Exit 1 if findings present
    upload-sarif: true     # Upload to GitHub Security tab
    python-version: '3.11' # Python version for the runner
```

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory or file to scan |
| `severity` | `MEDIUM` | Minimum severity to report |
| `ai-threshold` | `0.6` | AI confidence threshold (0.0–1.0) |
| `fail-on-findings` | `true` | Exit with code 1 if findings exist |
| `upload-sarif` | `true` | Upload SARIF to GitHub Security tab |
| `python-version` | `3.11` | Python version for the runner |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings across all severities |
| `ai-files-detected` | Number of files identified as AI-generated |
| `critical-count` | Number of CRITICAL severity findings |
| `high-count` | Number of HIGH severity findings |
| `sarif-path` | Path to the generated SARIF file |

### GitHub Security tab

When `upload-sarif` is enabled (the default), findings appear as inline annotations on pull requests and in the repository's **Security → Code scanning alerts** tab. Each alert includes the finding message, fix guidance, and AI context.

## Configuration

Create `.vibeguard.toml` in your project root:

```toml
[vibeguard]

# Minimum severity level to report.
# Options: CRITICAL, HIGH, MEDIUM, LOW
# Default: MEDIUM
min_severity = "MEDIUM"

# AI confidence threshold. Files scoring above this receive the full
# 18-rule scan. Files below receive a lighter scan (fewer rules).
# Range: 0.0 to 1.0. Default: 0.6
ai_threshold = 0.6

# File extensions to include in scanning.
# Default: [".py", ".js", ".ts", ".jsx", ".tsx"]
extensions = [".py", ".js", ".ts", ".jsx", ".tsx"]

# Output format when running from CLI without --format flag.
# Options: terminal, sarif, json
# Default: terminal
default_format = "terminal"

# Exit with code 1 if any findings are present (used in CI).
# Default: true
fail_on_findings = true

# Glob patterns to exclude from scanning.
# Default: common build and dependency directories.
exclude_paths = [
    "node_modules",
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    "dist",
    "build",
    "*.egg-info",
    "tests/fixtures",
]

# Rule IDs to ignore across all scans. Use sparingly.
# Example: ignore_rules = ["vibeguard-python-cors-wildcard"]
ignore_rules = []

# Additional directories containing custom YAML rules.
# Example: extra_rules_dirs = ["./my-custom-rules"]
extra_rules_dirs = []
```

Or generate it interactively:

```bash
vibe-guard init
```

## Pre-commit hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ahmbt/vibe-guard
    rev: v0.1.0
    hooks:
      - id: vibe-guard
```

The pre-commit hook defaults to `--severity HIGH` (not MEDIUM) because pre-commit runs on every commit and MEDIUM would be too noisy for the development loop. Override in `.vibeguard.toml` if needed.

## How vibe-guard compares

| Tool | AI-aware | Pre-commit | GitHub Action | Languages | License |
|------|----------|------------|---------------|-----------|---------|
| **vibe-guard** | ✅ | ✅ | ✅ | Python, JS, TS | MIT |
| Semgrep CE | ❌ | ✅ | ✅ | 30+ | LGPL-2.1 |
| Bandit | ❌ | ✅ | ✅ | Python only | Apache-2.0 |
| detect-secrets | ❌ | ✅ | ❌ | Language-agnostic | Apache-2.0 |

vibe-guard is not a replacement for Semgrep or Bandit — it uses Semgrep under the hood. The difference is the AI detection layer: vibe-guard identifies which files were likely AI-generated and applies proportionally stricter scanning, with findings that explain the AI-specific root cause.

## Docker

For non-GitHub CI systems or local containerized scanning:

```bash
docker build -t vibe-guard:local .
docker run --rm -v "$(pwd):/scan" vibe-guard:local scan . --format terminal
```

## Contributing

Writing a new YAML security rule is the highest-impact contribution you can make — under 30 minutes, and it protects every project using vibe-guard. The `rules/` directory is where most contributions belong.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide: development setup, rule schema, detector tuning, and PR process.

## License

MIT. See [LICENSE](LICENSE) for full text.

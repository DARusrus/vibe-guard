<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&pause=1000&color=E74C3C&center=true&vCenter=true&width=600&lines=slopscan;AI-aware+security+scanner;Find+vulns+before+they+ship" alt="slopscan" />

<br/>

**45% of AI-generated code has security vulnerabilities.**
**slopscan is built for that.**

<br/>

[![PyPI version](https://img.shields.io/pypi/v/slopscan?style=for-the-badge&logo=pypi&logoColor=white&color=E74C3C)](https://pypi.org/project/slopscan/)
[![Python](https://img.shields.io/badge/python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![CI](https://img.shields.io/github/actions/workflow/status/DARusrus/slopscan/ci.yml?style=for-the-badge&logo=github-actions&logoColor=white&label=CI)](https://github.com/DARusrus/slopscan/actions)
[![Rules](https://img.shields.io/badge/rules-81-brightgreen?style=for-the-badge&logo=semgrep&logoColor=white)](https://github.com/DARusrus/slopscan/tree/main/rules)
[![Security Score](https://img.shields.io/badge/slopscan-B%20(85)-green?style=for-the-badge)](https://github.com/DARusrus/slopscan)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)

[![Languages](https://img.shields.io/badge/Python-3DDC84?style=flat-square&logo=python&logoColor=white)](rules/python/)
[![Languages](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)](rules/javascript/)
[![Languages](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)](rules/typescript/)
[![Languages](https://img.shields.io/badge/Shell-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)](rules/shell/)
[![Languages](https://img.shields.io/badge/Dockerfile-2496ED?style=flat-square&logo=docker&logoColor=white)](rules/dockerfile/)
[![Languages](https://img.shields.io/badge/Kubernetes-326CE5?style=flat-square&logo=kubernetes&logoColor=white)](rules/kubernetes/)
[![Languages](https://img.shields.io/badge/GitHub_Actions-2088FF?style=flat-square&logo=github-actions&logoColor=white)](rules/github-actions/)
[![Languages](https://img.shields.io/badge/SQL-336791?style=flat-square&logo=postgresql&logoColor=white)](rules/sql/)

</div>

---

## What is this?

AI coding tools ship code fast. They also ship SQL injection, hardcoded API keys, and SSRF at scale — and generic SAST tools were not designed for this.

**slopscan** detects AI-generated files first using three offline heuristics — comment patterns, structural regularity, and token fingerprints — then applies stricter scanning exactly where the risk is highest. It also detects slopsquatting (hallucinated package names that attackers pre-register), secrets in `.env` and MCP config files, and prompt injection strings in source code.

```bash
pip install slopscan
slopscan scan .
```

---


## How it works

```text
Your code
│
▼
┌─────────────────────────────┐
│      AI Code Detector       │  ← scores each file 0.0–1.0
│  comments · structure       │    using offline heuristics
│  tokens                     │    no network, no LLM calls
└─────────────────────────────┘
│
├── score ≥ 0.6   → FULL scan        (all rules)
├── score 0.3–0.6 → MEDIUM scan      (Tier 1 rules)
└── score < 0.3   → CRITICAL scan    (secrets + SQLi only)
│
▼
┌─────────────────────────────┐
│   81 security rules         │  ← targets AI-specific
│   Semgrep CE + plugins      │    vulnerability patterns
└─────────────────────────────┘
│
▼
Terminal · SARIF · JSON
```



---

## Install

```bash
pip install slopscan
```

Requires Python 3.10+. Semgrep and detect-secrets are installed automatically.

---

## Quick start

**Scan your project:**
```bash
slopscan scan .
```

**Scan only changed files (faster in CI):**
```bash
slopscan scan . --diff
```

**Get your security score and badge:**
```bash
slopscan score .
```

**AI-powered fix suggestions** (requires free [Gemini API key](https://ai.google.dev)):
```bash
export GEMINI_API_KEY=your-key-here
slopscan fix .
```

**Set up pre-commit + GitHub Action in 60 seconds:**
```bash
slopscan init
```

---

## GitHub Action

```yaml
- uses: DARusrus/slopscan@v1
```

Full configuration:

```yaml
name: slopscan security scan

on: [push, pull_request]

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

      - uses: DARusrus/slopscan@v1
        with:
          severity: medium           # minimum severity to report
          fail-on-findings: true     # exit 1 if findings exist
          ai-threshold: 0.6          # confidence threshold for AI detection
          upload-sarif: true         # show findings in GitHub Security tab
```

Findings appear inline on pull requests via the GitHub Security tab.

---

## Pre-commit hook

```yaml
repos:
  - repo: https://github.com/DARusrus/slopscan
    rev: v0.1.0
    hooks:
      - id: slopscan
```

---

## Security rules

81 rules across 8 languages. Every rule includes the specific reason AI models produce that pattern.

### Python — 41 rules

| Rule | What it catches |
|------|----------------|
| `sqli-fstring` | SQL injection via f-string or concatenation in `execute()` calls |
| `cmdi-shell-true` | Command injection via `subprocess.run(shell=True)` with user input |
| `path-traversal` | Path traversal via unsanitized `open()` or `send_file()` |
| `ssrf-user-url` | SSRF via `requests.get(user_input)` |
| `hardcoded-secret` | Hardcoded API keys, passwords, tokens in assignments |
| `insecure-deserialization` | `pickle.loads()`, `yaml.load()` without Loader, `eval()` on untrusted data |
| `jwt-verify-disabled` | JWT `verify=False` or `verify_signature: False` |
| `timing-unsafe-comparison` | Token comparison with `==` instead of `hmac.compare_digest()` |
| `mass-assignment` | `Model(**request.get_json())` without field filtering |
| `cors-wildcard` | `CORS(app, origins="*")` |
| `verbose-error-response` | `return jsonify({"error": str(e), "traceback": ...})` |
| `nosql-injection` | MongoDB `.find(request.json)` without field extraction |
| `log-injection` | User input interpolated directly into log statements |
| `xxe` | Unsafe XML parsing with `ElementTree`, `lxml`, `minidom` |
| `ssti` | `render_template_string(user_input)` — Jinja2 RCE |
| `open-redirect` | `redirect(request.args.get('next'))` without validation |
| `graphql-injection` | GraphQL query strings built with f-string interpolation |
| `weak-password-hash` | `hashlib.sha256(password)` — use bcrypt or argon2 |
| `ecb-mode` | `AES.new(key, AES.MODE_ECB)` — leaks data patterns |
| `pii-in-logs` | Email, phone, SSN interpolated into log statements |
| `insecure-random` | `random.randint()` for tokens, OTP codes, session IDs |
| `debug-mode` | `app.run(debug=True)` — Werkzeug RCE in browser |
| `missing-rate-limit` | Login/auth endpoints without rate limiting decorator |
| `weak-session-token` | `uuid.uuid4()` used as a security token |
| `token-in-url` | Reset tokens, API keys passed as URL query parameters |
| `zip-slip` | `zipfile.extractall()` without path validation |
| `crlf-injection` | User input in response headers without CRLF stripping |
| `race-condition-balance` | Balance check + deduction without database transaction |
| `idor` | CRUD routes using URL ID without ownership verification |
| `default-credentials` | Seed scripts with `password='admin123'` literals |
| `plaintext-sensitive-fields` | `Column(String)` for SSN, credit card, medical data |
| `missing-security-headers` | Flask/FastAPI without Talisman or CSP middleware |
| `html-injection` | HTML response built with f-string, missing `markupsafe.escape()` |
| `client-side-pricing` | Price calculations in React components sent to payment API |
| `missing-rls` | Supabase `CREATE TABLE` without `ENABLE ROW LEVEL SECURITY` |
| `insecure-chmod` | `os.chmod(file, 0o777)` in Python code |
| `redos` | Regex patterns with catastrophic backtracking |
| `xxe-lxml` | `lxml.etree.parse()` without `resolve_entities=False` |
| `weak-crypto-md5` | `hashlib.md5()` for any security-sensitive operation |
| `missing-https` | `app.run()` without SSL context on auth routes |
| `sensitive-url-param` | Tokens, passwords in URL query strings |

### JavaScript — 18 rules

| Rule | What it catches |
|------|----------------|
| `sqli-template-literal` | SQL built with template literals in `query()`, `execute()` |
| `xss-inner-html` | `element.innerHTML = userInput` without sanitization |
| `xss-dangerous-html` | `dangerouslySetInnerHTML` with unsanitized content |
| `hardcoded-secret` | `apiKey`, `password`, `token` string literals in JS |
| `eval-user-input` | `eval()`, `new Function()` on user-controlled strings |
| `prototype-pollution` | `obj["__proto__"]` assignment or unsafe recursive merge |
| `csrf-missing-token` | `fetch()` POST without CSRF token in headers |
| `nosql-injection` | Mongoose `.find(req.body)` without field extraction |
| `client-side-auth` | `isAdmin`, `isAuthenticated` in React state used for access control |
| `client-side-pricing` | Price calculations in React components |
| `log-injection` | User input interpolated into `console.log()` |
| `supabase-service-role` | `createClient(url, SERVICE_ROLE_KEY)` in browser-side code |
| `open-redirect` | `res.redirect(req.query.url)` without validation |
| `graphql-injection` | GraphQL query string built with template literals |
| `crlf-injection` | User input in response headers |
| `ecb-mode` | `createCipheriv('aes-256-ecb', ...)` |
| `pii-in-logs` | PII fields interpolated into console or logger calls |
| `missing-helmet` | Express app without `helmet()` middleware |

### TypeScript — 4 rules

| Rule | What it catches |
|------|----------------|
| `sqli-orm` | Raw SQL in TypeORM `.query()`, Prisma `$executeRawUnsafe()`, Drizzle |
| `type-assertion-bypass` | `as any` cast passed to security-sensitive functions |
| `client-side-auth` | Auth state in React/Next.js components controlling access |
| `missing-server-validation` | `use server` functions accepting FormData without Zod validation |

### Shell — 3 rules

| Rule | What it catches |
|------|----------------|
| `curl-pipe-bash` | `curl URL \| bash` — executes remote code without verification |
| `missing-errexit` | Shell scripts without `set -euo pipefail` |
| `chmod-777` | `chmod 777` in scripts and deployment code |

### Dockerfile — 2 rules

| Rule | What it catches |
|------|----------------|
| `missing-user` | Dockerfile with no `USER` instruction — runs as root |
| `curl-pipe-bash` | `RUN curl URL \| bash` in build steps |

### GitHub Actions — 2 rules

| Rule | What it catches |
|------|----------------|
| `secret-echo` | `echo "${{ secrets.* }}"` in workflow run steps |
| `unpinned-action` | `uses: action@v3` — use full commit SHA instead |

### Kubernetes — 1 rule

| Rule | What it catches |
|------|----------------|
| `rbac-cluster-admin` | `ClusterRoleBinding` granting `cluster-admin` to service accounts |

### SQL — 1 rule

| Rule | What it catches |
|------|----------------|
| `missing-rls` | `CREATE TABLE` in Supabase migrations without `ENABLE ROW LEVEL SECURITY` |

---

## Supply chain detection

slopscan also runs supply chain checks that go beyond Semgrep rules:

| Plugin | What it detects |
|--------|----------------|
| **Slopsquatting** | Package names in `requirements.txt` / `package.json` that AI models hallucinate — attackers pre-register these names with malicious code |
| **CVE scanning** | Known CVEs in AI-recommended packages via OSV.dev |
| **Unpinned deps** | Packages without version pins (`flask` instead of `flask==3.0.0`) |
| **Missing lock files** | `requirements.txt` present but no `poetry.lock` or `package-lock.json` |
| **.env secrets** | High-entropy credentials in `.env` files not excluded from git |
| **MCP config secrets** | API keys in `.claude/settings.json`, `.cursor/mcp.json`, and other agent config files |
| **Prompt injection strings** | Adversarial strings designed to manipulate LLM code reviewers |

---

## AI features

All AI features are optional and require a free [Gemini API key](https://ai.google.dev) (1,500 requests/day free). Everything works without a key — AI features degrade gracefully.

```bash
export GEMINI_API_KEY=your-key-here
```

| Feature | Command | What it does |
|---------|---------|-------------|
| Auto-fix | `slopscan fix .` | Generates a context-aware secure replacement for each finding, shows a diff, asks for confirmation before applying |
| Explain | `slopscan scan . --explain` | Adds a plain-English attack scenario to each finding — what an attacker can actually do with it |
| Smart filter | `slopscan scan . --smart-filter` | Uses AI to remove likely false positives from HIGH/CRITICAL findings before surfacing them |

---

## Configuration

Create `.Slopscan.toml` in your project root:

```toml
[slopscan]
min_severity = "MEDIUM"     # CRITICAL | HIGH | MEDIUM | LOW
ai_threshold = 0.6          # 0.0–1.0 — files above this get full scan
fail_on_findings = true     # exit 1 in CI when findings exist
smart_filter = false        # AI false positive reduction (needs GEMINI_API_KEY)
explain = false             # plain-English attack explanations
online_sca = false          # live registry checks for slopsquatting
min_score = 0               # fail CI if score drops below this

exclude_paths = [
    "node_modules", ".git", "__pycache__",
    "venv", ".venv", "dist", "tests/fixtures"
]
```

---

## Commands

slopscan scan [PATH]    Scan a directory or file
slopscan fix [PATH]     AI-powered fix suggestions (needs GEMINI_API_KEY)
slopscan score [PATH]   Security score + README badge
slopscan rules          List all 81 built-in rules
slopscan init           Interactive setup wizard

---

## How slopscan compares

| | slopscan | Semgrep CE | Bandit | detect-secrets |
|---|:---:|:---:|:---:|:---:|
| AI-aware detection | ✓ | ✗ | ✗ | ✗ |
| Supply chain / slopsquatting | ✓ | ✗ | ✗ | ✗ |
| MCP config scanning | ✓ | ✗ | ✗ | ✗ |
| Pre-commit hook | ✓ | ✓ | ✓ | ✓ |
| GitHub Action | ✓ | ✓ | ✗ | ✗ |
| SARIF + GitHub Security tab | ✓ | ✓ | ✗ | ✗ |
| Security score badge | ✓ | ✗ | ✗ | ✗ |
| AI auto-fix | ✓ | ✗ | ✗ | ✗ |
| License | MIT | LGPL-2.1 | MIT | Apache-2.0 |

---

## Contributing

Writing a YAML rule takes under 30 minutes and has the highest impact per hour of any contribution. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).


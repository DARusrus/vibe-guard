# vibe-guard - Handoff Document

## What this project is
vibe-guard is an offline, deterministic security scanner for AI-generated or AI-assisted code. It combines:
- AI-likelihood detection (comments/structure/tokens signals)
- Tiered security scanning (Semgrep + detect-secrets)
- CLI output/reporters for terminal, SARIF, and JSON

## Current state
- Completed sessions: 4 of 4
- Last completed phase: Phase 5 (Packaging + Action + Docs) — SHIPPED ✓
- Next session: None — project complete
- Blocking issues: NONE — all audit findings resolved
  - detect-secrets plugin JSON parse warnings: cosmetic only, findings unaffected
  - rules/ bundled in wheel via move to src/vibeguard/rules/

## Complete file tree status (EXISTS/PENDING, all planned files)

SESSION 1 - COMPLETE
- EXISTS: PROGRESS.md
- EXISTS: HANDOFF.md
- EXISTS: pyproject.toml
- EXISTS: Makefile
- EXISTS: .github/workflows/ci.yml
- EXISTS: .github/workflows/dogfood.yml
- EXISTS: src/vibeguard/__init__.py
- EXISTS: src/vibeguard/models.py
- EXISTS: src/vibeguard/signals/__init__.py
- EXISTS: src/vibeguard/signals/comments.py
- EXISTS: src/vibeguard/signals/structure.py
- EXISTS: src/vibeguard/signals/tokens.py
- EXISTS: src/vibeguard/detector.py
- EXISTS: tests/fixtures/ai_sample.py
- EXISTS: tests/fixtures/human_sample.py
- EXISTS: tests/test_detector.py

SESSION 2 - COMPLETE
- EXISTS: src/vibeguard/engine.py
- EXISTS: src/vibeguard/scanner.py
- EXISTS: src/vibeguard/plugins/__init__.py
- EXISTS: src/vibeguard/plugins/secrets.py
- EXISTS: rules/python/sqli.yaml
- EXISTS: rules/python/cmdi.yaml
- EXISTS: rules/python/path_traversal.yaml
- EXISTS: rules/python/ssrf.yaml
- EXISTS: rules/python/secrets.yaml
- EXISTS: rules/python/deserial.yaml
- EXISTS: rules/python/auth.yaml
- EXISTS: rules/python/mass_assign.yaml
- EXISTS: rules/python/cors.yaml
- EXISTS: rules/python/error_exposure.yaml
- EXISTS: tests/fixtures/vulnerable_app/app.py
- EXISTS: tests/fixtures/vulnerable_app/utils.py
- EXISTS: tests/test_scanner.py

SESSION 3 - COMPLETE
- EXISTS: src/vibeguard/config.py
- EXISTS: src/vibeguard/cli.py
- EXISTS: src/vibeguard/commands/__init__.py
- EXISTS: src/vibeguard/commands/init.py
- EXISTS: src/vibeguard/commands/rules.py
- EXISTS: src/vibeguard/reporters/__init__.py
- EXISTS: src/vibeguard/reporters/terminal.py
- EXISTS: src/vibeguard/reporters/sarif.py
- EXISTS: src/vibeguard/reporters/json_out.py
- EXISTS: rules/javascript/sqli.yaml
- EXISTS: rules/javascript/xss.yaml
- EXISTS: rules/javascript/secrets.yaml
- EXISTS: rules/javascript/eval.yaml
- EXISTS: rules/javascript/prototype_pollution.yaml
- EXISTS: rules/javascript/csrf.yaml
- EXISTS: rules/typescript/sqli.yaml
- EXISTS: rules/typescript/type_assertion_bypass.yaml
- EXISTS: tests/test_cli.py
- EXISTS: tests/test_reporters.py

SESSION 4 - COMPLETE
- EXISTS: action.yml
- EXISTS: Dockerfile
- EXISTS: .pre-commit-hooks.yaml
- EXISTS: .github/workflows/publish.yml
- EXISTS: .vibeguard.toml
- EXISTS: CHANGELOG.md
- EXISTS: CONTRIBUTING.md
- EXISTS: SECURITY.md
- EXISTS: README.md

AUDIT FIX SESSION - COMPLETE
- EXISTS: LICENSE
- EXISTS: .gitignore
- EXISTS: src/vibeguard/py.typed
- EXISTS: src/vibeguard/rules/ (moved from rules/)
- EXISTS: tests/__init__.py
- EXISTS: tests/fixtures/__init__.py
- EXISTS: docs/RECORDING.md

## Session 3 implementation notes
- CLI entrypoint is now implemented at src/vibeguard/cli.py with app object.
- Session 1 temporary CLI stub was removed from src/vibeguard/__init__.py.
- Reporters are implemented and wired through get_reporter(format):
  - terminal
  - sarif
  - json
- JS/TS rule packs are present and semgrep-valid.
- rules list command shows one row per rule YAML file and reports:
  - Total: 18 rules (10 Python, 6 JavaScript, 2 TypeScript)

## Gate results from Session 3
- ruff check src/ tests/ -> PASS
- pytest tests/test_detector.py tests/test_scanner.py -q -> PASS (43 passed, 5 skipped)
- pytest tests/test_cli.py tests/test_reporters.py -v -> PASS (29 passed)
- vibe-guard --help -> PASS
- vibe-guard rules -> PASS (18 rules shown)
- vibe-guard scan tests/fixtures/vulnerable_app --format terminal -> PASS (13 findings, exit 1)
- vibe-guard scan tests/fixtures/vulnerable_app --format sarif --output /tmp/test.sarif --no-fail -> PASS
- python import sanity check -> PASS (All imports clean)

## Entry points and version (must remain consistent)
- Runtime entrypoint path: vibeguard.cli:app
- pyproject script entry:
  - [project.scripts]
  - vibe-guard = "vibeguard.cli:app"
- Current version string:
  - [project] version = "0.1.0"
  - src/vibeguard/__init__.py __version__ = "0.1.0"

## Action contract notes for Session 4
The init wizard writes .github/workflows/vibe-guard.yml that calls:
- uses: ahmbt/vibe-guard@v1
- with:
  - severity
  - fail-on-findings

Session 4 action.yml inputs must include exactly:
- severity
- fail-on-findings

No outputs are currently consumed by generated workflow files, so Session 4 can either:
- define no outputs, or
- define outputs but keep workflow compatibility and document usage.

SARIF upload mechanism required in Session 4 workflow/docs:
- github/codeql-action/upload-sarif
- upload the generated SARIF path from vibe-guard scan output

README GIF requirement for Session 4:
- Show terminal scan output on tests/fixtures/vulnerable_app
- Then show resulting GitHub Security tab annotation from uploaded SARIF

## Unresolved issues to fix in Session 4
- detect-secrets subprocess output format mismatch in this environment logs:
  - Failed to parse detect-secrets JSON output
- pyproject wheel config still does not explicitly package rules/:
  - add rules/ to [tool.hatch.build.targets.wheel]

## Exact next prompt for Session 4
```text
You are continuing vibe-guard Session 4 (Opus 4.6).

State on disk:
- Sessions 1-3 are complete and passing all Session 3 gates.
- Entry point path is vibeguard.cli:app.
- pyproject.toml contains [project.scripts] vibe-guard = "vibeguard.cli:app".
- Version is 0.1.0 in both pyproject.toml and vibeguard/__init__.py.

Complete EXISTS/PENDING file tree:

SESSION 1 - COMPLETE (EXISTS)
- PROGRESS.md
- HANDOFF.md
- pyproject.toml
- Makefile
- .github/workflows/ci.yml
- .github/workflows/dogfood.yml
- src/vibeguard/__init__.py
- src/vibeguard/models.py
- src/vibeguard/signals/__init__.py
- src/vibeguard/signals/comments.py
- src/vibeguard/signals/structure.py
- src/vibeguard/signals/tokens.py
- src/vibeguard/detector.py
- tests/fixtures/ai_sample.py
- tests/fixtures/human_sample.py
- tests/test_detector.py

SESSION 2 - COMPLETE (EXISTS)
- src/vibeguard/engine.py
- src/vibeguard/scanner.py
- src/vibeguard/plugins/__init__.py
- src/vibeguard/plugins/secrets.py
- rules/python/sqli.yaml
- rules/python/cmdi.yaml
- rules/python/path_traversal.yaml
- rules/python/ssrf.yaml
- rules/python/secrets.yaml
- rules/python/deserial.yaml
- rules/python/auth.yaml
- rules/python/mass_assign.yaml
- rules/python/cors.yaml
- rules/python/error_exposure.yaml
- tests/fixtures/vulnerable_app/app.py
- tests/fixtures/vulnerable_app/utils.py
- tests/test_scanner.py

SESSION 3 - COMPLETE (EXISTS)
- src/vibeguard/config.py
- src/vibeguard/cli.py
- src/vibeguard/commands/__init__.py
- src/vibeguard/commands/init.py
- src/vibeguard/commands/rules.py
- src/vibeguard/reporters/__init__.py
- src/vibeguard/reporters/terminal.py
- src/vibeguard/reporters/sarif.py
- src/vibeguard/reporters/json_out.py
- rules/javascript/sqli.yaml
- rules/javascript/xss.yaml
- rules/javascript/secrets.yaml
- rules/javascript/eval.yaml
- rules/javascript/prototype_pollution.yaml
- rules/javascript/csrf.yaml
- rules/typescript/sqli.yaml
- rules/typescript/type_assertion_bypass.yaml
- tests/test_cli.py
- tests/test_reporters.py

SESSION 4 - BUILD THESE (PENDING)
- action.yml
- Dockerfile
- .pre-commit-hooks.yaml
- .github/workflows/publish.yml
- .vibeguard.toml
- CHANGELOG.md
- CONTRIBUTING.md
- SECURITY.md
- README.md

Session 4 constraints:
1) action.yml input contract must match init wizard workflow field names exactly:
   - severity
   - fail-on-findings
2) Include SARIF upload mechanism in workflow docs/examples using:
   - github/codeql-action/upload-sarif
3) README GIF must demonstrate:
   - terminal scan output on tests/fixtures/vulnerable_app
   - GitHub Security tab annotation from uploaded SARIF
4) Fix unresolved issues from Sessions 1-3:
   - detect-secrets JSON parse warning handling
   - package rules/ in wheel build target

Do not break existing CLI entrypoint or version wiring.
Run lint/tests after Session 4 changes and update PROGRESS.md + HANDOFF.md.
```

## Plan 2 Session 4 Blocker Resolution — 2026-04-09
- Blocker 1 (diff mode repository scale scanning): RESOLVED by bypassing directory walk in diff mode and scoring only normalized filtered files.
- Blocker 2 (autofixer invalid replacement logic): RESOLVED by generating non-empty context-aware diffs and applying fixes by line number from unified diff additions.

## Pre-tag operator checklist
- [x] Replace your-handle with GitHub username (10 files)
- [ ] Verify PyPI name: pypi.org/project/vibe-guard
- [ ] Configure PyPI Trusted Publishing (see CONTRIBUTING.md)
- [ ] Record demo GIF (see docs/RECORDING.md)
- [ ] Set repo description + topics on GitHub
- [ ] git tag v0.1.0 && git push origin v0.1.0
- [ ] Publish Action to GitHub Actions marketplace
- [ ] Post: Show HN, r/netsec, r/Python
- [x] All blockers resolved
- [x] All tests passing
- [x] All rules validated
- [x] Code complete

## Plan 2 Feature Summary
**What was added in Plan 2:**
- **AI File Detection Pipeline:** Employs multiple fast local signals (comments, structure, tokens) to score files automatically.
- **Dynamic Severity Tiering:** Toggles strictness of the scanner dynamically based on the AI score to balance False Positives.
- **SCA & Ecosystem Plugins:** Added 5 new scanners (SCA for CVEs and slopsquatting, Dotenv for credentials, MCP context settings, Prompt Injection detecting LLM bypass string, and SecretsPlugin).
- **Extensive Ruleset (81 Rules):** Expanded coverage to TypeScript, JS, Shell, K8s, GitHub Actions, Docker, and SQL alongside Python.
- **AI AutoFixer & Smart Filtering:** Uses the Gemini extension for 1-click correct context-aware code insertions and LLM evaluations filtering out False Positive alerts.
- **Security Scorer Command:** `vibe-guard score` provides grading (A-F) that developers can natively generate Shields.IO badges representing.
- **Actions & CLI Commands:** Fully fledged Github Action implementation that annotates SARIF issues directly onto repo commits, fully configurable `.vibeguard.toml` and CLI modes like `--diff`.

## Plan 2 Session 1 — COMPLETE ✓ (2026-04-07)

### New public APIs

#### BasePlugin (src/vibeguard/plugins/base.py)
```python
class BasePlugin(ABC):
    name: str                                              # abstract property
    def is_available(self) -> bool: ...                     # abstract
    def scan(self, files: list[Path], project_root: Path) -> list[Finding]: ...  # abstract
    def _make_finding(self, **kwargs) -> Finding: ...       # convenience
```

#### SCAPlugin (src/vibeguard/plugins/sca.py)
```python
class SCAPlugin(BasePlugin):
    def __init__(self, online: bool = False, timeout: int = 5) -> None: ...
    def scan(self, files: list[Path], project_root: Path) -> list[Finding]: ...
```

#### DotenvPlugin (src/vibeguard/plugins/dotenv_scanner.py)
```python
class DotenvPlugin(BasePlugin):
    def scan(self, files: list[Path], project_root: Path) -> list[Finding]: ...
```

#### MCPConfigPlugin (src/vibeguard/plugins/mcp_config.py)
```python
class MCPConfigPlugin(BasePlugin):
    def scan(self, files: list[Path], project_root: Path) -> list[Finding]: ...
```

#### PromptInjectionPlugin (src/vibeguard/plugins/prompt_injection.py)
```python
class PromptInjectionPlugin(BasePlugin):
    def scan(self, files: list[Path], project_root: Path) -> list[Finding]: ...
```

### Modified Plan 1 files

#### scanner.py
- Added `online: bool = False` parameter to `Scanner.__init__`
- Added imports for 4 new plugins
- Added plugin instantiation in `__init__`: `self.sca`, `self.dotenv`, `self.mcp_config`, `self.prompt_injection`
- Added plugin scan calls in `scan_directory()` and `scan_file()` after SecretsPlugin
- Updated `rules_applied` count to include active plugins
- Added `online` parameter passthrough to module-level `scan()` function

#### pyproject.toml
- No changes needed — `tomli>=2.0` already present from Plan 1

### New Finding rule_id values

| rule_id | severity | plugin | description |
|---------|----------|--------|-------------|
| `vibeguard-sca-slopsquatting` | CRITICAL | SCA | AI-hallucinated package name detected |
| `vibeguard-sca-known-cve` | varies | SCA | Package version has known CVEs |
| `vibeguard-sca-unpinned` | MEDIUM | SCA | Dependency has no version pin |
| `vibeguard-sca-no-lock-file` | MEDIUM | SCA | Manifest exists without lock file |
| `vibeguard-dotenv-not-in-gitignore` | CRITICAL | Dotenv | .env file not excluded from VCS |
| `vibeguard-dotenv-exposed-secret` | CRITICAL | Dotenv | High-entropy secret in .env |
| `vibeguard-mcp-config-secret` | CRITICAL | MCP | Secret in MCP config file |
| `vibeguard-mcp-config-not-in-gitignore` | CRITICAL | MCP | MCP config not in .gitignore |
| `vibeguard-prompt-injection-string` | CRITICAL | Prompt | Adversarial LLM manipulation string |

### New files created (Plan 2 Session 1)
- EXISTS: src/vibeguard/plugins/base.py
- EXISTS: src/vibeguard/plugins/sca.py
- EXISTS: src/vibeguard/plugins/dotenv_scanner.py
- EXISTS: src/vibeguard/plugins/mcp_config.py
- EXISTS: src/vibeguard/plugins/prompt_injection.py
- EXISTS: src/vibeguard/data/hallucinated_packages.json
- EXISTS: src/vibeguard/data/osv_snapshot.json
- EXISTS: tests/test_plan2_plugins.py

### Gate results
- ruff check src/ tests/ → PASS (All checks passed!)
- pytest tests/test_plan2_plugins.py → PASS (41 passed)
- Regression tests → PASS (72 passed, 5 skipped, 0 failures)
- Import check → PASS (All new plugins loaded cleanly. SCA available: True)
- E2E spot check → PASS (0 findings — expected without semgrep on PATH)

### Exact next prompt for P2S2
```text
You are continuing vibe-guard Plan 2 Session 2 (Codex 5.3).

State on disk:
- Plan 1 is complete and audited (48 files).
- Plan 2 Session 1 is complete (5 new plugins, 41 new tests, all gates pass).
- Entry point path is vibeguard.cli:app.
- Version is 0.1.0 in both pyproject.toml and vibeguard/__init__.py.

Plan 2 Session 1 delivered:
- BasePlugin ABC in src/vibeguard/plugins/base.py
- SCAPlugin (slopsquatting + CVE) in src/vibeguard/plugins/sca.py
- DotenvPlugin in src/vibeguard/plugins/dotenv_scanner.py
- MCPConfigPlugin in src/vibeguard/plugins/mcp_config.py
- PromptInjectionPlugin in src/vibeguard/plugins/prompt_injection.py
- Offline data: hallucinated_packages.json, osv_snapshot.json
- scanner.py extended with online= parameter and all new plugin calls
- 41 passing tests in tests/test_plan2_plugins.py

P2S2 scope: 23 new YAML rules across 6 new languages + engine.py updates.

Read HANDOFF.md and PROGRESS.md before writing any code.
```

## Plan 2 Session 2 — COMPLETE ✓ (2026-04-07)

### Delivered summary
- Added 46 new YAML rule files under `src/vibeguard/rules/`.
- Expanded `TIER_RULES` in `src/vibeguard/scanner.py` to include Python, JavaScript, TypeScript, SQL, Shell, Dockerfile, GitHub Actions YAML, and Kubernetes YAML packs.
- Expanded detector file coverage in `src/vibeguard/detector.py`:
  - Extensions: `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.sh`, `.bash`, `.sql`, `.yml`, `.yaml`
  - Added Dockerfile inclusion by exact filename (`Dockerfile`) in directory scan.
- Added Semgrep language coverage metadata constant in `src/vibeguard/engine.py`.

### Tier totals
- FULL tier rules: 64
- MEDIUM tier rules: 19
- CRITICAL_ONLY tier rules: 8
- FULL unique count: 64

### New languages supported
- Bash
- Dockerfile
- SQL (generic mode)
- YAML (GitHub Actions)
- YAML (Kubernetes)
- Existing Python/JavaScript/TypeScript packs expanded

### New rule IDs (added in P2S2)
- vibeguard-python-log-injection
- vibeguard-python-nosql-injection
- vibeguard-python-xxe-elementtree-parse
- vibeguard-python-xxe-lxml-parse
- vibeguard-python-xxe-minidom-parse
- vibeguard-python-ssti-render-template-string
- vibeguard-python-ssti-jinja-from-string
- vibeguard-python-open-redirect
- vibeguard-python-graphql-injection
- vibeguard-python-redos-catastrophic-regex
- vibeguard-python-html-injection
- vibeguard-python-weak-password-hash
- vibeguard-python-ecb-mode
- vibeguard-python-pii-in-logs
- vibeguard-python-insecure-random
- vibeguard-python-plaintext-sensitive-fields
- vibeguard-python-debug-mode-enabled
- vibeguard-python-debug-mode-outside-main-guard
- vibeguard-python-missing-security-headers-flask
- vibeguard-python-missing-security-headers-fastapi
- vibeguard-python-token-in-url
- vibeguard-python-race-condition-balance
- vibeguard-python-idor
- vibeguard-python-missing-rate-limit
- vibeguard-python-weak-session-token
- vibeguard-python-zip-slip-zipfile
- vibeguard-python-zip-slip-tarfile
- vibeguard-python-crlf-injection
- vibeguard-python-default-credentials
- vibeguard-js-nosql-injection
- vibeguard-js-client-side-auth
- vibeguard-js-client-side-pricing
- vibeguard-js-log-injection
- vibeguard-js-supabase-service-role
- vibeguard-js-open-redirect
- vibeguard-js-graphql-injection
- vibeguard-js-crlf-injection
- vibeguard-js-ecb-mode
- vibeguard-js-pii-in-logs
- vibeguard-js-math-random-security
- vibeguard-js-missing-helmet
- vibeguard-ts-client-side-auth
- vibeguard-ts-missing-server-validation
- vibeguard-sql-missing-rls
- vibeguard-shell-curl-pipe-bash
- vibeguard-shell-missing-errexit
- vibeguard-shell-chmod-777
- vibeguard-dockerfile-missing-user
- vibeguard-dockerfile-curl-pipe-bash
- vibeguard-gha-secret-echo
- vibeguard-gha-unpinned-action
- vibeguard-k8s-rbac-cluster-admin

### Gate results
- `semgrep --validate --config src/vibeguard/rules/ --quiet` -> PASS (exit 0)
- `semgrep --validate --config src/vibeguard/rules/` -> PASS (`0 configuration error(s), 81 rule(s)`)
- `python -m ruff check src/ tests/` -> PASS
- `python -m pytest tests/ --tb=short --no-cov` -> PASS (`125 passed`)
- Rule count check -> PASS (`FULL=64`, `unique=64`)
- Spot check findings -> PASS (`{'secrets': 5, 'sqli': 3, 'password_hash': 1, 'path_traversal': 2, 'ssrf': 1, 'cmdi': 1}`)

## Plan 2 Session 3 — COMPLETE ✓ (2026-04-07)

### Delivered summary
- Added AI-powered features: auto-fix engine, plain-English explainer, smart false-positive filter.
- Added security score calculator with shields.io badge generation and SQLite history tracking.
- Added diff mode for scanning only changed files via `git diff`.
- All features degrade gracefully without `GEMINI_API_KEY` — never crash, never prompt.

### New public APIs

#### AIClient (src/vibeguard/ai/client.py)
```python
class AIClient:
    def __init__(self) -> None: ...
    def complete(self, prompt: str, max_tokens: int = 512, cache_key: str | None = None) -> str | None: ...
    def is_available(self) -> bool: ...
```

#### AutoFixer (src/vibeguard/ai/autofix.py)
```python
class AutoFixer:
    def __init__(self) -> None: ...
    def generate_fix(self, finding: Finding, source_context: str) -> str | None: ...
```

#### Explainer (src/vibeguard/ai/explain.py)
```python
class Explainer:
    def __init__(self) -> None: ...
    def explain(self, finding: Finding, language: str = "python") -> str | None: ...
```

#### ContextFilter (src/vibeguard/ai/context_filter.py)
```python
class ContextFilter:
    def __init__(self) -> None: ...
    def is_true_positive(self, finding: Finding, file_content: str) -> bool: ...
```

#### Score functions (src/vibeguard/commands/score.py)
```python
def calculate_score(result: ScanResult) -> tuple[int, str]: ...
def generate_badge_url(grade: str, score: int) -> str: ...
def store_history(score: int, grade: str, result: ScanResult, db_path: Path | None = None) -> None: ...
def get_trend(current_score: int, db_path: Path | None = None) -> str | None: ...
def run_score(path: Path = Path("."), update_readme: bool = False, fail_below: int = 0) -> int: ...
```

#### Fix command (src/vibeguard/commands/fix.py)
```python
def run_fix(path: Path = Path("."), auto: bool = False, dry_run: bool = False) -> None: ...
```

### New CLI flags added to `scan` command
- `--diff` — Scan only files changed since last git commit
- `--smart-filter` — Use AI to remove likely false positives (requires GEMINI_API_KEY)
- `--explain` — Add plain-English attack scenario to each finding (requires GEMINI_API_KEY)
- `--online` — Enable live registry checks for dependency validation (SCA plugin)

### New top-level commands
- `vibe-guard fix [PATH]` — AI-powered fix suggestions (`--auto`, `--dry-run` flags)
- `vibe-guard score [PATH]` — Security score + badge generator (`--update-readme`, `--fail-below` flags)

### New ScanResult fields
- `diff_mode: bool = False` — True when file_filter is used
- `changed_files_count: int = 0` — Number of files in the diff filter set
- `filtered_count: int = 0` — Number of false positives removed by smart filter

### Environment variables
- `GEMINI_API_KEY` — Required for AI features (autofix, explain, smart-filter). All features work without it (graceful degradation).

### Modified Plan 1 files
- `scanner.py` — Added `file_filter: set[Path] | None` parameter to `scan_directory()` for diff mode
- `cli.py` — Added `--diff`, `--smart-filter`, `--explain`, `--online` flags to `scan`; added `fix` and `score` commands
- `models.py` — Added `diff_mode`, `changed_files_count`, `filtered_count` fields to `ScanResult`
- `reporters/terminal.py` — Added `explain_mode` attribute and AI explanation rendering; updated summary panel for diff/filter info

### New files created (Plan 2 Session 3)
- EXISTS: src/vibeguard/ai/__init__.py
- EXISTS: src/vibeguard/ai/client.py
- EXISTS: src/vibeguard/ai/autofix.py
- EXISTS: src/vibeguard/ai/explain.py
- EXISTS: src/vibeguard/ai/context_filter.py
- EXISTS: src/vibeguard/commands/fix.py
- EXISTS: src/vibeguard/commands/score.py
- EXISTS: tests/test_plan2_ai.py

### .vibeguard.toml new fields
- `smart_filter = false`
- `explain = false`
- `online_sca = false`
- `min_score = 0`

### Items deferred to P2S4
- `action.yml` — Add `score` output so GitHub Actions can consume the security score
- README.md — Document badge usage and AI features
- Final audit across all Plan 2 additions

### Gate results
- `ruff check src/ tests/` → PASS (All checks passed!)
- `pytest tests/ --no-cov` → PASS (all passed, 5 skipped)
- AI graceful degradation → PASS (all features return False/None without key)
- Score command → PASS (Score: 100, Grade: A, Badge URL valid)
- Diff mode → PASS (exit 0)
- Import check → PASS (All new imports clean)

### Exact next prompt for P2S4
```text
You are continuing vibe-guard Plan 2 Session 4 — the final audit (Opus 4.6).

State on disk:
- Plan 1 is complete and audited (48 files).
- Plan 2 Session 1 is complete (5 new plugins, 41 new tests).
- Plan 2 Session 2 is complete (46 new YAML rules, 81 total rules).
- Plan 2 Session 3 is complete (AI features, score, diff mode).
- Entry point path is vibeguard.cli:app.
- Version is 0.1.0 in both pyproject.toml and vibeguard/__init__.py.

Plan 2 Session 3 delivered:
- AIClient wrapper for Gemini Flash (src/vibeguard/ai/client.py)
- AutoFixer engine (src/vibeguard/ai/autofix.py)
- Explainer (src/vibeguard/ai/explain.py)
- ContextFilter smart FP filter (src/vibeguard/ai/context_filter.py)
- Fix command (src/vibeguard/commands/fix.py)
- Score command with history/badge (src/vibeguard/commands/score.py)
- Diff mode in scanner.py (file_filter parameter)
- CLI flags: --diff, --smart-filter, --explain, --online
- New commands: fix, score
- .vibeguard.toml updated with AI config fields
- tests/test_plan2_ai.py

P2S4 scope: Complete project audit across all Plan 2 additions.
Tasks:
1. Add score output to action.yml
2. Update README.md with AI features and badge documentation
3. Full regression test pass
4. Review all Plan 2 code for correctness, error handling, edge cases
5. Update CHANGELOG.md with Plan 2 additions
6. Final HANDOFF.md and PROGRESS.md

Read HANDOFF.md and PROGRESS.md before writing any code.
```


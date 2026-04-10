# Contributing to vibe-guard

Every contribution makes AI-generated code safer. Whether you write a rule, improve the detector, or fix a typo — thank you.

## The fastest way to contribute

- **Write a new YAML rule.** Pick a vulnerability pattern AI models produce, write a Semgrep rule, and add a test fixture. Start to finish in under 30 minutes. See [Writing a new security rule](#writing-a-new-security-rule) below.
- **Improve a detector signal weight.** Run the detector on real AI-generated code, find where it under- or over-scores, and adjust weights in `src/vibeguard/detector.py`. See [Improving the AI detector](#improving-the-ai-detector).
- **Add a test fixture.** Drop a real-world vulnerable code sample into `tests/fixtures/` and verify the scanner catches it. Every fixture makes the test suite stronger.

## Development setup

From zero to running tests in four commands:

```bash
git clone https://github.com/ahmbt/vibe-guard.git
cd vibe-guard
pip install -e ".[dev]"
pre-commit install
```

Verify everything works:

```bash
pytest
vibe-guard scan .
```

You need Python 3.10+ and [Semgrep CE](https://semgrep.dev/) installed for integration tests. Unit tests run without Semgrep.

## Project structure

```
src/vibeguard/
├── __init__.py          # Package version
├── cli.py               # Typer CLI entrypoint
├── config.py            # .vibeguard.toml loader
├── detector.py          # AI code detector (aggregates signals)
├── engine.py            # Semgrep subprocess wrapper
├── scanner.py           # Scan orchestrator (detector → engine → findings)
├── models.py            # Finding, ScanResult, DetectorResult dataclasses
├── signals/             # Three heuristic signals for AI detection
│   ├── comments.py      # Comment pattern analysis
│   ├── structure.py     # Structural regularity scoring
│   └── tokens.py        # Token fingerprint matching
├── plugins/
│   └── secrets.py       # detect-secrets integration
├── commands/
│   ├── init.py          # Interactive setup wizard
│   └── rules.py         # Rule listing command
└── reporters/
    ├── terminal.py      # Rich colored terminal output
    ├── sarif.py         # SARIF 2.1.0 for GitHub Security tab
    └── json_out.py      # Machine-readable JSON

rules/                   # Semgrep YAML rules (the most important directory)
├── python/              # 10 rules: sqli, cmdi, ssrf, secrets, etc.
├── javascript/          # 6 rules: sqli, xss, eval, secrets, etc.
└── typescript/          # 2 rules: sqli, type_assertion_bypass

tests/
├── fixtures/            # Sample code for detector and scanner tests
├── test_detector.py     # AI detector unit tests
├── test_scanner.py      # Scanner integration tests
├── test_cli.py          # CLI command tests
└── test_reporters.py    # Output format tests
```

## Writing a new security rule

Rules are Semgrep YAML files in the `rules/` directory, organized by language.

### Annotated example

```yaml
rules:
  - id: vibeguard-python-sqli-fstring
    languages: [python]
    severity: ERROR                    # Semgrep severity: ERROR, WARNING, INFO
    message: >
      SQL injection via string interpolation in execute() call.
      User-controlled input is directly embedded into the SQL query string.
    metadata:
      cwe: "CWE-89: Improper Neutralization of Special Elements in SQL Command"
      category: security
      confidence: HIGH
      fix_guidance: >
        Use parameterized queries instead of string interpolation.
        Replace cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        with cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
      ai_context: >                    # ← This is what makes vibe-guard unique
        AI models default to f-strings for SQL queries because training
        examples prioritize readability over security, producing vulnerable
        code that looks clean and idiomatic.
      severity_label: "CRITICAL"       # Display severity: CRITICAL, HIGH, MEDIUM, LOW
      rule_category: "sqli"            # Category for grouping in reports
    pattern-either:
      - pattern: $CURSOR.execute(f"...", ...)
      - pattern: $CURSOR.execute("..." % ..., ...)
```

### Key fields

- **`ai_context`** — Explain *why AI specifically produces this pattern*. Not just "this is bad" — explain the training data bias or generation shortcut that causes it. This appears in terminal output and SARIF reports.
- **`severity_label`** — The severity shown to users. Use `CRITICAL` for RCE/data exfil, `HIGH` for injection/auth bypass, `MEDIUM` for config issues, `LOW` for best practices.
- **`rule_category`** — Short category name used for grouping (`sqli`, `secrets`, `xss`, etc.).

### Testing your rule

1. Create a fixture file with vulnerable code in `tests/fixtures/`:

```python
# tests/fixtures/my_vuln_sample.py
def bad_function(user_input):
    cursor.execute(f"DELETE FROM users WHERE id = {user_input}")
```

2. Validate the rule syntax:

```bash
semgrep --validate --config rules/
```

3. Run the scanner against your fixture:

```bash
vibe-guard scan tests/fixtures/my_vuln_sample.py --format terminal --no-fail
```

4. Add assertions to a test file if the pattern is complex.

## Improving the AI detector

The detector combines three signals to score each file 0.0–1.0:

| Signal | File | What it measures |
|--------|------|-----------------|
| Comments | `signals/comments.py` | Google-style docstrings, `# AI-generated` markers, uniform comment density |
| Structure | `signals/structure.py` | Function length uniformity, consistent return patterns, regular spacing |
| Tokens | `signals/tokens.py` | Textbook variable names, bare `except`, `isinstance` guard frequency |

Each signal returns a float 0.0–1.0. The detector in `detector.py` combines them with weighted averaging to produce a final confidence score.

### Adding a new signal

1. Create `src/vibeguard/signals/mysignal.py` with a function that takes file content and returns a float 0.0–1.0.
2. Register it in `src/vibeguard/signals/__init__.py`.
3. Add the weight in `src/vibeguard/detector.py`.
4. Test against the fixture files:
   - `tests/fixtures/ai_sample.py` should score **high** (≥ 0.6)
   - `tests/fixtures/human_sample.py` should score **low** (< 0.4)

### Calibration targets

When tuning weights or adding signals:
- AI fixture: confidence ≥ 0.6 (should trigger FULL scan tier)
- Human fixture: confidence < 0.4 (should trigger CRITICAL_ONLY tier)
- The gap between them should be as wide as possible

## Running the test suite

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_detector.py

# Run with coverage report
pytest --cov=vibeguard --cov-report=html
```

**Integration tests** (in `test_scanner.py`) require Semgrep to be installed. They are automatically skipped if Semgrep is not available. Unit tests always run.

## Submitting a pull request

### Branch naming

Use a prefix that describes the change type:

- `feat/` — New feature or rule
- `fix/` — Bug fix
- `rule/` — New or improved security rule
- `docs/` — Documentation only
- `test/` — Test additions or fixes

Example: `rule/python-jwt-algorithm-none`

### PR title format

```
feat: add JWT algorithm none detection rule
fix: false positive in CORS wildcard rule for localhost
rule: python insecure random for cryptographic use
```

### What CI checks

Every PR runs:
1. `ruff check src/ tests/` — must produce zero errors
2. `pytest --tb=short -q` — all tests must pass
3. `vibe-guard scan .` — dogfood scan (via `dogfood.yml`)

### What reviewers look for

- Rules have `ai_context` that explains the AI-specific angle
- Rules have a test fixture that demonstrates the vulnerability
- Code has type annotations on all public functions
- Code has docstrings on all public functions

## PyPI release process (maintainers only)

### Publishing a new version

1. Bump the version in `src/vibeguard/__init__.py`:

```python
__version__ = "0.2.0"
```

2. Update `pyproject.toml` version to match:

```toml
version = "0.2.0"
```

3. Add a changelog entry in `CHANGELOG.md`:

```markdown
## [0.2.0] — 2026-XX-XX

### Added
- ...
```

4. Commit and tag:

```bash
git add -A
git commit -m "release: v0.2.0"
git tag v0.2.0
git push origin main --tags
```

5. The `publish.yml` workflow handles the rest — builds the package, publishes to PyPI, and creates a GitHub Release with the changelog entry.

### Setting up PyPI Trusted Publishing (one-time)

Before the first tag push, configure PyPI to trust your GitHub Actions workflow:

1. Go to [pypi.org](https://pypi.org) → your project → **Publishing** → **Add a new publisher**
2. Select **GitHub Actions**
3. Fill in:
   - **Repository owner:** ahmbt
   - **Repository name:** vibe-guard
   - **Workflow name:** `publish.yml`
   - **Environment name:** `pypi`
4. Save. No API tokens needed — OIDC handles authentication.

This must be done once before the first `git push origin v0.1.0`.

## Code style

All code must pass `ruff check src/ tests/` with zero errors.

Required conventions:

- `from __future__ import annotations` at the top of every Python file
- Type annotations on all public functions
- Docstrings on all public functions
- Import sorting via `ruff` (isort-compatible)
- Line length: 100 characters (configured in `pyproject.toml`)

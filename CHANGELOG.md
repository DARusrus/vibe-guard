# Changelog

All notable changes to vibe-guard are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-04-04

### Added
- AI code detector with three offline heuristic signals (comment patterns,
  structural regularity, token fingerprints) producing a 0.0–1.0 confidence
  score per file
- Tiered scanning: files above the AI threshold receive the full 10-rule
  scan; files below receive a proportionally lighter rule set
- 10 Python security rules covering SQL injection, command injection,
  path traversal, SSRF, hardcoded secrets, insecure deserialization,
  broken authentication, mass assignment, permissive CORS, and verbose
  error exposure
- 6 JavaScript security rules covering SQL injection, XSS via innerHTML
  and dangerouslySetInnerHTML, hardcoded secrets, eval injection,
  prototype pollution, and missing CSRF tokens
- 2 TypeScript-specific rules covering raw SQL in TypeORM/Prisma/Drizzle
  and type assertion bypass into security-sensitive functions
- Three output formats: terminal (Rich colored output), SARIF 2.1.0
  (GitHub Security tab integration), and JSON (CI pipelines)
- GitHub Action with SARIF upload, per-severity finding counts as outputs,
  and GitHub Step Summary table
- Pre-commit hook integration via pre-commit framework
- Interactive `vibe-guard init` wizard: configures .vibeguard.toml,
  pre-commit hook, and GitHub Actions workflow in under 60 seconds
- `vibe-guard rules` command listing all 18 built-in rules with severity,
  CWE reference, and AI context explanation
- detect-secrets integration for entropy-based credential detection
- `.vibeguard.toml` configuration file support with automatic discovery
- Dogfooding: vibe-guard scans its own source code on every push to main

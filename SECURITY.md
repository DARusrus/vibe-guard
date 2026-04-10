# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes     |
| < 0.1   | ❌ N/A     |

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub Security Advisories for private disclosure:

1. Go to the repository's **Security** tab
2. Click **Advisories** → **Report a vulnerability**
3. Describe the vulnerability with steps to reproduce

### Response timeline

- **Acknowledgment:** within 48 hours
- **Fix timeline provided:** within 7 days
- **Patch released:** as soon as a fix is validated

## Scope

The following are considered vulnerabilities in vibe-guard itself:

- **False negative in a security rule** — a real vulnerability pattern that a rule claims to detect but misses
- **Command injection in the scanner** — malicious filenames or file content that could execute arbitrary commands via the Semgrep or detect-secrets subprocess calls
- **Path traversal in the detector** — crafted directory structures or symlinks that cause the scanner to read or write files outside the target directory
- **Information disclosure via error output** — verbose error messages, stack traces, or file contents leaked to terminal output or SARIF reports that should not be exposed

## Out of scope

The following are **not** considered vulnerabilities in vibe-guard:

- **False positives in rules** — a rule flagging safe code. Report these as a regular [GitHub issue](https://github.com/ahmbt/vibe-guard/issues). They are bugs, not security vulnerabilities.
- **Vulnerabilities in scanned code** — vibe-guard detects these; it does not cause them.
- **Vulnerabilities in Semgrep or detect-secrets** — report these to the respective upstream projects:
  - Semgrep: [github.com/returntocorp/semgrep](https://github.com/returntocorp/semgrep/security)
  - detect-secrets: [github.com/Yelp/detect-secrets](https://github.com/Yelp/detect-secrets/security)

## Acknowledgments

We acknowledge security reporters in:

- The `CHANGELOG.md` entry for the version containing the fix
- The GitHub Release notes for that version
- The Security Advisory itself (with reporter's permission)

Thank you for helping keep vibe-guard and the projects that use it secure.

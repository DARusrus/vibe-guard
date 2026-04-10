from __future__ import annotations

import logging
import time
from pathlib import Path

from vibeguard.detector import DEFAULT_EXTENSIONS, Detector
from vibeguard.engine import SemgrepEngine
from vibeguard.models import DetectorResult, Finding, ScanResult
from vibeguard.plugins.dotenv_scanner import DotenvPlugin
from vibeguard.plugins.mcp_config import MCPConfigPlugin
from vibeguard.plugins.prompt_injection import PromptInjectionPlugin
from vibeguard.plugins.sca import SCAPlugin
from vibeguard.plugins.secrets import SecretsPlugin

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent / "rules"

TIER_RULES: dict[str, list[str]] = {
    "FULL": [
        # Python
        "python/sqli.yaml",
        "python/cmdi.yaml",
        "python/path_traversal.yaml",
        "python/ssrf.yaml",
        "python/secrets.yaml",
        "python/deserial.yaml",
        "python/auth.yaml",
        "python/mass_assign.yaml",
        "python/cors.yaml",
        "python/error_exposure.yaml",
        "python/log-injection.yaml",
        "python/nosql-injection.yaml",
        "python/xxe.yaml",
        "python/ssti.yaml",
        "python/open-redirect.yaml",
        "python/graphql-injection.yaml",
        "python/redos.yaml",
        "python/html-injection.yaml",
        "python/weak-password-hash.yaml",
        "python/ecb-mode.yaml",
        "python/pii-in-logs.yaml",
        "python/insecure-random.yaml",
        "python/plaintext-sensitive-fields.yaml",
        "python/debug-mode.yaml",
        "python/missing-security-headers.yaml",
        "python/token-in-url.yaml",
        "python/race-condition-balance.yaml",
        "python/idor.yaml",
        "python/missing-rate-limit.yaml",
        "python/weak-session.yaml",
        "python/zip-slip.yaml",
        "python/crlf-injection.yaml",
        "python/default-credentials.yaml",
        # JavaScript / TypeScript
        "javascript/sqli.yaml",
        "javascript/xss.yaml",
        "javascript/secrets.yaml",
        "javascript/eval.yaml",
        "javascript/prototype_pollution.yaml",
        "javascript/csrf.yaml",
        "javascript/nosql-injection.yaml",
        "javascript/client-side-auth.yaml",
        "javascript/client-side-pricing.yaml",
        "javascript/log-injection.yaml",
        "javascript/supabase-service-role.yaml",
        "javascript/open-redirect.yaml",
        "javascript/graphql-injection.yaml",
        "javascript/crlf-injection.yaml",
        "javascript/ecb-mode.yaml",
        "javascript/pii-in-logs.yaml",
        "javascript/math-random-security.yaml",
        "javascript/missing-helmet.yaml",
        "typescript/sqli.yaml",
        "typescript/type_assertion_bypass.yaml",
        "typescript/client-side-auth.yaml",
        "typescript/missing-server-validation.yaml",
        # SQL / Shell / Dockerfile / GitHub Actions / Kubernetes
        "sql/missing-rls.yaml",
        "shell/curl-pipe-bash.yaml",
        "shell/missing-errexit.yaml",
        "shell/overpermissive-chmod.yaml",
        "dockerfile/missing-user.yaml",
        "dockerfile/curl-pipe-bash.yaml",
        "github-actions/secret-echo.yaml",
        "github-actions/unpinned-action.yaml",
        "kubernetes/rbac-cluster-admin.yaml",
    ],
    "MEDIUM": [
        # Existing Tier 1 rules
        "python/sqli.yaml",
        "python/cmdi.yaml",
        "python/path_traversal.yaml",
        "python/ssrf.yaml",
        "python/secrets.yaml",
        # Existing JS/TS high-risk rules
        "javascript/sqli.yaml",
        "javascript/secrets.yaml",
        "javascript/eval.yaml",
        "typescript/sqli.yaml",
        # New high-risk additions
        "python/idor.yaml",
        "python/debug-mode.yaml",
        "python/weak-password-hash.yaml",
        "python/insecure-random.yaml",
        "javascript/client-side-auth.yaml",
        "javascript/supabase-service-role.yaml",
        "javascript/client-side-pricing.yaml",
        "dockerfile/missing-user.yaml",
        "shell/curl-pipe-bash.yaml",
        "github-actions/secret-echo.yaml",
    ],
    "CRITICAL_ONLY": [
        # Baseline critical rules
        "python/secrets.yaml",
        "python/sqli.yaml",
        "javascript/secrets.yaml",
        "javascript/sqli.yaml",
        # New critical additions
        "python/debug-mode.yaml",
        "python/idor.yaml",
        "shell/curl-pipe-bash.yaml",
        "javascript/supabase-service-role.yaml",
    ],
}

# Map Semgrep severity strings to our severity labels as fallback
_SEMGREP_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


class Scanner:
    """Orchestrates the full scan pipeline.

    Ties together: Detector → tier grouping → rule selection →
    SemgrepEngine → SecretsPlugin → Finding assembly → ScanResult.
    """

    def __init__(
        self,
        ai_threshold: float = 0.6,
        min_severity: str = "MEDIUM",
        online: bool = False,
    ) -> None:
        """Initialize Scanner with configurable thresholds.

        Args:
            ai_threshold: Confidence threshold for AI detection.
            min_severity: Minimum severity to include in results.
                          One of "CRITICAL", "HIGH", "MEDIUM", "LOW".
            online: If True, enable online registry/API checks in SCA plugin.
        """
        self.detector = Detector(ai_threshold=ai_threshold)
        self.engine = SemgrepEngine()
        self.secrets = SecretsPlugin()
        self.sca = SCAPlugin(online=online)
        self.dotenv = DotenvPlugin()
        self.mcp_config = MCPConfigPlugin()
        self.prompt_injection = PromptInjectionPlugin()
        self.min_severity = min_severity
        self._severity_order: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
        }

    def scan_directory(
        self,
        path: str | Path,
        extensions: set[str] | None = None,
        file_filter: set[Path] | None = None,
    ) -> ScanResult:
        """Full scan pipeline on a directory.

        Pipeline steps:
          1. Run Detector.score_directory() → list[DetectorResult]
          2. Group files by scan_tier
          3. For each tier group, resolve rule paths from TIER_RULES
          4. Call SemgrepEngine.run(files, rules) per tier group
          5. Call SecretsPlugin.scan_files() on ALL files (not tier-gated)
          6. Assemble Finding objects from raw engine output
          7. Attach file_confidence from the matching DetectorResult
          8. Filter findings below min_severity
          9. Deduplicate (same rule_id + file_path + line = one finding)
         10. Return ScanResult

        Args:
            path: Directory path to scan.
            extensions: Optional set of file extensions to scan.
            file_filter: If provided, only scan files in this set (diff mode).

        Returns:
            ScanResult with all findings, counts, and detector data.
        """
        start_time = time.monotonic()
        target = Path(path)

        if not target.exists():
            return ScanResult(
                findings=[],
                files_scanned=0,
                ai_files_detected=0,
                detector_results=[],
                scan_duration_seconds=0.0,
                rules_applied=0,
            )

        is_diff_mode = file_filter is not None
        if file_filter is not None:
            # In diff mode, avoid walking the entire repository.
            exts = extensions or DEFAULT_EXTENSIONS
            filtered_files: set[Path] = set()
            for entry in file_filter:
                candidate = entry if entry.is_absolute() else target / entry
                try:
                    resolved = candidate.resolve()
                except (OSError, RuntimeError):
                    continue
                if not resolved.exists() or not resolved.is_file():
                    continue
                if self.detector._should_skip(resolved):
                    continue
                if resolved.suffix not in exts and resolved.name != "Dockerfile":
                    continue
                filtered_files.add(resolved)

            detector_results = [
                self.detector.score_file(file_path) for file_path in sorted(filtered_files, key=str)
            ]
            detector_results = sorted(
                detector_results,
                key=lambda result: result.confidence,
                reverse=True,
            )
        else:
            # Step 1: Detect AI-generated files
            detector_results = self.detector.score_directory(target, extensions)

        dr_map: dict[str, DetectorResult] = {dr.file_path: dr for dr in detector_results}

        # Step 2: Group files by scan tier
        tier_groups: dict[str, list[Path]] = {
            "FULL": [],
            "MEDIUM": [],
            "CRITICAL_ONLY": [],
        }
        all_files: list[Path] = []
        for dr in detector_results:
            file_path = Path(dr.file_path)
            tier_groups.setdefault(dr.scan_tier, []).append(file_path)
            all_files.append(file_path)

        # Step 3 & 4: For each tier, resolve rules and run engine
        all_raw_findings: list[dict] = []
        rules_applied_set: set[str] = set()

        for tier, files in tier_groups.items():
            if not files:
                continue
            rules = self._resolve_rules(tier)
            if not rules:
                continue
            for r in rules:
                rules_applied_set.add(str(r))
            raw = self.engine.run(files, rules)
            all_raw_findings.extend(raw)

        # Step 5: Run secrets plugin on ALL files
        # First assemble semgrep findings so we can deduplicate
        semgrep_findings: list[Finding] = []
        for raw in all_raw_findings:
            finding = self._assemble_finding(raw, dr_map)
            if finding is not None:
                semgrep_findings.append(finding)

        secrets_findings = self.secrets.scan_files(
            all_files,
            existing_findings=[f for f in semgrep_findings if f.rule_category == "secrets"],
        )

        # Attach file_confidence to secrets findings
        for sf in secrets_findings:
            dr = dr_map.get(sf.file_path)
            if dr:
                sf.file_confidence = dr.confidence

        # Step 6-7: Combine all findings
        all_findings = semgrep_findings + secrets_findings

        # Step 6b: Run new Plan 2 plugins
        # SCA plugin — runs on project root, not individual files
        sca_findings = self.sca.scan(all_files, target)
        all_findings.extend(sca_findings)

        # Dotenv scanner
        dotenv_findings = self.dotenv.scan(all_files, target)
        all_findings.extend(dotenv_findings)

        # MCP config scanner
        mcp_findings = self.mcp_config.scan(all_files, target)
        all_findings.extend(mcp_findings)

        # Prompt injection scanner
        injection_findings = self.prompt_injection.scan(all_files, target)
        all_findings.extend(injection_findings)

        # Step 8: Filter by min_severity
        all_findings = self._filter_severity(all_findings)

        # Step 9: Deduplicate
        all_findings = self._deduplicate(all_findings)

        elapsed = time.monotonic() - start_time

        ai_count = sum(1 for dr in detector_results if dr.is_ai_generated())

        # Count active plugins in rules_applied
        active_plugins = sum(
            1
            for p in [self.sca, self.dotenv, self.mcp_config, self.prompt_injection]
            if p.is_available()
        )

        return ScanResult(
            findings=all_findings,
            files_scanned=len(detector_results),
            ai_files_detected=ai_count,
            detector_results=detector_results,
            scan_duration_seconds=round(elapsed, 3),
            rules_applied=len(rules_applied_set) + active_plugins,
            diff_mode=is_diff_mode,
            changed_files_count=len(file_filter) if file_filter else 0,
        )

    def scan_file(
        self,
        path: str | Path,
    ) -> ScanResult:
        """Score a single file and scan with appropriate tier rules.

        Args:
            path: Path to the file to scan.

        Returns:
            ScanResult containing findings for the single file.
        """
        start_time = time.monotonic()
        target = Path(path)

        if not target.exists() or not target.is_file():
            return ScanResult(
                findings=[],
                files_scanned=0,
                ai_files_detected=0,
                detector_results=[],
                scan_duration_seconds=0.0,
                rules_applied=0,
            )

        # Score the file
        dr = self.detector.score_file(target)
        dr_map: dict[str, DetectorResult] = {dr.file_path: dr}

        # Resolve rules for this file's tier
        rules = self._resolve_rules(dr.scan_tier)

        # Run engine
        raw_findings = self.engine.run([target], rules) if rules else []

        # Assemble findings
        findings: list[Finding] = []
        for raw in raw_findings:
            finding = self._assemble_finding(raw, dr_map)
            if finding is not None:
                findings.append(finding)

        # Run secrets plugin
        secrets_findings = self.secrets.scan_files(
            [target],
            existing_findings=[f for f in findings if f.rule_category == "secrets"],
        )
        for sf in secrets_findings:
            sf.file_confidence = dr.confidence
        findings.extend(secrets_findings)

        # Run new Plan 2 plugins on single file
        project_root = target.parent
        sca_findings = self.sca.scan([target], project_root)
        findings.extend(sca_findings)

        dotenv_findings = self.dotenv.scan([target], project_root)
        findings.extend(dotenv_findings)

        mcp_findings = self.mcp_config.scan([target], project_root)
        findings.extend(mcp_findings)

        injection_findings = self.prompt_injection.scan([target], project_root)
        findings.extend(injection_findings)

        # Filter and deduplicate
        findings = self._filter_severity(findings)
        findings = self._deduplicate(findings)

        elapsed = time.monotonic() - start_time
        ai_count = 1 if dr.is_ai_generated() else 0

        active_plugins = sum(
            1
            for p in [self.sca, self.dotenv, self.mcp_config, self.prompt_injection]
            if p.is_available()
        )

        return ScanResult(
            findings=findings,
            files_scanned=1,
            ai_files_detected=ai_count,
            detector_results=[dr],
            scan_duration_seconds=round(elapsed, 3),
            rules_applied=len(rules) + active_plugins,
        )

    def _assemble_finding(
        self,
        raw: dict,
        detector_results: dict[str, DetectorResult],
    ) -> Finding | None:
        """Map a raw Semgrep result dict to a Finding.

        Extract fix_guidance and ai_context from rule metadata fields
        (populated in the YAML files). Return None if the raw dict is
        missing required fields — never raise.

        Args:
            raw: Normalized finding dict from SemgrepEngine._parse_finding().
            detector_results: Map of file_path → DetectorResult for
                              looking up file_confidence.

        Returns:
            Finding instance, or None if required fields are missing.
        """
        try:
            check_id = raw.get("check_id", "")
            file_path = raw.get("path", "")
            line = raw.get("line", 0)
            col = raw.get("col", 0)
            message = raw.get("message", "")
            snippet = raw.get("snippet", "")

            if not check_id or not file_path:
                return None

            metadata = raw.get("metadata", {})

            # Get severity from our custom metadata, fall back to Semgrep severity
            severity_label = metadata.get("severity_label", "")
            if not severity_label:
                semgrep_sev = raw.get("severity", "WARNING")
                severity_label = _SEMGREP_SEVERITY_MAP.get(semgrep_sev, "MEDIUM")

            cwe_id = metadata.get("cwe", "")
            fix_guidance = metadata.get("fix_guidance", "")
            ai_context = metadata.get("ai_context", "")
            rule_category = metadata.get("rule_category", "")

            # Look up file confidence from detector results
            # Normalize path for matching
            file_confidence = 0.0
            for dr_path, dr in detector_results.items():
                try:
                    if Path(dr_path).resolve() == Path(file_path).resolve():
                        file_confidence = dr.confidence
                        break
                except (OSError, ValueError):
                    if dr_path == file_path:
                        file_confidence = dr.confidence
                        break

            return Finding(
                rule_id=check_id,
                severity=severity_label,
                file_path=file_path,
                line=line,
                col=col,
                message=message,
                fix_guidance=fix_guidance,
                cwe_id=cwe_id,
                ai_context=ai_context,
                file_confidence=file_confidence,
                rule_category=rule_category,
                snippet=snippet,
                semgrep_rule_id=check_id,
            )
        except Exception:
            logger.exception("Failed to assemble finding from raw: %s", raw)
            return None

    def _resolve_rules(self, tier: str) -> list[Path]:
        """Return absolute Paths to rule files for a given tier.

        Skip rules that do not exist on disk with a warning — never crash.

        Args:
            tier: One of 'FULL', 'MEDIUM', 'CRITICAL_ONLY'.

        Returns:
            List of absolute paths to existing rule YAML files.
        """
        rule_names = TIER_RULES.get(tier, TIER_RULES["CRITICAL_ONLY"])
        resolved: list[Path] = []
        for name in rule_names:
            rule_path = RULES_DIR / name
            if rule_path.exists():
                resolved.append(rule_path)
            else:
                logger.warning("Rule file not found: %s", rule_path)
        return resolved

    def _filter_severity(self, findings: list[Finding]) -> list[Finding]:
        """Remove findings below self.min_severity.

        Args:
            findings: List of findings to filter.

        Returns:
            Filtered list containing only findings at or above min_severity.
        """
        min_rank = self._severity_order.get(self.min_severity, 2)
        return [f for f in findings if self._severity_order.get(f.severity, 99) <= min_rank]

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove exact duplicates. Key: (rule_id, file_path, line).

        Args:
            findings: List of findings that may contain duplicates.

        Returns:
            Deduplicated list preserving first occurrence order.
        """
        seen: set[tuple[str, str, int]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.file_path, f.line)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


def scan(
    path: str | Path,
    ai_threshold: float = 0.6,
    online: bool = False,
) -> ScanResult:
    """Module-level convenience function. Session 3's CLI calls this.

    Args:
        path: Directory or file path to scan.
        ai_threshold: Confidence threshold for AI detection.
        online: If True, enable online registry/API checks.

    Returns:
        ScanResult from scanning the given path.
    """
    return Scanner(ai_threshold=ai_threshold, online=online).scan_directory(path)

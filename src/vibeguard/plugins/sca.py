from __future__ import annotations

import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]

from vibeguard.models import Finding
from vibeguard.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

# Version comparison helpers ────────────────────────────────────────────

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple of ints."""
    m = _VERSION_RE.match(v.strip())
    if not m:
        return (0,)
    return tuple(int(g) for g in m.groups() if g is not None)


def _version_lt(a: str, b: str) -> bool:
    """Return True if version *a* is strictly less than version *b*."""
    return _parse_version(a) < _parse_version(b)


# Dependency file parsers ──────────────────────────────────────────────

_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9][-A-Za-z0-9_.]*)"  # package name
    r"(?:\[.*?\])?"  # optional extras
    r"(?:\s*(==|>=|<=|~=|!=|>|<)\s*"  # operator
    r"([A-Za-z0-9][-A-Za-z0-9_.]*))?",  # version
)

_NPM_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


class SCAPlugin(BasePlugin):
    """Software Composition Analysis plugin.

    Detects slopsquatting (hallucinated package names) and
    known CVEs in AI-recommended dependencies. Works offline
    using bundled corpus. Optionally validates against live
    registry APIs when --online flag is passed.
    """

    CORPUS_PATH = Path(__file__).parent.parent / "data" / "hallucinated_packages.json"
    OSV_SNAPSHOT_PATH = Path(__file__).parent.parent / "data" / "osv_snapshot.json"
    OSV_API = "https://api.osv.dev/v1/query"

    DEPENDENCY_FILES: dict[str, str] = {
        "requirements.txt": "python",
        "requirements-dev.txt": "python",
        "requirements-test.txt": "python",
        "setup.py": "python",
        "setup.cfg": "python",
        "Pipfile": "python",
        "pyproject.toml": "python",
        "package.json": "npm",
        "package-lock.json": "npm",
        "yarn.lock": "npm",
        "go.mod": "go",
        "Cargo.toml": "rust",
    }

    # Lock file mapping: if a manifest exists, which lock files to expect
    _LOCK_FILES: dict[str, list[str]] = {
        "requirements.txt": ["requirements.txt.lock", "Pipfile.lock", "poetry.lock"],
        "Pipfile": ["Pipfile.lock"],
        "pyproject.toml": ["poetry.lock", "pdm.lock", "uv.lock"],
        "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    }

    def __init__(self, online: bool = False, timeout: int = 5) -> None:
        """Initialize SCA plugin.

        Args:
            online: If True, validate packages against live registries.
            timeout: Timeout in seconds for HTTP requests.
        """
        self.online = online
        self.timeout = timeout
        self._corpus: dict[str, set[str]] = self._load_corpus()
        self._osv_snapshot: dict = self._load_osv_snapshot()
        self._registry_cache: dict[str, bool] = {}

    @property
    def name(self) -> str:
        """Plugin identifier."""
        return "sca"

    def is_available(self) -> bool:
        """Return True if the bundled corpus file exists."""
        return self.CORPUS_PATH.exists()

    def scan(self, files: list[Path], project_root: Path) -> list[Finding]:
        """Scan dependency files for slopsquatting and CVEs.

        Args:
            files: List of source files (unused — SCA walks project_root).
            project_root: Root directory of the project to scan.

        Returns:
            List of findings. Never raises.
        """
        try:
            return self._scan_impl(project_root)
        except Exception:
            logger.exception("SCAPlugin.scan failed")
            return []

    # ── Internal implementation ───────────────────────────────────────

    def _scan_impl(self, project_root: Path) -> list[Finding]:
        """Core scan logic."""
        findings: list[Finding] = []
        seen_keys: set[tuple[str, str, int]] = set()

        # Discover dependency files
        dep_files = self._find_dependency_files(project_root)
        if not dep_files:
            return []

        # Parse all dependency files
        all_deps: list[
            tuple[str, str, str, Path, int]
        ] = []  # (name, version, ecosystem, file, line)
        for dep_file, ecosystem in dep_files:
            try:
                deps = self._parse_dependency_file(dep_file, ecosystem)
                for pkg_name, version, line_num in deps:
                    all_deps.append((pkg_name, version, ecosystem, dep_file, line_num))
            except Exception:
                logger.warning("Failed to parse %s", dep_file)
                continue

        # Step B — Slopsquatting check
        for pkg_name, version, ecosystem, dep_file, line_num in all_deps:
            normalized = pkg_name.lower().strip()
            corpus_set = self._corpus.get(ecosystem, set())
            if normalized in corpus_set:
                f = self._make_slopsquatting_finding(
                    normalized,
                    ecosystem,
                    str(dep_file),
                    line_num,
                )
                key = (f.rule_id, f.file_path, f.line)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(f)

        # Online registry validation (opt-in)
        if self.online:
            online_findings = self._online_registry_check(all_deps, seen_keys)
            findings.extend(online_findings)

        # Step C — CVE check
        for pkg_name, version, ecosystem, dep_file, line_num in all_deps:
            if not version:
                continue
            cve_findings = self._check_cve_offline(
                pkg_name.lower().strip(),
                version,
                ecosystem,
                str(dep_file),
                line_num,
            )
            for f in cve_findings:
                key = (f.rule_id, f.file_path, f.line)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(f)

        # Step D — Unpinned dependencies
        for pkg_name, version, ecosystem, dep_file, line_num in all_deps:
            if not version:
                f = self._make_unpinned_finding(
                    pkg_name.lower().strip(),
                    str(dep_file),
                    line_num,
                )
                key = (f.rule_id, f.file_path, f.line)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(f)

        # Step E — Missing lock files
        lock_findings = self._check_missing_lock_files(project_root, dep_files)
        for f in lock_findings:
            key = (f.rule_id, f.file_path, f.line)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append(f)

        return findings

    def _find_dependency_files(
        self,
        project_root: Path,
    ) -> list[tuple[Path, str]]:
        """Walk project_root for dependency files."""
        found: list[tuple[Path, str]] = []
        try:
            for name, ecosystem in self.DEPENDENCY_FILES.items():
                candidate = project_root / name
                if candidate.exists() and candidate.is_file():
                    found.append((candidate, ecosystem))
        except OSError:
            pass
        return found

    def _parse_dependency_file(
        self,
        path: Path,
        ecosystem: str,
    ) -> list[tuple[str, str, int]]:
        """Parse a dependency file into (name, version, line_number) tuples."""
        filename = path.name
        if filename in (
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-test.txt",
        ):
            return self._parse_requirements_txt(path)
        if filename == "package.json":
            return self._parse_package_json(path)
        if filename == "pyproject.toml":
            return self._parse_pyproject_toml(path)
        # Best-effort for other formats
        return self._parse_requirements_txt(path)

    def _parse_requirements_txt(self, path: Path) -> list[tuple[str, str, int]]:
        """Parse requirements.txt format files.

        Args:
            path: Path to the requirements file.

        Returns:
            List of (package_name, version, line_number) tuples.
        """
        results: list[tuple[str, str, int]] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        for line_num, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = _REQ_LINE_RE.match(line)
            if m:
                name = m.group(1)
                version = m.group(3) or ""
                results.append((name, version, line_num))
        return results

    def _parse_package_json(self, path: Path) -> list[tuple[str, str, int]]:
        """Parse package.json for dependencies.

        Args:
            path: Path to package.json.

        Returns:
            List of (package_name, version, line_number) tuples.
        """
        results: list[tuple[str, str, int]] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return []

        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, ver_spec in deps.items():
                # Extract numeric version from npm version spec
                ver = ""
                if isinstance(ver_spec, str):
                    m = _NPM_VERSION_RE.search(ver_spec)
                    if m:
                        ver = m.group(1)
                results.append((name, ver, 1))
        return results

    def _parse_pyproject_toml(self, path: Path) -> list[tuple[str, str, int]]:
        """Parse pyproject.toml [project.dependencies].

        Args:
            path: Path to pyproject.toml.

        Returns:
            List of (package_name, version, line_number) tuples.
        """
        results: list[tuple[str, str, int]] = []
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return []

        deps = data.get("project", {}).get("dependencies", [])
        if not isinstance(deps, list):
            return []

        for i, dep in enumerate(deps):
            if not isinstance(dep, str):
                continue
            m = _REQ_LINE_RE.match(dep.strip())
            if m:
                name = m.group(1)
                version = m.group(3) or ""
                results.append((name, version, i + 1))
        return results

    # ── Slopsquatting ─────────────────────────────────────────────────

    def _make_slopsquatting_finding(
        self,
        name: str,
        ecosystem: str,
        file_path: str,
        line: int,
    ) -> Finding:
        """Create a CRITICAL slopsquatting finding."""
        registry_url = (
            f"pypi.org/project/{name}" if ecosystem == "python" else f"npmjs.com/package/{name}"
        )
        return self._make_finding(
            rule_id="vibeguard-sca-slopsquatting",
            severity="CRITICAL",
            file_path=file_path,
            line=line,
            message=(
                f"Package '{name}' matches a known AI-hallucinated package "
                f"name. Verify this package exists before installing."
            ),
            fix_guidance=(
                f"Verify this package exists: pip show {name} or "
                f"check {registry_url}. If it does not exist, "
                f"find the correct package name manually."
            ),
            cwe_id="CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
            ai_context=(
                "AI models hallucinate package names that sound plausible "
                "but do not exist. Attackers pre-register these names with "
                "malicious code — a technique called slopsquatting."
            ),
            rule_category="sca",
        )

    def _online_registry_check(
        self,
        all_deps: list[tuple[str, str, str, Path, int]],
        seen_keys: set[tuple[str, str, int]],
    ) -> list[Finding]:
        """Check packages against live registries using ThreadPoolExecutor.

        Args:
            all_deps: All discovered dependencies.
            seen_keys: Already-seen finding keys for dedup.

        Returns:
            List of slopsquatting findings from online check.
        """
        findings: list[Finding] = []
        to_check: list[tuple[str, str, Path, int]] = []

        for pkg_name, _version, ecosystem, dep_file, line_num in all_deps:
            normalized = pkg_name.lower().strip()
            key = ("vibeguard-sca-slopsquatting", str(dep_file), line_num)
            if key in seen_keys:
                continue
            if ecosystem not in ("python", "npm"):
                continue
            if normalized not in self._registry_cache:
                to_check.append((normalized, ecosystem, dep_file, line_num))

        if not to_check:
            return []

        def _check_one(
            item: tuple[str, str, Path, int],
        ) -> tuple[str, str, Path, int, bool]:
            name, eco, dep_file, line_num = item
            exists = self._check_registry_exists(name, eco)
            return (name, eco, dep_file, line_num, exists)

        try:
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = {pool.submit(_check_one, item): item for item in to_check}
                for future in as_completed(futures, timeout=self.timeout * 3):
                    try:
                        name, eco, dep_file, line_num, exists = future.result(timeout=self.timeout)
                        self._registry_cache[name] = exists
                        if not exists:
                            f = self._make_slopsquatting_finding(
                                name,
                                eco,
                                str(dep_file),
                                line_num,
                            )
                            key = (f.rule_id, f.file_path, f.line)
                            if key not in seen_keys:
                                seen_keys.add(key)
                                findings.append(f)
                    except Exception:
                        pass
        except Exception:
            logger.warning("Online registry check timed out or failed")

        return findings

    def _check_registry_exists(self, name: str, ecosystem: str) -> bool:
        """Check if a package exists on the public registry.

        Args:
            name: Package name.
            ecosystem: 'python' or 'npm'.

        Returns:
            True if the package exists, False if 404.
        """
        if name in self._registry_cache:
            return self._registry_cache[name]

        if ecosystem == "python":
            url = f"https://pypi.org/pypi/{name}/json"
        elif ecosystem == "npm":
            url = f"https://registry.npmjs.org/{name}"
        else:
            return True  # assume exists for unsupported ecosystems

        try:
            req = Request(url, method="GET")
            req.add_header("User-Agent", "vibe-guard/0.1.0")
            with urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except HTTPError as e:
            if e.code == 404:
                return False
            return True  # on other errors, assume exists to avoid false positives
        except (URLError, OSError, TimeoutError):
            return True  # network error → assume exists

    # ── CVE checking ──────────────────────────────────────────────────

    def _check_cve_offline(
        self,
        name: str,
        version: str,
        ecosystem: str,
        file_path: str,
        line: int,
    ) -> list[Finding]:
        """Check a package against the bundled OSV snapshot.

        Args:
            name: Package name (lowercase).
            version: Package version string.
            ecosystem: 'python' or 'npm'.
            file_path: Path to the dependency file.
            line: Line number in the dependency file.

        Returns:
            List of CVE findings (0 or 1 items).
        """
        packages = self._osv_snapshot.get("packages", {}).get(ecosystem, {})
        pkg_info = packages.get(name)
        if not pkg_info:
            return []

        safe_from = pkg_info.get("safe_from", "")
        if not safe_from or not _version_lt(version, safe_from):
            return []

        cve_list = pkg_info.get("known_cves", [])
        severity = pkg_info.get("severity", "HIGH")

        return [
            self._make_finding(
                rule_id="vibeguard-sca-known-cve",
                severity=severity,
                file_path=file_path,
                line=line,
                message=(
                    f"Package '{name}=={version}' has known CVEs: "
                    f"{', '.join(cve_list)}. Safe version: {safe_from}."
                ),
                fix_guidance=f"Upgrade to {name}>={safe_from}",
                cwe_id="CWE-1395: Dependency on Vulnerable Third-Party Component",
                ai_context=(
                    "AI code generators frequently recommend outdated package "
                    "versions with known security vulnerabilities."
                ),
                rule_category="sca",
            )
        ]

    def _check_osv_api(
        self,
        name: str,
        version: str,
        ecosystem: str,
    ) -> list[dict]:
        """Query the OSV.dev API for vulnerabilities.

        Args:
            name: Package name.
            version: Package version.
            ecosystem: Ecosystem string for OSV (e.g., 'PyPI', 'npm').

        Returns:
            List of vulnerability dicts from OSV response.
        """
        osv_ecosystem = {"python": "PyPI", "npm": "npm"}.get(ecosystem, ecosystem)
        payload = json.dumps(
            {
                "package": {"name": name, "ecosystem": osv_ecosystem},
                "version": version,
            }
        ).encode("utf-8")

        try:
            req = Request(
                self.OSV_API,
                data=payload,
                method="POST",
            )
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", "vibe-guard/0.1.0")
            with urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
                return data.get("vulns", [])
        except Exception:
            return []

    # ── Unpinned / missing lock ───────────────────────────────────────

    def _make_unpinned_finding(
        self,
        name: str,
        file_path: str,
        line: int,
    ) -> Finding:
        """Create a MEDIUM finding for an unpinned dependency."""
        return self._make_finding(
            rule_id="vibeguard-sca-unpinned",
            severity="MEDIUM",
            file_path=file_path,
            line=line,
            message=(
                f"Package '{name}' has no version pin. Unpinned dependencies "
                f"are a supply chain risk — a compromised future version "
                f"could be installed automatically."
            ),
            fix_guidance=f"Pin to a specific version: {name}==<version>",
            cwe_id="CWE-1357: Reliance on Insufficiently Trustworthy Component",
            ai_context=(
                "AI code generators often omit version pins in requirements "
                "files, leaving projects vulnerable to dependency confusion "
                "and supply chain attacks."
            ),
            rule_category="sca",
        )

    def _check_missing_lock_files(
        self,
        project_root: Path,
        dep_files: list[tuple[Path, str]],
    ) -> list[Finding]:
        """Check whether manifest files have corresponding lock files.

        Args:
            project_root: Project root directory.
            dep_files: List of (path, ecosystem) dependency files found.

        Returns:
            List of MEDIUM findings for missing lock files.
        """
        findings: list[Finding] = []
        checked: set[str] = set()

        for dep_file, _ecosystem in dep_files:
            manifest_name = dep_file.name
            lock_candidates = self._LOCK_FILES.get(manifest_name)
            if lock_candidates is None:
                continue
            if manifest_name in checked:
                continue
            checked.add(manifest_name)

            has_lock = any((project_root / lock).exists() for lock in lock_candidates)
            if not has_lock:
                findings.append(
                    self._make_finding(
                        rule_id="vibeguard-sca-no-lock-file",
                        severity="MEDIUM",
                        file_path=str(dep_file),
                        line=1,
                        message=(
                            f"'{manifest_name}' exists but no corresponding lock file "
                            f"was found. Without a lock file, dependency resolution "
                            f"is non-deterministic."
                        ),
                        fix_guidance=(
                            "Generate a lock file to pin transitive dependencies: "
                            "pip freeze > requirements.txt, poetry lock, or npm install"
                        ),
                        cwe_id="CWE-1357: Reliance on Insufficiently Trustworthy Component",
                        ai_context=(
                            "AI-generated projects frequently omit lock files, "
                            "making builds non-reproducible and vulnerable to "
                            "supply chain attacks."
                        ),
                        rule_category="sca",
                    )
                )
        return findings

    # ── Data loading ──────────────────────────────────────────────────

    def _load_corpus(self) -> dict[str, set[str]]:
        """Load the hallucinated packages corpus.

        Returns:
            Dict mapping ecosystem to set of hallucinated package names.
        """
        try:
            data = json.loads(self.CORPUS_PATH.read_text(encoding="utf-8"))
            return {
                "python": set(data.get("python", [])),
                "npm": set(data.get("npm", [])),
            }
        except Exception:
            logger.warning("Failed to load hallucinated packages corpus")
            return {"python": set(), "npm": set()}

    def _load_osv_snapshot(self) -> dict:
        """Load the OSV CVE snapshot.

        Returns:
            Parsed JSON dict from the snapshot file.
        """
        try:
            return json.loads(
                self.OSV_SNAPSHOT_PATH.read_text(encoding="utf-8"),
            )
        except Exception:
            logger.warning("Failed to load OSV snapshot")
            return {}

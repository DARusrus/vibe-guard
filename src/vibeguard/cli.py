from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

import click
import typer
from click.core import ParameterSource

from vibeguard import __version__
from vibeguard.config import load_config
from vibeguard.models import ScanResult
from vibeguard.reporters import get_reporter
from vibeguard.scanner import Scanner

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="vibe-guard",
    help="AI-aware security scanner. Finds vulnerabilities in AI-generated code.",
    rich_markup_mode="rich",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)


def _was_explicit(param_name: str) -> bool:
    """Return True if the CLI parameter was explicitly provided by user."""
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return False
    return ctx.get_parameter_source(param_name) != ParameterSource.DEFAULT


def _ensure_tooling_on_path() -> None:
    """Ensure subprocess tools in the active Python environment are discoverable."""
    scripts_dir = str(Path(sys.executable).resolve().parent)
    current = os.environ.get("PATH", "")
    if scripts_dir.lower() not in current.lower().split(os.pathsep):
        os.environ["PATH"] = f"{scripts_dir}{os.pathsep}{current}" if current else scripts_dir


def _get_diff_files(target: Path) -> set[Path] | None:
    """Get files changed since last git commit.

    Returns a set of Path objects, or None if git is unavailable or fails.
    Prints warnings to stderr on failure.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(target if target.is_dir() else target.parent),
        )
        if result.returncode != 0:
            typer.echo(
                "Warning: git diff failed. Running full scan.",
                err=True,
            )
            return None

        lines = result.stdout.strip().splitlines()
        if not lines:
            typer.echo(
                "No changed files detected. Showing full scan.",
                err=True,
            )
            return None

        # Resolve to absolute paths relative to target dir
        base = target if target.is_dir() else target.parent
        changed = set()
        for line in lines:
            p = (base / line).resolve()
            if p.exists():  # Skip deleted files
                changed.add(p)

        if not changed:
            typer.echo(
                "All changed files were deleted. Showing full scan.",
                err=True,
            )
            return None

        return changed

    except FileNotFoundError:
        typer.echo(
            "Warning: git not found. Running full scan.",
            err=True,
        )
        return None
    except subprocess.TimeoutExpired:
        typer.echo(
            "Warning: git diff timed out. Running full scan.",
            err=True,
        )
        return None
    except Exception:
        typer.echo(
            "Warning: git diff failed. Running full scan.",
            err=True,
        )
        return None


@app.command()
def scan(
    path: Path = typer.Argument(
        default=".",
        help="Directory or file to scan.",
        exists=True,
    ),
    severity: str = typer.Option(
        "MEDIUM",
        "--severity",
        "-s",
        help="Minimum severity to report. [CRITICAL|HIGH|MEDIUM|LOW]",
    ),
    ai_threshold: float = typer.Option(
        0.6,
        "--ai-threshold",
        help="Confidence threshold for AI detection. Files above this get full scan.",
        min=0.0,
        max=1.0,
    ),
    format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format. [terminal|sarif|json]",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write output to this file instead of stdout.",
    ),
    no_fail: bool = typer.Option(
        False,
        "--no-fail",
        help="Always exit 0, even if findings are present.",
    ),
    config_path: Path | None = typer.Option(
        None,
        "--config",
        help="Path to .vibeguard.toml (auto-detected if omitted).",
    ),
    diff: bool = typer.Option(
        False,
        "--diff",
        help="Scan only files changed since last git commit.",
    ),
    smart_filter: bool = typer.Option(
        False,
        "--smart-filter",
        help="Use AI to remove likely false positives from HIGH/CRITICAL findings. "
        "Requires GEMINI_API_KEY environment variable.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Add plain-English attack scenario to each finding. "
        "Requires GEMINI_API_KEY environment variable.",
    ),
    online: bool = typer.Option(
        False,
        "--online",
        help="Enable live registry checks for dependency validation "
        "(SCA plugin). Queries PyPI and npm APIs.",
    ),
) -> None:
    """Scan a directory or file for security vulnerabilities in AI-generated code."""
    _ensure_tooling_on_path()
    config = load_config(config_path if config_path is not None else path)

    if _was_explicit("severity"):
        config.min_severity = severity.upper()
    if _was_explicit("ai_threshold"):
        config.ai_threshold = ai_threshold
    if _was_explicit("format"):
        config.default_format = format.lower()
    if _was_explicit("output"):
        config.output_path = str(output) if output else None
    if _was_explicit("no_fail"):
        config.no_fail = no_fail

    scanner = Scanner(
        ai_threshold=config.ai_threshold,
        min_severity=config.min_severity,
        online=online,
    )

    # Diff mode: get changed files
    file_filter: set[Path] | None = None
    if diff:
        file_filter = _get_diff_files(path)

    if path.is_file():
        result = scanner.scan_file(path)
    else:
        result = scanner.scan_directory(
            path, extensions=set(config.extensions), file_filter=file_filter
        )

    # Smart filter: reduce false positives for HIGH/CRITICAL
    if smart_filter:
        result = _apply_smart_filter(result)

    output_path = (
        output if output is not None else (Path(config.output_path) if config.output_path else None)
    )

    try:
        reporter = get_reporter(config.default_format)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--format") from exc

    # For terminal reporter, pass explain flag
    if config.default_format == "terminal" and explain:
        from vibeguard.reporters.terminal import TerminalReporter

        if isinstance(reporter, TerminalReporter):
            reporter.explain_mode = True

    reporter.write(result, output_path)
    typer.echo(result.summary_line(), err=True)

    if no_fail or config.no_fail or not config.fail_on_findings:
        raise typer.Exit(code=0)
    if result.findings:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


def _apply_smart_filter(result: ScanResult) -> ScanResult:
    """Apply AI-powered false positive filtering to HIGH/CRITICAL findings."""
    from vibeguard.ai.context_filter import ContextFilter

    ctx_filter = ContextFilter()
    if not ctx_filter.client.is_available():
        typer.echo(
            "Smart filter requires GEMINI_API_KEY. Skipping AI filtering.",
            err=True,
        )
        return result

    filtered_findings = []
    removed_count = 0

    for finding in result.findings:
        if finding.severity in ("CRITICAL", "HIGH"):
            # Read file content for context
            try:
                content = Path(finding.file_path).read_text(encoding="utf-8", errors="replace")
            except Exception:
                filtered_findings.append(finding)
                continue

            if ctx_filter.is_true_positive(finding, content):
                filtered_findings.append(finding)
            else:
                removed_count += 1
        else:
            filtered_findings.append(finding)

    # Create updated result with filtered findings
    return ScanResult(
        findings=filtered_findings,
        files_scanned=result.files_scanned,
        ai_files_detected=result.ai_files_detected,
        detector_results=result.detector_results,
        scan_duration_seconds=result.scan_duration_seconds,
        rules_applied=result.rules_applied,
        diff_mode=result.diff_mode,
        changed_files_count=result.changed_files_count,
        filtered_count=removed_count,
    )


@app.command()
def fix(
    path: Path = typer.Argument(
        default=".",
        help="File or directory to scan and fix.",
        exists=True,
    ),
    auto: bool = typer.Option(
        False,
        "--auto",
        help="Apply all fixes automatically without confirmation. Use with caution.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show fixes without applying them.",
    ),
) -> None:
    """Generate and apply AI-powered secure code fixes."""
    _ensure_tooling_on_path()
    from vibeguard.commands.fix import run_fix

    run_fix(path, auto=auto, dry_run=dry_run)


@app.command()
def score(
    path: Path = typer.Argument(
        default=".",
        help="Directory or file to score.",
        exists=True,
    ),
    update_readme: bool = typer.Option(
        False,
        "--update-readme",
        help="Automatically update README.md badge URL.",
    ),
    fail_below: int = typer.Option(
        0,
        "--fail-below",
        help="Exit 1 if score is below this threshold. Example: --fail-below 70",
    ),
) -> None:
    """Calculate security score and generate a README badge."""
    _ensure_tooling_on_path()
    from vibeguard.commands.score import run_score

    result_score = run_score(path, update_readme=update_readme, fail_below=fail_below)

    if fail_below > 0 and result_score < fail_below:
        typer.echo(
            f"Score {result_score} is below threshold {fail_below}.",
            err=True,
        )
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command()
def init(
    path: Path = typer.Argument(
        default=".",
        help="Project root to configure.",
    ),
) -> None:
    """Interactive setup: create config, add pre-commit hook, add GitHub Action."""
    from vibeguard.commands.init import run_init_wizard

    run_init_wizard(path)


@app.command()
def rules(
    language: str | None = typer.Option(
        None,
        "--language",
        "-l",
        help="Filter by language. [python|javascript|typescript]",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity. [CRITICAL|HIGH|MEDIUM|LOW]",
    ),
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by rule category. e.g. sqli, secrets, ssrf",
    ),
) -> None:
    """List all built-in security rules."""
    from vibeguard.commands.rules import list_rules

    list_rules(language=language, severity=severity, category=category)


def version_callback(value: bool) -> None:
    """Print package version and exit when --version is passed."""
    if value:
        typer.echo(f"vibe-guard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Top-level callback for app-wide options."""
    _ = version

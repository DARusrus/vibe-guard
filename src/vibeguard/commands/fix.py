"""AI-powered secure code fix command.

Scans a path for vulnerabilities, then offers AI-generated fixes
for each finding. Falls back to manual fix guidance when
GEMINI_API_KEY is not set.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from vibeguard.ai.autofix import AutoFixer
from vibeguard.scanner import Scanner


def run_fix(
    path: Path = Path("."),
    auto: bool = False,
    dry_run: bool = False,
) -> None:
    """Scan path, then offer AI-generated fixes for each finding.

    Args:
        path: File or directory to scan and fix.
        auto: Apply all fixes without confirmation.
        dry_run: Show fixes without applying them.
    """
    console = Console(highlight=False)
    fixer = AutoFixer()

    # Check AI availability up front
    if not fixer.client.is_available():
        console.print(
            "[yellow]AI auto-fix requires GEMINI_API_KEY environment variable.\n"
            "Showing manual fix guidance instead.\n"
            "Get a free key: ai.google.dev[/yellow]\n"
        )

    # Scan
    scanner = Scanner()
    if path.is_file():
        result = scanner.scan_file(path)
    else:
        result = scanner.scan_directory(path)

    if not result.findings:
        console.print("[bold green]No findings — nothing to fix![/bold green]")
        return

    # Sort findings: CRITICAL first, then HIGH, MEDIUM, LOW
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (severity_order.get(f.severity, 99), f.file_path, f.line),
    )

    applied_count = 0
    skipped_count = 0
    errored_count = 0

    console.print(
        f"[bold]Found {len(sorted_findings)} findings. "
        f"Processing fixes...[/bold]\n"
    )

    for i, finding in enumerate(sorted_findings, 1):
        severity_style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "dim yellow",
        }.get(finding.severity, "white")

        console.print(
            f"\n[{severity_style}]── [{i}/{len(sorted_findings)}] "
            f"{finding.severity} — {finding.rule_id}[/]"
        )
        console.print(f"  {finding.file_path}:{finding.line}")
        console.print(f"  {finding.message}")

        # Extract source context
        context = _extract_context(finding.file_path, finding.line)
        if context is None:
            console.print("  [dim]Could not read source file[/dim]")
            skipped_count += 1
            continue

        # Try AI fix
        fix_diff = fixer.generate_fix(finding, context)

        if fix_diff is None:
            # Fall back to manual guidance
            if finding.fix_guidance:
                console.print(
                    Panel(
                        finding.fix_guidance,
                        title="Manual fix guidance",
                        border_style="dim",
                        expand=False,
                    )
                )
            else:
                console.print("  [dim]No fix guidance available[/dim]")
            skipped_count += 1
            continue

        # Show the diff
        console.print()
        console.print(
            Syntax(fix_diff, "diff", theme="monokai", word_wrap=True)
        )

        if dry_run:
            console.print("  [dim]Dry run — not applying[/dim]")
            skipped_count += 1
            continue

        # Confirm or auto-apply
        if auto:
            apply = True
        else:
            try:
                apply = typer.confirm("  Apply this fix?", default=False)
            except (EOFError, KeyboardInterrupt):
                console.print("\n[yellow]Interrupted. Stopping.[/yellow]")
                break

        if apply:
            success = _apply_fix(finding.file_path, finding.line, context, fix_diff)
            if success:
                console.print("  [green]✓ Fix applied[/green]")
                applied_count += 1
            else:
                console.print("  [red]✗ Failed to apply fix[/red]")
                errored_count += 1
        else:
            console.print("  [dim]Skipped[/dim]")
            skipped_count += 1

    # Summary
    console.print("\n" + "─" * 50)
    parts = []
    if applied_count:
        parts.append(f"[green]{applied_count} applied[/green]")
    if skipped_count:
        parts.append(f"[yellow]{skipped_count} skipped[/yellow]")
    if errored_count:
        parts.append(f"[red]{errored_count} errors[/red]")
    console.print(f"Fix summary: {', '.join(parts) if parts else 'none'}")


def _extract_context(file_path: str, line: int, window: int = 5) -> str | None:
    """Read source file and extract lines around the finding.

    Returns the context string or None if the file can't be read.
    """
    try:
        p = Path(file_path)
        if not p.exists():
            return None
        content = p.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        start = max(0, line - 1 - window)
        end = min(len(lines), line + window)
        return "\n".join(lines[start:end])
    except Exception:
        return None


def _apply_fix(
    file_path: str,
    line: int,
    original_context: str,
    fix_diff: str,
) -> bool:
    """Apply a fix by replacing the vulnerable line by line number.

    Returns True on success, False on failure.
    """
    try:
        p = Path(file_path)
        source_lines = p.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        line_idx = line - 1
        if line_idx < 0 or line_idx >= len(source_lines):
            return False

        replacement_lines: list[str] = []
        for diff_line in fix_diff.splitlines():
            if diff_line.startswith("+++") or diff_line.startswith("---"):
                continue
            if diff_line.startswith("@@"):
                continue
            if diff_line.startswith("+"):
                replacement = diff_line[1:]
                replacement_lines.append(
                    replacement if replacement.endswith("\n") else f"{replacement}\n"
                )

        if not replacement_lines:
            return False

        source_lines[line_idx:line_idx + 1] = replacement_lines
        p.write_text("".join(source_lines), encoding="utf-8")
        return True
    except Exception:
        return False

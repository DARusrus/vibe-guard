from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from vibeguard import __version__
from vibeguard.models import Finding, ScanResult
from vibeguard.reporters import BaseReporter


class TerminalReporter(BaseReporter):
    """Rich terminal renderer for human-facing scan results."""

    def __init__(self) -> None:
        self.explain_mode: bool = False

    def render(self, result: ScanResult) -> str:
        """Capture Rich console output into a plain text string."""
        buf = StringIO()
        console = Console(file=buf, highlight=False)
        self._render_to_console(console, result)
        return buf.getvalue()

    def write(self, result: ScanResult, output_path: Path | None = None) -> None:
        """Write to file (plain text) or render directly to terminal."""
        if output_path:
            output_path.write_text(self.render(result), encoding="utf-8")
            return

        console = Console(highlight=False)
        self._render_to_console(console, result)

    def _render_to_console(self, console: Console, result: ScanResult) -> None:
        """Render all terminal sections in a fixed order."""
        self._render_header(console)
        self._render_detector_summary(console, result)
        self._render_findings(console, result)
        self._render_summary(console, result)

    def _render_header(self, console: Console) -> None:
        """Render product title and opening rule."""
        console.print(f"[bold magenta]vibe-guard v{__version__}[/bold magenta]")
        console.print("AI-aware security scanner")
        console.print(Rule())

    def _render_detector_summary(self, console: Console, result: ScanResult) -> None:
        """Render detector confidence/tier summary."""
        rows = sorted(
            (dr for dr in result.detector_results if dr.confidence > 0.0),
            key=lambda dr: dr.confidence,
            reverse=True,
        )

        if not rows:
            console.print("[dim]No files found[/dim]")
            return

        tier_styles = {
            "FULL": "bold red",
            "MEDIUM": "yellow",
            "CRITICAL_ONLY": "dim green",
        }

        table = Table(title="Detector Summary", show_lines=False)
        table.add_column("File", overflow="fold")
        table.add_column("AI Score", justify="right")
        table.add_column("Tier")

        for dr in rows:
            table.add_row(
                str(dr.file_path),
                f"{dr.confidence:.4f}",
                Text(dr.scan_tier, style=tier_styles.get(dr.scan_tier, "white")),
            )

        console.print(table)

    def _render_findings(self, console: Console, result: ScanResult) -> None:
        """Render one panel per finding in severity-first order."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        severity_style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "dim yellow",
        }

        sorted_findings = sorted(
            result.findings,
            key=lambda f: (
                severity_order.get(f.severity, 99),
                f.file_path,
                f.line,
                f.col,
            ),
        )

        for finding in sorted_findings:
            style = severity_style.get(finding.severity, "white")
            panel = Panel(
                self._render_finding_body(finding),
                title=f"[{style}] {finding.severity} [/] {finding.rule_id}",
                border_style=style,
                expand=True,
            )
            console.print(panel)

    def _render_finding_body(self, finding: Finding) -> Group:
        """Build the panel body for a finding."""
        header = (
            f"{finding.file_path}:{finding.line}:{finding.col}\n\n"
            f"{finding.message}\n\n"
            f"Fix: {finding.fix_guidance}\n\n"
            f"[dim]CWE: {finding.cwe_id}[/dim]  "
            f"[dim]AI context: {finding.ai_context}[/dim]"
        )

        renderables: list[object] = [Text.from_markup(header)]
        if finding.snippet.strip():
            renderables.append(
                Syntax(
                    finding.snippet,
                    lexer="python",
                    theme="monokai",
                    word_wrap=True,
                )
            )

        # Explain mode: add plain-English explanation
        if self.explain_mode:
            explanation = self._get_explanation(finding)
            if explanation:
                renderables.append(Text(""))
                renderables.append(
                    Text.from_markup(
                        f"[bold]What this means:[/bold]\n[italic dim]{explanation}[/italic dim]"
                    )
                )

        return Group(*renderables)

    def _get_explanation(self, finding: Finding) -> str | None:
        """Get AI explanation for a finding, falling back to fix_guidance."""
        try:
            from vibeguard.ai.explain import Explainer

            explainer = Explainer()
            result = explainer.explain(finding)
            if result is not None:
                return result
        except Exception:
            pass
        # Fall back to fix_guidance
        return finding.fix_guidance if finding.fix_guidance else None

    def _render_summary(self, console: Console, result: ScanResult) -> None:
        """Render summary panel and final status line."""
        by_severity = result.findings_by_severity()
        critical = len(by_severity.get("CRITICAL", []))
        high = len(by_severity.get("HIGH", []))
        medium = len(by_severity.get("MEDIUM", []))
        low = len(by_severity.get("LOW", []))
        total = len(result.findings)

        summary_text = (
            f"Files scanned:      {result.files_scanned}\n"
            f"AI-generated files: {result.ai_files_detected}\n"
            f"Total findings:     {total} ({critical} critical, {high} high, "
            f"{medium} medium, {low} low)\n"
            f"Duration:           {result.scan_duration_seconds:.2f}s\n"
            f"Rules applied:      {result.rules_applied}"
        )

        if result.diff_mode:
            summary_text += f"\nDiff mode:          {result.changed_files_count} changed files"

        if result.filtered_count > 0:
            summary_text += (
                f"\nSmart filter:       removed {result.filtered_count} likely false positives"
            )

        console.print(Panel(summary_text, title="Scan Complete", expand=True))

        if total == 0:
            console.print("[bold green]No findings. Your AI-generated code looks clean.[/]")
        elif critical > 0:
            console.print("[bold red]Critical issues found. Fix before merging.[/]")

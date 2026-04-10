from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table


def run_init_wizard(path: Path = Path(".")) -> None:
    """Interactive wizard that configures vibe-guard for a project."""
    console = Console()
    root = path.resolve()
    created_items: list[tuple[str, str]] = []

    config_file = root / ".vibeguard.toml"

    if config_file.exists():
        overwrite = typer.confirm(
            "A .vibeguard.toml already exists. Overwrite?",
            default=False,
        )
        if not overwrite:
            console.print("[yellow]Init cancelled. Existing config kept.[/yellow]")
            return

    min_severity = typer.prompt(
        "Minimum severity to report? [MEDIUM]:",
        default="MEDIUM",
    ).upper()
    ai_threshold = typer.prompt(
        "AI confidence threshold? [0.6]:",
        default=0.6,
        type=float,
    )
    fail_ci = typer.confirm("Fail CI on findings? [yes]:", default=True)

    _write_config_file(
        config_file, min_severity=min_severity, ai_threshold=ai_threshold, fail_ci=fail_ci
    )
    console.print("[green]✓ Created .vibeguard.toml[/green]")
    created_items.append((".vibeguard.toml", "created"))

    add_pre_commit = typer.confirm("Add vibe-guard as a pre-commit hook?", default=True)
    if add_pre_commit:
        pre_commit_file = _ensure_pre_commit(root)
        console.print("[green]✓ pre-commit hook added[/green]")
        console.print("Run: pre-commit install")
        created_items.append((str(pre_commit_file.relative_to(root)), "updated"))
    else:
        created_items.append((".pre-commit-config.yaml", "skipped"))

    add_workflow = typer.confirm("Add GitHub Actions workflow?", default=True)
    if add_workflow:
        workflow_file = _ensure_workflow(root)
        console.print("[green]✓ Created .github/workflows/vibe-guard.yml[/green]")
        created_items.append((str(workflow_file.relative_to(root)), "created"))
    else:
        created_items.append((".github/workflows/vibe-guard.yml", "skipped"))

    _print_summary(console, created_items)
    console.print("Run 'vibe-guard scan .' to start scanning.")


def _write_config_file(
    config_file: Path, min_severity: str, ai_threshold: float, fail_ci: bool
) -> None:
    """Write the main .vibeguard.toml file."""
    config_file.parent.mkdir(parents=True, exist_ok=True)
    content = (
        "[vibeguard]\n"
        f'min_severity = "{min_severity}"\n'
        f"ai_threshold = {ai_threshold}\n"
        f"fail_on_findings = {str(fail_ci).lower()}\n"
    )
    config_file.write_text(content, encoding="utf-8")


def _ensure_pre_commit(root: Path) -> Path:
    """Create or update pre-commit configuration with vibe-guard hook."""
    pre_commit_file = root / ".pre-commit-config.yaml"
    hook_block = (
        "  - repo: https://github.com/ahmbt/vibe-guard\n"
        "    rev: v0.1.0\n"
        "    hooks:\n"
        "      - id: vibe-guard\n"
    )

    if pre_commit_file.exists():
        existing = pre_commit_file.read_text(encoding="utf-8")
        if "https://github.com/ahmbt/vibe-guard" not in existing:
            content = existing.rstrip() + "\n" + hook_block
            pre_commit_file.write_text(content, encoding="utf-8")
    else:
        pre_commit_file.write_text("repos:\n" + hook_block, encoding="utf-8")

    return pre_commit_file


def _ensure_workflow(root: Path) -> Path:
    """Create the default GitHub Actions workflow for vibe-guard."""
    workflow_file = root / ".github" / "workflows" / "vibe-guard.yml"
    workflow_file.parent.mkdir(parents=True, exist_ok=True)

    workflow_file.write_text(
        "name: vibe-guard security scan\n"
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "  pull_request:\n"
        "permissions:\n"
        "  security-events: write\n"
        "  contents: read\n"
        "jobs:\n"
        "  scan:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          fetch-depth: 0\n"
        "      - uses: ahmbt/vibe-guard@v1\n"
        "        with:\n"
        "          severity: medium\n"
        "          fail-on-findings: true\n",
        encoding="utf-8",
    )
    return workflow_file


def _print_summary(console: Console, created_items: list[tuple[str, str]]) -> None:
    """Render a summary table of initialization changes."""
    table = Table(title="vibe-guard init summary")
    table.add_column("Item")
    table.add_column("Status")

    for item, status in created_items:
        table.add_row(item, status)

    console.print(table)

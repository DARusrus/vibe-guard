"""Security score calculator and badge generator.

Computes a 0–100 security score with letter grade (A–F),
generates a shields.io badge URL, and tracks score history
in a local SQLite database.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from vibeguard.models import ScanResult
from vibeguard.scanner import Scanner

logger = logging.getLogger(__name__)

# ── Score formula constants ──────────────────────────────────────

_DEDUCTIONS: dict[str, int] = {
    "CRITICAL": 25,
    "HIGH": 10,
    "MEDIUM": 3,
    "LOW": 1,
}

_GRADE_THRESHOLDS: list[tuple[int, str, str]] = [
    (90, "A", "Excellent — ship it"),
    (75, "B", "Good — minor issues"),
    (60, "C", "Acceptable — fix HIGH findings"),
    (40, "D", "Poor — fix CRITICAL findings first"),
    (0, "F", "Critical risk — do not ship"),
]

_GRADE_COLORS: dict[str, str] = {
    "A": "brightgreen",
    "B": "green",
    "C": "yellow",
    "D": "orange",
    "F": "red",
}

_HISTORY_DB = ".vibeguard-history.db"


# ── Public API ───────────────────────────────────────────────────


def calculate_score(result: ScanResult) -> tuple[int, str]:
    """Calculate the security score and letter grade.

    Formula:
        BASE_SCORE = 100
        Deductions: CRITICAL=-25, HIGH=-10, MEDIUM=-3, LOW=-1
        Bonuses: AI ratio <10% → +10, <30% → +5; no CRIT/HIGH → +5
        Final = max(0, min(100, BASE - deductions + bonuses))

    Returns:
        (score, grade) tuple.
    """
    base = 100

    # Count findings by severity
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in result.findings:
        if f.severity in counts:
            counts[f.severity] += 1

    # Deductions (uncapped)
    deductions = sum(
        counts[sev] * pts for sev, pts in _DEDUCTIONS.items()
    )

    # Bonuses
    bonuses = 0
    if result.files_scanned > 0:
        ai_ratio = result.ai_files_detected / result.files_scanned
        if ai_ratio < 0.10:
            bonuses += 10
        elif ai_ratio < 0.30:
            bonuses += 5

    if counts["CRITICAL"] == 0 and counts["HIGH"] == 0:
        bonuses += 5

    score = max(0, min(100, base - deductions + bonuses))

    # Determine grade
    grade = "F"
    for threshold, letter, _desc in _GRADE_THRESHOLDS:
        if score >= threshold:
            grade = letter
            break

    return score, grade


def generate_badge_url(grade: str, score: int) -> str:
    """Generate a shields.io badge URL for the given grade and score.

    Example: https://img.shields.io/badge/vibe--guard-A%20(94)-brightgreen
    """
    color = _GRADE_COLORS.get(grade, "lightgrey")
    return (
        f"https://img.shields.io/badge/"
        f"vibe--guard-{grade}%20({score})-{color}"
    )


def store_history(
    score: int,
    grade: str,
    result: ScanResult,
    db_path: Path | None = None,
) -> None:
    """Store a score run in the SQLite history database.

    Creates the database and table if they don't exist.
    """
    db = db_path or Path(_HISTORY_DB)
    try:
        conn = sqlite3.connect(str(db))
        conn.execute(
            """CREATE TABLE IF NOT EXISTS score_history (
                timestamp TEXT NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                findings_count INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL
            )"""
        )
        counts = _count_by_severity(result)
        conn.execute(
            """INSERT INTO score_history
               (timestamp, score, grade, findings_count,
                critical_count, high_count, medium_count, low_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(tz=timezone.utc).isoformat(),
                score,
                grade,
                len(result.findings),
                counts["CRITICAL"],
                counts["HIGH"],
                counts["MEDIUM"],
                counts["LOW"],
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        logger.debug("Failed to store score history", exc_info=True)


def get_trend(
    current_score: int,
    db_path: Path | None = None,
) -> str | None:
    """Read the last score from history and return a trend string.

    Returns None if no history exists.
    """
    db = db_path or Path(_HISTORY_DB)
    if not db.exists():
        return None
    try:
        conn = sqlite3.connect(str(db))
        cursor = conn.execute(
            """SELECT score, timestamp FROM score_history
               ORDER BY rowid DESC LIMIT 1 OFFSET 1"""
        )
        row = cursor.fetchone()
        conn.close()
        if row is None:
            return None
        prev_score, prev_ts = row
        delta = current_score - prev_score
        # Parse date for display
        try:
            dt = datetime.fromisoformat(prev_ts)
            date_str = dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            date_str = "previous scan"
        if delta > 0:
            return f"▲ +{delta} from last scan on {date_str}"
        if delta < 0:
            return f"▼ {delta} from last scan on {date_str}"
        return f"── unchanged from last scan on {date_str}"
    except Exception:
        logger.debug("Failed to read score history", exc_info=True)
        return None


def run_score(
    path: Path = Path("."),
    update_readme: bool = False,
    fail_below: int = 0,
) -> int:
    """Calculate and display the security score.

    Returns the integer score (0-100) for use in CI exit conditions.
    """
    console = Console(highlight=False)

    scanner = Scanner()
    if path.is_file():
        result = scanner.scan_file(path)
    else:
        result = scanner.scan_directory(path)

    score, grade = calculate_score(result)
    badge_url = generate_badge_url(grade, score)

    # Store and get trend
    store_history(score, grade, result)
    trend = get_trend(score)

    # Build output
    counts = _count_by_severity(result)
    breakdown_parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = counts[sev]
        if c > 0:
            pts = c * _DEDUCTIONS[sev]
            breakdown_parts.append(f"{c} {sev} (-{pts})")

    score_line = f"Score: {score} / 100   Grade: {grade}"
    if trend:
        score_line += f"  ({trend})"

    grade_desc = ""
    for threshold, letter, desc in _GRADE_THRESHOLDS:
        if grade == letter:
            grade_desc = desc
            break

    body_lines = [
        f"[bold]{score_line}[/bold]",
        "",
    ]
    if grade_desc:
        body_lines.append(f"[dim]{grade_desc}[/dim]")
        body_lines.append("")

    if breakdown_parts:
        body_lines.append("Findings breakdown:")
        body_lines.append(", ".join(breakdown_parts))
        body_lines.append("")

    body_lines.append(f"Badge URL:\n{badge_url}")
    body_lines.append("")
    body_lines.append(f"Markdown:\n![vibe-guard score]({badge_url})")

    body = "\n".join(body_lines)

    grade_style = {
        "A": "bold green",
        "B": "green",
        "C": "yellow",
        "D": "bold yellow",
        "F": "bold red",
    }.get(grade, "white")

    console.print(
        Panel(
            body,
            title=f"[{grade_style}]vibe-guard security score[/]",
            border_style=grade_style,
            expand=False,
        )
    )

    # Optionally update README.md
    if update_readme:
        _update_readme_badge(badge_url)

    return score


# ── Helpers ──────────────────────────────────────────────────────


def _count_by_severity(result: ScanResult) -> dict[str, int]:
    """Count findings by severity level."""
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in result.findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def _update_readme_badge(badge_url: str) -> None:
    """Replace existing vibe-guard badge in README.md or append it."""
    readme = Path("README.md")
    if not readme.exists():
        logger.info("No README.md found — skipping badge update")
        return

    content = readme.read_text(encoding="utf-8")
    badge_md = f"![vibe-guard score]({badge_url})"

    # Replace existing badge
    pattern = r"!\[vibe-guard score\]\(https://img\.shields\.io/badge/vibe--guard-[^)]+\)"
    if re.search(pattern, content):
        content = re.sub(pattern, badge_md, content)
    else:
        # Append after first heading
        content = content + f"\n\n{badge_md}\n"

    readme.write_text(content, encoding="utf-8")
    logger.info("Updated README.md with badge: %s", badge_url)

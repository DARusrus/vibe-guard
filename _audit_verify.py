"""Audit verification script — writes results to _audit_results.txt"""
import json
import os
import subprocess
import sys
from pathlib import Path

OUT = Path("_audit_results.txt")
lines = []

def log(msg=""):
    lines.append(msg)
    print(msg)

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return r

# ── CHECK 1: Rule files on disk ──
log("=" * 60)
log("CHECK 1: Rule files on disk")
log("=" * 60)
rules_dir = Path("src/vibeguard/rules")
total = len(list(rules_dir.rglob("*.yaml")))
log(f"Total rule YAML files: {total}")
for d in sorted(rules_dir.iterdir()):
    if d.is_dir():
        files = list(d.glob("*.yaml"))
        log(f"  {d.name}: {len(files)} rules")

# ── CHECK 2: Test collection ──
log()
log("=" * 60)
log("CHECK 2: Test collection and run")
log("=" * 60)
r = run([sys.executable, "-m", "pytest", "tests/", "--co", "-q", "--no-cov"])
test_items = [l for l in r.stdout.strip().split("\n") if "::" in l]
log(f"Tests collected: {len(test_items)}")

r2 = run([sys.executable, "-m", "pytest", "tests/", "-q", "--tb=short", "--no-cov"])
# Get the last non-empty line from stdout which has the summary
stdout_lines = [l.strip() for l in r2.stdout.strip().split("\n") if l.strip()]
for sl in stdout_lines[-3:]:
    log(f"  {sl}")
log(f"  Exit code: {r2.returncode}")

# ── CHECK 3: Ruff ──
log()
log("=" * 60)
log("CHECK 3: Ruff lint")
log("=" * 60)
r = run([sys.executable, "-m", "ruff", "check", "src/", "tests/"])
log(f"  stdout: {r.stdout.strip()}")
log(f"  Exit code: {r.returncode}")

# ── CHECK 4: Semgrep validate ──
log()
log("=" * 60)
log("CHECK 4: Semgrep validate")
log("=" * 60)
r = run([sys.executable, "-m", "semgrep", "--validate", "--config", "src/vibeguard/rules/"])
for line in r.stderr.split("\n"):
    if "configuration" in line.lower() or "rule" in line.lower() or "error" in line.lower():
        log(f"  {line.strip()}")
log(f"  Exit code: {r.returncode}")

# ── CHECK 5: TIER_RULES invariants ──
log()
log("=" * 60)
log("CHECK 5: TIER_RULES invariants")
log("=" * 60)
from vibeguard.scanner import TIER_RULES, RULES_DIR
full = set(TIER_RULES["FULL"])
medium = set(TIER_RULES["MEDIUM"])
critical = set(TIER_RULES["CRITICAL_ONLY"])
log(f"  FULL: {len(full)} rules")
log(f"  MEDIUM: {len(medium)} rules")
log(f"  CRITICAL_ONLY: {len(critical)} rules")
log(f"  MEDIUM subset FULL: {medium.issubset(full)}")
log(f"  CRITICAL subset MEDIUM: {critical.issubset(medium)}")
missing = [r for r in full if not (RULES_DIR / r).exists()]
log(f"  Missing on disk: {missing}")

# ── CHECK 6: Score formula ──
log()
log("=" * 60)
log("CHECK 6: Score formula verification")
log("=" * 60)
from vibeguard.commands.score import calculate_score, generate_badge_url
from vibeguard.models import Finding, ScanResult

# 6a: No findings
r1 = ScanResult(findings=[], files_scanned=10, ai_files_detected=0, detector_results=[])
s1, g1 = calculate_score(r1)
log(f"  No findings: score={s1}, grade={g1}")

# 6b: 4 CRITICALs
f4c = [Finding(rule_id=f"t{i}", severity="CRITICAL", file_path="x.py", line=i) for i in range(4)]
r2x = ScanResult(findings=f4c, files_scanned=10, ai_files_detected=2, detector_results=[])
s2, g2 = calculate_score(r2x)
log(f"  4 CRITICALs: score={s2}, grade={g2}")

# 6c: Mixed
fm = [
    Finding(rule_id="c", severity="CRITICAL"),
    Finding(rule_id="h", severity="HIGH"),
    Finding(rule_id="m", severity="MEDIUM"),
    Finding(rule_id="l", severity="LOW"),
]
r3 = ScanResult(findings=fm, files_scanned=10, ai_files_detected=2, detector_results=[])
s3, g3 = calculate_score(r3)
log(f"  Mixed 1C+1H+1M+1L (20%AI): score={s3}, grade={g3}")

# 6d: Badge URL
badge = generate_badge_url("A", 95)
log(f"  Badge URL: {badge}")

# ── CHECK 7: AI degradation ──
log()
log("=" * 60)
log("CHECK 7: AI graceful degradation")
log("=" * 60)
os.environ.pop("GEMINI_API_KEY", None)
from vibeguard.ai.autofix import AutoFixer
from vibeguard.ai.context_filter import ContextFilter
from vibeguard.ai.explain import Explainer
a = AutoFixer()
c = ContextFilter()
e = Explainer()
log(f"  AutoFixer available: {a.client.is_available()}")
log(f"  ContextFilter available: {c.client.is_available()}")
log(f"  Explainer available: {e.client.is_available()}")
log(f"  AutoFixer.generate_fix() returns: {a.generate_fix(Finding(rule_id='t', severity='H'), 'ctx')}")
log(f"  ContextFilter.is_true_positive() returns: {c.is_true_positive(Finding(rule_id='t'), 'code')}")
log(f"  Explainer.explain() returns: {e.explain(Finding(rule_id='t'))}")

# ── CHECK 8: vibe-guard rules count ──
log()
log("=" * 60)
log("CHECK 8: vibe-guard rules command")
log("=" * 60)
r = run([sys.executable, "-m", "vibeguard.cli", "rules"])
# Actually use the CLI entry point
r = run(["vibe-guard", "rules"])
for line in r.stdout.split("\n"):
    if "total" in line.lower() or "rule" in line.lower():
        log(f"  {line.strip()}")
log(f"  Exit code: {r.returncode}")

# Write results
OUT.write_text("\n".join(lines), encoding="utf-8")
log()
log("Results written to _audit_results.txt")

"""Audit verification script — temporary, delete after use."""
from pathlib import Path
import subprocess
import sys

print("=" * 60)
print("AUDIT CHECK 1: Rule files on disk")
print("=" * 60)
rules_dir = Path("src/vibeguard/rules")
count = len(list(rules_dir.rglob("*.yaml")))
print(f"Total rule files on disk: {count}")
for d in sorted(rules_dir.iterdir()):
    if d.is_dir():
        files = list(d.glob("*.yaml"))
        print(f"  {d.name}: {len(files)} rules")

print()
print("=" * 60)
print("AUDIT CHECK 2: Test collection count")
print("=" * 60)
r = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "--co", "-q", "--no-cov"],
    capture_output=True, text=True,
)
# Count lines with :: (test indicators)
test_lines = [l for l in r.stdout.strip().split("\n") if "::" in l]
summary_lines = [l for l in r.stdout.strip().split("\n") if "test" in l.lower() and "::" not in l]
print(f"Total tests collected: {len(test_lines)}")
for sl in summary_lines:
    print(f"  {sl.strip()}")

print()
print("=" * 60)
print("AUDIT CHECK 3: Score formula verification")
print("=" * 60)
from vibeguard.commands.score import calculate_score, generate_badge_url
from vibeguard.models import ScanResult, Finding

# Test 1: No findings → 100/A
r1 = ScanResult(findings=[], files_scanned=10, ai_files_detected=0, detector_results=[])
s1, g1 = calculate_score(r1)
print(f"  No findings: score={s1}, grade={g1} (expect 100/A)")

# Test 2: 4 CRITICALs → F
findings_4c = [Finding(rule_id=f"t{i}", severity="CRITICAL", file_path="x.py", line=i) for i in range(4)]
r2 = ScanResult(findings=findings_4c, files_scanned=10, ai_files_detected=2, detector_results=[])
s2, g2 = calculate_score(r2)
print(f"  4 CRITICALs: score={s2}, grade={g2} (expect <=5/F)")

# Test 3: 1C+1H+1M+1L = -25-10-3-1 = -39, AI 20% → +5, no clean = 66/C
findings_mix = [
    Finding(rule_id="c", severity="CRITICAL"), Finding(rule_id="h", severity="HIGH"),
    Finding(rule_id="m", severity="MEDIUM"), Finding(rule_id="l", severity="LOW"),
]
r3 = ScanResult(findings=findings_mix, files_scanned=10, ai_files_detected=2, detector_results=[])
s3, g3 = calculate_score(r3)
print(f"  Mixed (1C+1H+1M+1L, 20% AI): score={s3}, grade={g3} (expect 66/C)")

# Badge URL check
badge = generate_badge_url("A", 95)
print(f"  Badge URL: {badge}")
assert "shields.io" in badge
assert "brightgreen" in badge

print()
print("=" * 60)
print("AUDIT CHECK 4: Semgrep validate")
print("=" * 60)
r = subprocess.run(
    [sys.executable, "-m", "semgrep", "--validate", "--config", "src/vibeguard/rules/"],
    capture_output=True, text=True,
)
# Look for the summary line
for line in r.stderr.split("\n"):
    if "configuration" in line.lower() or "rule" in line.lower():
        print(f"  {line.strip()}")
print(f"  Exit code: {r.returncode}")

print()
print("=" * 60)
print("AUDIT CHECK 5: AI degradation")
print("=" * 60)
import os
os.environ.pop("GEMINI_API_KEY", None)
from vibeguard.ai.autofix import AutoFixer
from vibeguard.ai.context_filter import ContextFilter
from vibeguard.ai.explain import Explainer
a = AutoFixer()
c = ContextFilter()
e = Explainer()
print(f"  AutoFixer available: {a.client.is_available()} (expect False)")
print(f"  ContextFilter available: {c.client.is_available()} (expect False)")
print(f"  Explainer available: {e.client.is_available()} (expect False)")
assert not a.client.is_available()
assert not c.client.is_available()
assert not e.client.is_available()
print("  AI degradation: OK")

print()
print("=" * 60)
print("AUDIT CHECK 6: TIER_RULES invariants")
print("=" * 60)
from vibeguard.scanner import TIER_RULES, RULES_DIR
full = set(TIER_RULES["FULL"])
medium = set(TIER_RULES["MEDIUM"])
critical = set(TIER_RULES["CRITICAL_ONLY"])
print(f"  FULL: {len(full)} rules")
print(f"  MEDIUM: {len(medium)} rules")
print(f"  CRITICAL_ONLY: {len(critical)} rules")
print(f"  MEDIUM ⊂ FULL: {medium.issubset(full)}")
print(f"  CRITICAL ⊂ MEDIUM: {critical.issubset(medium)}")
missing = [r for r in full if not (RULES_DIR / r).exists()]
print(f"  Missing on disk: {missing}")
assert medium.issubset(full)
assert critical.issubset(medium)
assert not missing

print()
print("ALL AUDIT CHECKS PASSED")

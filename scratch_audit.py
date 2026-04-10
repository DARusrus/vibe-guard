import os
import subprocess
import tempfile
import sys

def run_cmd(cmd):
    print(f"\n=======================================================")
    print(f"--- RUNNING: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print("STDOUT:")
        print(result.stdout)
        print("STDERR:")
        print(result.stderr)
        print(f"RETURN CODE: {result.returncode}")
    except Exception as e:
        print(f"EXCEPTION: {e}")
    print("=======================================================\n")

env_dir = os.path.join(tempfile.gettempdir(), 'vg-final-audit-env')
pip_bin = os.path.join(env_dir, 'Scripts', 'pip')
vg_bin = os.path.join(env_dir, 'Scripts', 'vibe-guard')
py_bin = os.path.join(env_dir, 'Scripts', 'python')

run_cmd("pytest tests/ -v --tb=short")
run_cmd("ruff check src/ tests/")
run_cmd("semgrep --validate --config src/vibeguard/rules/ --quiet")

run_cmd(f"python -m venv {env_dir}")
run_cmd(f"{pip_bin} install . --quiet")
run_cmd(f"{pip_bin} install semgrep detect-secrets --quiet")
run_cmd(f"{vg_bin} --version")
run_cmd(f"{vg_bin} rules")

out_json = os.path.join(tempfile.gettempdir(), 'vg-audit-final.json')
run_cmd(f"{vg_bin} scan tests/fixtures/vulnerable_app --format json --output {out_json} --no-fail")

py_script_4 = f"""
import json
with open(r'{out_json}') as f:
    d = json.load(f)
print('Version:', d.get('vibe_guard_version'))
print('Files scanned:', d['summary']['files_scanned'])
print('AI files detected:', d['summary']['ai_files_detected'])
print('Total findings:', d['summary']['total_findings'])
print('Findings by severity:', d['summary']['findings_by_severity'])
print('Rules applied:', d['summary']['rules_applied'])
assert d['summary']['total_findings'] >= 8, 'Too few findings'
print('INSTALL TEST: PASS')
"""
run_cmd(f"{py_bin} -c \"{py_script_4}\"")

out_sarif = os.path.join(tempfile.gettempdir(), 'vg-audit.sarif')
run_cmd(f"{vg_bin} scan tests/fixtures/vulnerable_app --format sarif --output {out_sarif} --no-fail")

py_script_5 = f"""
import json
with open(r'{out_sarif}') as f:
    d = json.load(f)
assert d['version'] == '2.1.0'
runs = d['runs'][0]
print('Tool name:', runs['tool']['driver']['name'])
print('Rules in SARIF:', len(runs['tool']['driver']['rules']))
print('Findings in SARIF:', len(runs['results']))
for r in runs['results'][:3]:
    loc = r['locations'][0]['physicalLocation']
    uri = loc['artifactLocation']['uri']
    assert not uri.startswith('/'), f'Absolute path in SARIF: {{uri}}'
print('SARIF TEST: PASS')
"""
run_cmd(f"{py_bin} -c \"{py_script_5}\"")

run_cmd(f"{vg_bin} score tests/fixtures/vulnerable_app")
run_cmd(f"{vg_bin} scan . --diff --no-fail")

py_script_8 = """
import os
os.environ.pop('GEMINI_API_KEY', None)
from vibeguard.ai.autofix import AutoFixer
from vibeguard.ai.context_filter import ContextFilter
from vibeguard.ai.explain import Explainer
assert not AutoFixer().client.is_available()
assert not ContextFilter().client.is_available()
assert not Explainer().client.is_available()
print('AI degradation from installed package: OK')
"""
run_cmd(f"{py_bin} -c \"{py_script_8}\"")


py_script_9 = """
import os, sys
# add src to path first because we are running inside the repo
sys.path.insert(0, os.path.abspath('src'))
from vibeguard.scanner import TIER_RULES, RULES_DIR
full = set(TIER_RULES['FULL'])
medium = set(TIER_RULES['MEDIUM'])
critical = set(TIER_RULES['CRITICAL_ONLY'])
assert medium.issubset(full), f'MEDIUM not subset of FULL: {medium-full}'
assert critical.issubset(medium), f'CRITICAL_ONLY not subset of MEDIUM: {critical-medium}'
missing = [r for r in full if not (RULES_DIR/r).exists()]
print(f'FULL: {len(full)} rules')
print(f'MEDIUM: {len(medium)} rules')
print(f'CRITICAL_ONLY: {len(critical)} rules')
print(f'Missing on disk: {missing}')
assert not missing, f'Rules in TIER_RULES but not on disk: {missing}'
print('TIER INVARIANTS: PASS')
"""
run_cmd(f"{py_bin} -c \"{py_script_9}\"")

py_script_10 = """
import os, sys
sys.path.insert(0, os.path.abspath('src'))
from vibeguard.plugins.sca import SCAPlugin
p = SCAPlugin()
print('SCA available:', p.is_available())
print('Corpus path:', p.CORPUS_PATH)
print('Corpus exists:', p.CORPUS_PATH.exists())
print('OSV snapshot exists:', p.OSV_SNAPSHOT_PATH.exists())
corpus = p._load_corpus()
print('Python hallucinated packages:', len(corpus.get('python',[])))
print('NPM hallucinated packages:', len(corpus.get('npm',[])))
assert p.is_available(), 'SCA plugin reports unavailable after install'
print('DATA BUNDLING: PASS')
"""
run_cmd(f"{py_bin} -c \"{py_script_10}\"")

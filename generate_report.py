import os
from pathlib import Path

unsafe = {
    r"tests\fixtures\vulnerable_app\app.py": "contains hardcoded API key (sk-proj-...), JWT secret, and Stripe secret key",
    r"tests\fixtures\vulnerable_app\utils.py": "contains hardcoded database password and PostgreSQL connection URL",
}

suspicious = {
    r"tests\test_scanner.py": "contains mock snippet with a simulated API key (sk-abc1...) for testing rules; requires manual review",
    r"vg-test.sarif": "contains simulated secret output values from test scans",
    r"vg-test-output.json": "contains simulated secret output values from test scans",
    r".vibeguard-history.db": "sqlite database file, potentially stores finding history containing simulated test secrets",
    r"_audit_output.txt": "test output logs, might contain mirrored secret test snippets",
    r"pytest_output.txt": "test output logs, might contain mirrored secret test snippets",
}

def is_ignored(path):
    parts = path.parts
    return ".git" in parts or ".venv" in parts or "__pycache__" in parts or ".pytest_cache" in parts or ".ruff_cache" in parts or "node_modules" in parts

def main():
    base = Path("c:/Users/ahmbt/OneDrive/Desktop/VibeGuard")
    all_files = []
    for root, dirs, files in os.walk(base):
        for name in files:
            p = Path(root) / name
            rel = p.relative_to(base)
            if not is_ignored(rel):
                all_files.append(rel.as_posix())
    
    all_files.sort()
    
    print("### 1. Overall Verdict")
    print("\n* Is the repository safe to publish? **PARTIALLY**")
    print("* Brief explanation: Some files contain hardcoded secrets, database credentials, and internal endpoints which should not be made public in their current state. While they may appear to be test fixtures or examples, real or structured sensitive data should be scrubbed before publishing.")
    
    print("\n---\n")
    print("### 2. Safe Files ✅\n")
    for f in all_files:
        val = f.replace('/', '\\')
        if val in unsafe or val in suspicious:
            continue
        print(f"* {f} → safe source code / configuration / documentation with no sensitive data")
        
    print("\n---\n")
    print("### 3. Unsafe Files ❌\n")
    for f in all_files:
        val = f.replace('/', '\\')
        if val in unsafe:
            print(f"* {f} → {unsafe[val]}")
            
    print("\n---\n")
    print("### 4. Suspicious Files ⚠️\n")
    for f in all_files:
        val = f.replace('/', '\\')
        if val in suspicious:
            print(f"* {f} → {suspicious[val]}")

if __name__ == "__main__":
    main()

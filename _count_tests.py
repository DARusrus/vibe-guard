import subprocess, os, re

env = os.environ.copy()
env["NO_COLOR"] = "1"
env["TERM"] = "dumb"

r = subprocess.run(
    [r".venv\Scripts\python.exe", "-m", "pytest", "tests/", "-q", "--tb=no", "--no-cov"],
    capture_output=True,
    text=True,
    env=env,
    cwd=r"c:\Users\ahmbt\OneDrive\Desktop\VibeGuard",
)
# Combine stdout+stderr, strip ANSI
combined = r.stdout + r.stderr
clean = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', combined)
# Find the summary line
for line in clean.splitlines():
    if 'passed' in line or 'failed' in line or 'error' in line:
        print("FOUND:", line.strip())
# Also just count the dot chars
dots = clean.count('.')
s_chars = len(re.findall(r'(?<![a-zA-Z])s(?![a-zA-Z])', clean[:clean.find('[100%]')+10] if '[100%]' in clean else clean))
print(f"Exit code: {r.returncode}")
print(f"Approximate dots (passed): {dots}")
# Print last 5 lines
for line in clean.strip().splitlines()[-5:]:
    print(f"TAIL: {line}")

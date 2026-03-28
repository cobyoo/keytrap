"""Compare leak-guard vs gitleaks vs trufflehog on the same test data."""

import os
import subprocess
import tempfile
import time
from pathlib import Path


def generate_test_repo(directory: Path, num_files: int = 500, lines_per_file: int = 200):
    """Generate a git repo with realistic source files + some secrets."""
    # Init git repo (needed for gitleaks)
    subprocess.run(["git", "init"], cwd=directory, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=directory, capture_output=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=directory, capture_output=True)

    clean_content = "\n".join([
        "import os",
        "import json",
        "from pathlib import Path",
        "",
        "def process_data(input_path: str) -> dict:",
        '    """Process data from input file."""',
        "    with open(input_path) as f:",
        "        data = json.load(f)",
        "    results = {}",
        "    for key, value in data.items():",
        "        results[key] = str(value).upper()",
        "    return results",
        "",
        "class DataProcessor:",
        "    def __init__(self, config: dict):",
        "        self.config = config",
        "",
        "    def run(self):",
        "        for item in self.config.get('items', []):",
        "            print(item)",
    ])

    for i in range(num_files):
        file_path = directory / f"module_{i:04d}.py"
        lines = [clean_content]
        for j in range(lines_per_file // 20):
            lines.append(f"\ndef handler_{j}(request):")
            lines.append(f"    return {{'status': 'ok', 'id': {j}}}")
        file_path.write_text("\n".join(lines))

    # Files with secrets
    (directory / "config_leak.py").write_text("\n".join([
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        'token = "ghp_' + 'A' * 36 + '"',
        'DB = "postgres://admin:secret@prod-db:5432/main"',
        '-----BEGIN RSA PRIVATE KEY-----',
    ]))

    subprocess.run(["git", "add", "."], cwd=directory, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=directory, capture_output=True)

    total_lines = sum(
        len(f.read_text().splitlines())
        for f in directory.rglob("*.py")
    )
    return total_lines


def run_tool(name, cmd, cwd):
    start = time.perf_counter()
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    return elapsed, result


def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        num_files = 500

        print("Generating test repo (500 files)...", flush=True)
        total_lines = generate_test_repo(root, num_files=num_files)
        print(f"Total lines: {total_lines:,}\n")

        print(f"{'Tool':<20} {'Time (s)':<12} {'Lines/sec':<15} {'Findings'}")
        print("=" * 65)

        # leak-guard
        leak_guard_py = str(Path(__file__).parent / "src")
        env = os.environ.copy()
        env["PYTHONPATH"] = leak_guard_py
        elapsed, result = run_tool(
            "leak-guard",
            ["python3", "-m", "leak_guard", "--no-color", str(root)],
            cwd=root,
        )
        # Count findings from output
        findings = sum(1 for line in (result.stdout + result.stderr).splitlines() if line.strip().startswith("L"))
        print(f"{'leak-guard':<20} {elapsed:<12.3f} {total_lines / elapsed:<15,.0f} {findings}")

        # gitleaks
        elapsed, result = run_tool(
            "gitleaks",
            ["gitleaks", "detect", "--source", str(root), "--no-git", "--no-banner"],
            cwd=root,
        )
        gl_findings = result.stdout.count('"RuleID"') if result.stdout else 0
        # also check stderr
        if not gl_findings:
            gl_findings = (result.stdout + result.stderr).count("Finding")
        print(f"{'gitleaks':<20} {elapsed:<12.3f} {total_lines / elapsed:<15,.0f} {gl_findings}")

        # trufflehog (filesystem mode)
        elapsed, result = run_tool(
            "trufflehog",
            ["trufflehog", "filesystem", str(root), "--no-update", "--json"],
            cwd=root,
        )
        tf_findings = sum(1 for line in result.stdout.splitlines() if line.strip().startswith("{"))
        print(f"{'trufflehog':<20} {elapsed:<12.3f} {total_lines / elapsed:<15,.0f} {tf_findings}")


if __name__ == "__main__":
    main()

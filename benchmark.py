"""Benchmark leak-guard scanning speed."""

import tempfile
import time
from pathlib import Path

from leak_guard.patterns import get_patterns
from leak_guard.scanner import scan_content, scan_directory


def generate_test_files(directory: Path, num_files: int = 500, lines_per_file: int = 200):
    """Generate realistic-looking source files for benchmarking."""
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
        "        self.cache = {}",
        "",
        "    def run(self):",
        "        for item in self.config.get('items', []):",
        "            self.cache[item['id']] = self.process(item)",
        "",
        "    def process(self, item: dict) -> str:",
        "        return item.get('name', 'unknown')",
    ])

    for i in range(num_files):
        file_path = directory / f"module_{i:04d}.py"
        lines = [clean_content]
        for j in range(lines_per_file // 25):
            lines.append(f"\ndef handler_{j}(request):")
            lines.append(f"    return {{'status': 'ok', 'id': {j}}}")
        file_path.write_text("\n".join(lines))

    # Add a few files with secrets
    secret_file = directory / "config_leaked.py"
    secret_file.write_text("\n".join([
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        'token = "ghp_' + 'A' * 36 + '"',
        'DB = "postgres://admin:secret@prod-db:5432/main"',
    ]))


def run_benchmark():
    patterns = get_patterns()
    num_patterns = len(patterns)

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        num_files = 500
        lines_per_file = 200

        print(f"leak-guard benchmark")
        print(f"{'=' * 50}")
        print(f"Patterns loaded:  {num_patterns}")
        print(f"Test files:       {num_files}")
        print(f"Lines per file:   ~{lines_per_file}")
        print(f"Total lines:      ~{num_files * lines_per_file:,}")
        print()

        print("Generating test files...", end=" ", flush=True)
        generate_test_files(root, num_files=num_files, lines_per_file=lines_per_file)
        print("done")
        print()

        # Benchmark directory scan
        start = time.perf_counter()
        findings = scan_directory(root, patterns)
        elapsed = time.perf_counter() - start

        total_lines = sum(
            len(f.read_text().splitlines())
            for f in root.rglob("*.py")
        )

        print(f"Directory scan:")
        print(f"  Time:           {elapsed:.3f}s")
        print(f"  Files scanned:  {num_files + 1}")
        print(f"  Lines scanned:  {total_lines:,}")
        print(f"  Lines/sec:      {total_lines / elapsed:,.0f}")
        print(f"  Findings:       {len(findings)}")
        print()

        # Benchmark single content scan
        large_content = "\n".join([f"line_{i} = {i}" for i in range(10_000)])
        start = time.perf_counter()
        for _ in range(10):
            scan_content(large_content, patterns=patterns)
        elapsed = time.perf_counter() - start

        print(f"Content scan (10k lines x 10 runs):")
        print(f"  Time:           {elapsed:.3f}s")
        print(f"  Lines/sec:      {100_000 / elapsed:,.0f}")


if __name__ == "__main__":
    run_benchmark()

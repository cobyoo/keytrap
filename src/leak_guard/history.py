"""Scan git history for leaked secrets."""

import subprocess
from pathlib import Path

from .patterns import SecretPattern, get_patterns
from .scanner import Finding, scan_content


def scan_git_history(
    max_commits: int = 100,
    patterns: list[SecretPattern] | None = None,
    branch: str = "HEAD",
) -> list[Finding]:
    """Scan git commit diffs for secrets."""
    if patterns is None:
        patterns = get_patterns()

    result = subprocess.run(
        ["git", "log", f"-{max_commits}", "--pretty=format:%H", branch],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return []

    commits = result.stdout.strip().splitlines()
    findings: list[Finding] = []

    for commit_hash in commits:
        diff_result = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "-r", "-p", commit_hash],
            capture_output=True, text=True,
        )
        if diff_result.returncode != 0:
            continue

        current_file = ""
        for line in diff_result.stdout.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
            elif line.startswith("+") and not line.startswith("+++"):
                added_line = line[1:]
                line_findings = scan_content(
                    added_line,
                    filename=f"{current_file} (commit:{commit_hash[:8]})",
                    patterns=patterns,
                )
                findings.extend(line_findings)

    return findings


def scan_git_diff(
    base: str = "HEAD~1",
    head: str = "HEAD",
    patterns: list[SecretPattern] | None = None,
) -> list[Finding]:
    """Scan diff between two refs."""
    if patterns is None:
        patterns = get_patterns()

    result = subprocess.run(
        ["git", "diff", base, head],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return []

    findings: list[Finding] = []
    current_file = ""

    for line in result.stdout.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            added_line = line[1:]
            line_findings = scan_content(
                added_line,
                filename=current_file,
                patterns=patterns,
            )
            findings.extend(line_findings)

    return findings

"""Core scanning engine — fast, single-pass, zero dependencies."""

from dataclasses import dataclass
from pathlib import Path

from .patterns import SecretPattern, get_patterns

BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".zst",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pyc", ".pyo", ".so", ".dll", ".dylib", ".o", ".a",
    ".exe", ".bin", ".dat", ".img", ".iso",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".sqlite", ".db",
})

SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".next", ".nuxt", ".output",
    "vendor", ".tox", ".eggs", "*.egg-info",
    ".terraform", ".serverless",
    "coverage", ".coverage", "htmlcov",
})

INLINE_IGNORE = "leak-guard:ignore"


@dataclass(slots=True)
class Finding:
    file: str
    line_number: int
    line: str
    pattern_name: str
    severity: str
    category: str
    matched_text: str


GENERIC_CATEGORIES = frozenset({"generic"})

SEVERITY_RANK = {"high": 2, "medium": 1, "low": 0}


def dedup_line_findings(line_findings: list[Finding]) -> list[Finding]:
    """Remove generic duplicates when a specific pattern already matched the same text."""
    if len(line_findings) <= 1:
        return line_findings

    specific = [f for f in line_findings if f.category not in GENERIC_CATEGORIES]
    generic = [f for f in line_findings if f.category in GENERIC_CATEGORIES]

    if not specific:
        # All generic — keep the highest severity one per matched region
        return _dedup_by_overlap(generic)

    # Drop generic findings whose matched_text overlaps with a specific finding
    specific_texts = {f.matched_text for f in specific}
    kept_generic = [
        g for g in generic
        if not any(g.matched_text in st or st in g.matched_text for st in specific_texts)
    ]

    return specific + kept_generic


def _dedup_by_overlap(findings: list[Finding]) -> list[Finding]:
    """Among findings on the same line, keep the highest severity per overlapping match."""
    if not findings:
        return findings
    findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)
    kept: list[Finding] = []
    seen_texts: set[str] = set()
    for f in findings:
        if not any(f.matched_text in s or s in f.matched_text for s in seen_texts):
            kept.append(f)
            seen_texts.add(f.matched_text)
    return kept


def is_binary(path: Path) -> bool:
    return path.suffix.lower() in BINARY_EXTENSIONS


def scan_content(
    content: str,
    filename: str = "<stdin>",
    patterns: list[SecretPattern] | None = None,
    allowlist: set[str] | None = None,
) -> list[Finding]:
    if patterns is None:
        patterns = get_patterns()

    findings: list[Finding] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        if INLINE_IGNORE in line:
            continue

        line_findings: list[Finding] = []
        for pat in patterns:
            match = pat.pattern.search(line)
            if match:
                matched = match.group(0)
                if allowlist and matched in allowlist:
                    continue
                line_findings.append(Finding(
                    file=filename,
                    line_number=line_number,
                    line=line.rstrip(),
                    pattern_name=pat.name,
                    severity=pat.severity,
                    category=pat.category,
                    matched_text=matched,
                ))

        findings.extend(dedup_line_findings(line_findings))

    return findings


def scan_file(
    path: Path,
    patterns: list[SecretPattern] | None = None,
    allowlist: set[str] | None = None,
) -> list[Finding]:
    if is_binary(path):
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return []

    return scan_content(content, filename=str(path), patterns=patterns, allowlist=allowlist)


def scan_directory(
    root: Path,
    patterns: list[SecretPattern] | None = None,
    allowlist: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    for path in root.rglob("*"):
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if path.is_file() and not is_binary(path):
            findings.extend(scan_file(path, patterns, allowlist))

    return findings


def scan_staged_files(
    patterns: list[SecretPattern] | None = None,
    allowlist: set[str] | None = None,
) -> list[Finding]:
    """Scan git staged files only (for pre-commit hook)."""
    import subprocess

    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return []

    findings: list[Finding] = []
    for filename in result.stdout.strip().splitlines():
        if not filename:
            continue
        path = Path(filename)
        if path.exists():
            findings.extend(scan_file(path, patterns, allowlist))

    return findings

"""Output formatting for scan results."""

import json
import sys
from .scanner import Finding

SEVERITY_COLORS = {
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def report_text(findings: list[Finding], use_color: bool = True) -> str:
    if not findings:
        return ""

    lines: list[str] = []
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.file, []).append(f)

    for filepath, file_findings in grouped.items():
        if use_color:
            lines.append(f"\n{BOLD}{filepath}{RESET}")
        else:
            lines.append(f"\n{filepath}")

        for f in file_findings:
            color = SEVERITY_COLORS.get(f.severity, "") if use_color else ""
            reset = RESET if use_color else ""
            dim = DIM if use_color else ""
            severity_label = f"[{f.severity.upper()}]"
            category_label = f"({f.category})"
            lines.append(
                f"  L{f.line_number}: {color}{severity_label}{reset} {f.pattern_name} {dim}{category_label}{reset}"
            )
            masked_line = f.line.replace(f.matched_text, "***REDACTED***")
            lines.append(f"    {masked_line.strip()}")

    return "\n".join(lines)


def report_json(findings: list[Finding]) -> str:
    return json.dumps(
        [
            {
                "file": f.file,
                "line": f.line_number,
                "severity": f.severity,
                "category": f.category,
                "pattern": f.pattern_name,
                "content": f.line.replace(f.matched_text, "***REDACTED***"),
            }
            for f in findings
        ],
        indent=2,
        ensure_ascii=False,
    )


def report_sarif(findings: list[Finding]) -> str:
    """SARIF 2.1.0 output for GitHub Advanced Security integration."""
    rules = {}
    results = []

    for f in findings:
        rule_id = f.pattern_name.lower().replace(" ", "-")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f.pattern_name},
                "defaultConfiguration": {
                    "level": "error" if f.severity == "high" else "warning",
                },
            }

        results.append({
            "ruleId": rule_id,
            "message": {"text": f"Potential secret detected: {f.pattern_name}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line_number},
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "leak-guard",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def print_summary(findings: list[Finding], use_color: bool = True) -> None:
    total = len(findings)
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")

    if total == 0:
        print("\n\u2705 No secrets detected.")
    else:
        print(f"\n\u26a0\ufe0f  {total} potential secret(s) found: "
              f"{high} high, {medium} medium, {low} low")
        sys.exit(1)

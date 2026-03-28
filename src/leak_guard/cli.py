"""Command-line interface for leak-guard."""

import argparse
import sys
from pathlib import Path

from .patterns import get_patterns, CATEGORIES
from .scanner import scan_directory, scan_file, scan_staged_files
from .reporter import report_text, report_json, report_sarif, print_summary
from .custom import find_config, load_custom_patterns, load_allowlist


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leak-guard",
        description="Fast, lightweight, extensible secret detection. Zero dependencies.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="file or directory to scan (default: .)",
    )
    parser.add_argument(
        "--pre-commit",
        action="store_true",
        help="scan only git staged files",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "sarif"],
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable colored output",
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["high", "medium", "low"],
        default=None,
        help="minimum severity to report",
    )
    parser.add_argument(
        "--category", "-c",
        choices=list(CATEGORIES.keys()),
        action="append",
        help="only scan specific categories (can repeat)",
    )
    parser.add_argument(
        "--exclude-category",
        action="append",
        help="exclude specific categories (can repeat)",
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help="list available pattern categories and exit",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="path to .leakguard.yml config file",
    )
    return parser


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_categories:
        for name, pats in CATEGORIES.items():
            print(f"  {name:15s}  ({len(pats)} patterns)")
        return

    # Load patterns
    patterns = get_patterns(
        categories=args.category,
        exclude_categories=args.exclude_category,
    )

    # Load custom config
    config_path = args.config or find_config()
    allowlist: set[str] = set()
    if config_path and config_path.exists():
        patterns = patterns + load_custom_patterns(config_path)
        allowlist = load_allowlist(config_path)

    # Scan
    if args.pre_commit:
        findings = scan_staged_files(patterns, allowlist)
    else:
        target = Path(args.path)
        if target.is_file():
            findings = scan_file(target, patterns, allowlist)
        elif target.is_dir():
            findings = scan_directory(target, patterns, allowlist)
        else:
            print(f"Error: {args.path} not found", file=sys.stderr)
            sys.exit(2)

    # Filter by severity
    if args.severity:
        min_level = SEVERITY_ORDER[args.severity]
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= min_level]

    # Output
    use_color = not args.no_color and sys.stdout.isatty()

    if args.format == "json":
        print(report_json(findings))
    elif args.format == "sarif":
        print(report_sarif(findings))
    else:
        output = report_text(findings, use_color=use_color)
        if output:
            print(output)

    print_summary(findings, use_color=use_color)

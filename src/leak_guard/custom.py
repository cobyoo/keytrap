"""Load custom patterns from .leakguard.yml files."""

import re
from pathlib import Path

from .patterns import SecretPattern

try:
    # PyYAML is optional — custom patterns only work if installed
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


DEFAULT_CONFIG_NAME = ".leakguard.yml"


def find_config(start: Path | None = None) -> Path | None:
    current = start or Path.cwd()
    for directory in [current, *current.parents]:
        config = directory / DEFAULT_CONFIG_NAME
        if config.is_file():
            return config
    return None


def load_custom_patterns(config_path: Path) -> list[SecretPattern]:
    if not HAS_YAML:
        return []

    try:
        data = yaml.safe_load(config_path.read_text())
    except Exception:
        return []

    if not data or "patterns" not in data:
        return []

    patterns: list[SecretPattern] = []
    for entry in data["patterns"]:
        name = entry.get("name", "Custom Pattern")
        regex = entry.get("pattern", "")
        severity = entry.get("severity", "medium")
        category = entry.get("category", "custom")
        if regex:
            try:
                compiled = re.compile(regex, re.IGNORECASE if entry.get("ignorecase", False) else 0)
                patterns.append(SecretPattern(name, compiled, severity, category))
            except re.error:
                continue

    return patterns


def load_allowlist(config_path: Path) -> set[str]:
    if not HAS_YAML:
        return set()

    try:
        data = yaml.safe_load(config_path.read_text())
    except Exception:
        return set()

    if not data:
        return set()

    return set(data.get("allowlist", []))

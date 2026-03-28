# leak-guard

> Fast, lightweight, extensible secret detection. Zero dependencies.

Catch leaked API keys, tokens, and credentials **before** they reach your repository. Built for speed and simplicity — works out of the box with 60+ patterns across 11 categories.

## Why leak-guard?

| | **leak-guard** | gitleaks | trufflehog |
|---|---|---|---|
| Language | Pure Python | Go | Python |
| Dependencies | **0** | - | Many |
| Setup | `pip install leak-guard` | Binary download | pip + extras |
| Custom patterns | **YAML — one line** | TOML config | Complex |
| Regional support | **Built-in plugins** | Global only | Global only |
| SARIF output | Yes | Yes | No |
| Extensible | **Category-based** | Flat list | Detectors |

## Installation

```bash
pip install leak-guard
```

## Quick Start

```bash
# Scan current directory
leak-guard .

# Scan a specific file
leak-guard src/config.py

# Only high severity
leak-guard --severity high .

# JSON output for CI/CD
leak-guard --format json .

# SARIF output for GitHub Advanced Security
leak-guard --format sarif . > results.sarif
```

## Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/cobyoo/leak-guard
    rev: v0.2.0
    hooks:
      - id: leak-guard
```

## Pattern Categories

```bash
leak-guard --list-categories
```

| Category | Examples | Count |
|----------|----------|-------|
| `cloud` | AWS, GCP, Azure, DigitalOcean, Heroku, Vercel, Supabase, Firebase | 14 |
| `vcs` | GitHub, GitLab, Bitbucket, npm, PyPI, RubyGems | 7 |
| `payments` | Stripe, PayPal, Square | 5 |
| `messaging` | Slack, Discord, Telegram, Twilio, SendGrid, Mailgun | 9 |
| `databases` | PostgreSQL, MySQL, MongoDB, Redis connection strings | 2 |
| `ci_cd` | CircleCI, Travis CI, Jenkins | 3 |
| `identity` | Auth0, Okta, JWT, OAuth | 4 |
| `crypto` | Private keys (RSA, EC, DSA, PGP, OpenSSH) | 2 |
| `ai_ml` | OpenAI, Anthropic, HuggingFace, Replicate, Cohere | 6 |
| `generic` | API keys, passwords, tokens, base64 private keys | 3 |
| `regional_kr` | Kakao, Naver, Toss, PortOne | 5 |

### Scan specific categories only

```bash
# Only check cloud and payments
leak-guard --category cloud --category payments .

# Exclude regional patterns
leak-guard --exclude-category regional_kr .
```

## Custom Patterns

Create `.leakguard.yml` in your project root:

```yaml
patterns:
  - name: "Internal Service Token"
    pattern: "MYCO_[A-Z0-9]{32}"
    severity: high
    category: custom

  - name: "Internal DB Password"
    pattern: "db_pass_[a-zA-Z0-9]{16,}"
    severity: high
    ignorecase: true

allowlist:
  - "EXAMPLE_KEY_FOR_DOCS"
  - "test_token_placeholder"
```

## Inline Ignore

Suppress a specific line:

```python
api_key = "not-a-real-key"  # leak-guard:ignore
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Secret Scan
  run: |
    pip install leak-guard
    leak-guard --format sarif . > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
secret-scan:
  script:
    - pip install leak-guard
    - leak-guard --format json . > gl-secret-detection-report.json
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json
```

## Output Formats

**Text** (default) — human-readable with colors and redaction

**JSON** — structured output for automation

**SARIF** — GitHub Advanced Security / code scanning integration

## Contributing

Contributions welcome! Especially:
- New service patterns (open a PR with test cases)
- Regional pattern plugins
- Performance improvements

## License

MIT

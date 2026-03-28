"""Built-in secret detection patterns.

Organized by category: cloud, vcs, payments, messaging, databases,
ci_cd, identity, crypto, generic, and regional extensions.
"""

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern
    severity: str  # "high", "medium", "low"
    category: str = "generic"


# ── Cloud Providers ──────────────────────────────────────────────

CLOUD = [
    SecretPattern("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "high", "cloud"),
    SecretPattern("AWS Secret Access Key", re.compile(r"""(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""", re.I), "high", "cloud"),
    SecretPattern("AWS Session Token", re.compile(r"""(?:aws_session_token)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?""", re.I), "high", "cloud"),
    SecretPattern("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "high", "cloud"),
    SecretPattern("Google OAuth Client Secret", re.compile(r"""client_secret.*?['"](GOCSPX-[A-Za-z0-9_-]{28})['"]"""), "high", "cloud"),
    SecretPattern("Google Service Account Key", re.compile(r'"type"\s*:\s*"service_account"'), "high", "cloud"),
    SecretPattern("Azure Storage Key", re.compile(r"""(?:AccountKey|azure_storage_key)\s*[=:]\s*['"]?([A-Za-z0-9+/=]{88})['"]?""", re.I), "high", "cloud"),
    SecretPattern("Azure Client Secret", re.compile(r"""(?:AZURE_CLIENT_SECRET|azure_secret)\s*[=:]\s*['"]?([A-Za-z0-9_.\-~]{34,})['"]?""", re.I), "high", "cloud"),
    SecretPattern("DigitalOcean Token", re.compile(r"dop_v1_[a-f0-9]{64}"), "high", "cloud"),
    SecretPattern("Heroku API Key", re.compile(r"""(?:HEROKU_API_KEY|heroku.*api.*key)\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?""", re.I), "high", "cloud"),
    SecretPattern("Cloudflare API Token", re.compile(r"""(?:CF_API_TOKEN|cloudflare.*token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40})['"]?""", re.I), "high", "cloud"),
    SecretPattern("Supabase Service Key", re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}"), "high", "cloud"),
    SecretPattern("Firebase API Key", re.compile(r"""(?:FIREBASE_API_KEY|firebase.*key)\s*[=:]\s*['"]?(AIza[0-9A-Za-z_-]{35})['"]?""", re.I), "high", "cloud"),
    SecretPattern("Vercel Token", re.compile(r"""(?:VERCEL_TOKEN|vercel.*token)\s*[=:]\s*['"]?([A-Za-z0-9]{24})['"]?""", re.I), "medium", "cloud"),
]

# ── Version Control & Dev Platforms ──────────────────────────────

VCS = [
    SecretPattern("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), "high", "vcs"),
    SecretPattern("GitHub Fine-grained Token", re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"), "high", "vcs"),
    SecretPattern("GitLab Token", re.compile(r"glpat-[A-Za-z0-9\-]{20,}"), "high", "vcs"),
    SecretPattern("Bitbucket App Password", re.compile(r"""(?:BITBUCKET_APP_PASSWORD|bitbucket.*password)\s*[=:]\s*['"]?([A-Za-z0-9]{18,})['"]?""", re.I), "high", "vcs"),
    SecretPattern("npm Token", re.compile(r"npm_[A-Za-z0-9]{36}"), "high", "vcs"),
    SecretPattern("PyPI Token", re.compile(r"pypi-[A-Za-z0-9_-]{50,}"), "high", "vcs"),
    SecretPattern("RubyGems API Key", re.compile(r"rubygems_[a-f0-9]{48}"), "high", "vcs"),
]

# ── Payments ─────────────────────────────────────────────────────

PAYMENTS = [
    SecretPattern("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "high", "payments"),
    SecretPattern("Stripe Restricted Key", re.compile(r"rk_live_[0-9a-zA-Z]{24,}"), "high", "payments"),
    SecretPattern("PayPal Client Secret", re.compile(r"""(?:PAYPAL_SECRET|paypal.*secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?""", re.I), "high", "payments"),
    SecretPattern("Square Access Token", re.compile(r"sq0atp-[A-Za-z0-9_-]{22}"), "high", "payments"),
    SecretPattern("Square OAuth Secret", re.compile(r"sq0csp-[A-Za-z0-9_-]{43}"), "high", "payments"),
]

# ── Messaging & Communication ────────────────────────────────────

MESSAGING = [
    SecretPattern("Slack Bot Token", re.compile(r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"), "high", "messaging"),
    SecretPattern("Slack User Token", re.compile(r"xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"), "high", "messaging"),
    SecretPattern("Slack Webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"), "high", "messaging"),
    SecretPattern("Discord Bot Token", re.compile(r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"), "high", "messaging"),
    SecretPattern("Discord Webhook URL", re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"), "high", "messaging"),
    SecretPattern("Telegram Bot Token", re.compile(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}"), "high", "messaging"),
    SecretPattern("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), "high", "messaging"),
    SecretPattern("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), "high", "messaging"),
    SecretPattern("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), "high", "messaging"),
]

# ── Databases ────────────────────────────────────────────────────

DATABASES = [
    SecretPattern("Database Connection String", re.compile(r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s'\"]{10,}"), "high", "databases"),
    SecretPattern("MongoDB SRV", re.compile(r"mongodb\+srv://[^\s'\"]{10,}"), "high", "databases"),
]

# ── CI/CD ────────────────────────────────────────────────────────

CI_CD = [
    SecretPattern("CircleCI Token", re.compile(r"""(?:CIRCLECI_TOKEN|circle.*token)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?""", re.I), "high", "ci_cd"),
    SecretPattern("Travis CI Token", re.compile(r"""(?:TRAVIS_TOKEN|travis.*token)\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?""", re.I), "high", "ci_cd"),
    SecretPattern("Jenkins API Token", re.compile(r"""(?:JENKINS_TOKEN|jenkins.*token)\s*[=:]\s*['"]?([A-Fa-f0-9]{32,})['"]?""", re.I), "high", "ci_cd"),
]

# ── Identity & Auth ──────────────────────────────────────────────

IDENTITY = [
    SecretPattern("Auth0 Client Secret", re.compile(r"""(?:AUTH0_CLIENT_SECRET|auth0.*secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{32,})['"]?""", re.I), "high", "identity"),
    SecretPattern("Okta API Token", re.compile(r"""(?:OKTA_TOKEN|okta.*token)\s*[=:]\s*['"]?([0-9a-zA-Z_-]{42})['"]?""", re.I), "high", "identity"),
    SecretPattern("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}"), "high", "identity"),
    SecretPattern("OAuth Client Secret", re.compile(r"""(?:client_secret)\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"]""", re.I), "medium", "identity"),
]

# ── Crypto & Keys ────────────────────────────────────────────────

CRYPTO = [
    SecretPattern("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "high", "crypto"),
    SecretPattern("PGP Private Key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "high", "crypto"),
]

# ── AI & ML ──────────────────────────────────────────────────────

AI_ML = [
    SecretPattern("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"), "high", "ai_ml"),
    SecretPattern("OpenAI Project Key", re.compile(r"sk-proj-[A-Za-z0-9_-]{40,}"), "high", "ai_ml"),
    SecretPattern("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_-]{40,}"), "high", "ai_ml"),
    SecretPattern("HuggingFace Token", re.compile(r"hf_[A-Za-z0-9]{34,}"), "high", "ai_ml"),
    SecretPattern("Replicate API Token", re.compile(r"r8_[A-Za-z0-9]{36,}"), "high", "ai_ml"),
    SecretPattern("Cohere API Key", re.compile(r"""(?:COHERE_API_KEY|cohere.*key)\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?""", re.I), "high", "ai_ml"),
]

# ── Generic ──────────────────────────────────────────────────────

GENERIC = [
    SecretPattern("Generic API Key", re.compile(r"""(?:api_key|apikey|api[-_]?secret)\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"]""", re.I), "medium", "generic"),
    SecretPattern("Generic Secret", re.compile(r"""(?:secret|password|passwd|pwd|token)\s*[=:]\s*['"]([^\s'"]{8,})['"]""", re.I), "medium", "generic"),
    SecretPattern("Encoded Private Key (base64)", re.compile(r"""(?:PRIVATE_KEY|private_key)\s*[=:]\s*['"]([A-Za-z0-9+/=]{100,})['"]""", re.I), "high", "generic"),
]

# ── Regional: Korea ──────────────────────────────────────────────

REGIONAL_KR = [
    SecretPattern("Kakao REST API Key", re.compile(r"""(?:kakao|KAKAO)[\w_]*(?:api[_-]?key|rest[_-]?key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?""", re.I), "high", "regional_kr"),
    SecretPattern("Kakao Admin Key", re.compile(r"""(?:kakao|KAKAO)[\w_]*admin[_-]?key\s*[=:]\s*['"]?([a-f0-9]{32})['"]?""", re.I), "high", "regional_kr"),
    SecretPattern("Naver Client Secret", re.compile(r"""(?:naver|NAVER)[\w_]*client[_-]?secret\s*[=:]\s*['"]?([A-Za-z0-9_]{10,})['"]?""", re.I), "high", "regional_kr"),
    SecretPattern("Toss Payments Secret Key", re.compile(r"""(?:toss|TOSS)[\w_]*secret[_-]?key\s*[=:]\s*['"]?(test_sk_|live_sk_)[A-Za-z0-9]{20,}['"]?""", re.I), "high", "regional_kr"),
    SecretPattern("PortOne (Iamport) Key", re.compile(r"""(?:iamport|imp|portone|PORTONE)[\w_]*(?:key|secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?""", re.I), "high", "regional_kr"),
]

# ── All built-in patterns ────────────────────────────────────────

BUILTIN_PATTERNS = (
    CLOUD + VCS + PAYMENTS + MESSAGING + DATABASES
    + CI_CD + IDENTITY + CRYPTO + AI_ML + GENERIC + REGIONAL_KR
)

CATEGORIES = {
    "cloud": CLOUD,
    "vcs": VCS,
    "payments": PAYMENTS,
    "messaging": MESSAGING,
    "databases": DATABASES,
    "ci_cd": CI_CD,
    "identity": IDENTITY,
    "crypto": CRYPTO,
    "ai_ml": AI_ML,
    "generic": GENERIC,
    "regional_kr": REGIONAL_KR,
}


def get_patterns(
    categories: list[str] | None = None,
    exclude_categories: list[str] | None = None,
) -> list[SecretPattern]:
    if categories:
        return [p for cat in categories if cat in CATEGORIES for p in CATEGORIES[cat]]

    patterns = list(BUILTIN_PATTERNS)
    if exclude_categories:
        excluded = set(exclude_categories)
        patterns = [p for p in patterns if p.category not in excluded]

    return patterns

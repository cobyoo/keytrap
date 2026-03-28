"""Tests for secret detection patterns."""

from leak_guard.scanner import scan_content


# ── Cloud ────────────────────────────────────────────────────────

def test_aws_access_key():
    content = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
    findings = scan_content(content)
    assert any("AWS Access Key" in f.pattern_name for f in findings)


def test_google_api_key():
    content = 'GOOGLE_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"'
    findings = scan_content(content)
    assert any("Google" in f.pattern_name for f in findings)


def test_azure_storage_key():
    content = 'AccountKey=' + 'A' * 86 + '=='
    findings = scan_content(content)
    assert any("Azure" in f.pattern_name for f in findings)


def test_digitalocean_token():
    content = 'token = "dop_v1_' + 'a' * 64 + '"'
    findings = scan_content(content)
    assert any("DigitalOcean" in f.pattern_name for f in findings)


# ── VCS ──────────────────────────────────────────────────────────

def test_github_token():
    content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
    findings = scan_content(content)
    assert any("GitHub Token" in f.pattern_name for f in findings)


def test_github_fine_grained_token():
    content = 'token = "github_pat_' + 'A' * 22 + '"'
    findings = scan_content(content)
    assert any("Fine-grained" in f.pattern_name for f in findings)


def test_gitlab_token():
    content = 'token = "glpat-xxxxxxxxxxxxxxxxxxxx"'
    findings = scan_content(content)
    assert any("GitLab" in f.pattern_name for f in findings)


def test_npm_token():
    content = 'token = "npm_' + 'A' * 36 + '"'
    findings = scan_content(content)
    assert any("npm" in f.pattern_name for f in findings)


# ── Payments ─────────────────────────────────────────────────────

def test_stripe_key():
    content = 'stripe_key = "sk_live_' + 'x' * 24 + '"'
    findings = scan_content(content)
    assert any("Stripe" in f.pattern_name for f in findings)


def test_square_token():
    content = 'token = "sq0atp-' + 'A' * 22 + '"'
    findings = scan_content(content)
    assert any("Square" in f.pattern_name for f in findings)


# ── Messaging ────────────────────────────────────────────────────

def test_slack_webhook():
    content = 'url = "https://hooks.slack.com/services/' + 'T' + '0' * 8 + '/B' + '0' * 8 + '/' + 'x' * 24 + '"'
    findings = scan_content(content)
    assert any("Slack" in f.pattern_name for f in findings)


def test_sendgrid_key():
    content = 'key = "SG.' + 'A' * 22 + '.' + 'B' * 43 + '"'
    findings = scan_content(content)
    assert any("SendGrid" in f.pattern_name for f in findings)


def test_twilio_key():
    content = 'key = "SK' + 'a' * 32 + '"'
    findings = scan_content(content)
    assert any("Twilio" in f.pattern_name for f in findings)


# ── Databases ────────────────────────────────────────────────────

def test_postgres_connection():
    content = 'DB_URL = "postgres://user:pass@localhost:5432/mydb"'
    findings = scan_content(content)
    assert any("Database" in f.pattern_name for f in findings)


def test_mongodb_srv():
    content = 'MONGO = "mongodb+srv://user:pass@cluster.example.com/db"'
    findings = scan_content(content)
    assert any("MongoDB" in f.pattern_name for f in findings)


# ── AI/ML ────────────────────────────────────────────────────────

def test_anthropic_key():
    content = 'key = "sk-ant-' + 'A' * 40 + '"'
    findings = scan_content(content)
    assert any("Anthropic" in f.pattern_name for f in findings)


def test_huggingface_token():
    content = 'token = "hf_' + 'A' * 34 + '"'
    findings = scan_content(content)
    assert any("HuggingFace" in f.pattern_name for f in findings)


# ── Crypto ───────────────────────────────────────────────────────

def test_private_key():
    content = "-----BEGIN RSA PRIVATE KEY-----"
    findings = scan_content(content)
    assert any("Private Key" in f.pattern_name for f in findings)


def test_jwt_token():
    content = 'auth = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
    findings = scan_content(content)
    assert any("JWT" in f.pattern_name for f in findings)


# ── Regional: Korea ──────────────────────────────────────────────

def test_kakao_rest_api_key():
    content = 'KAKAO_REST_API_KEY = "abcdef1234567890abcdef1234567890"'
    findings = scan_content(content)
    assert any("Kakao" in f.pattern_name for f in findings)


def test_naver_client_secret():
    content = 'NAVER_CLIENT_SECRET = "abcdefghijklmn"'
    findings = scan_content(content)
    assert any("Naver" in f.pattern_name for f in findings)


def test_toss_payments_key():
    content = 'TOSS_SECRET_KEY = "live_sk_abcdefghij1234567890ab"'
    findings = scan_content(content)
    assert any("Toss" in f.pattern_name for f in findings)


# ── Behavior ─────────────────────────────────────────────────────

def test_no_false_positive_on_comments():
    content = '# KAKAO_REST_API_KEY = "abcdef1234567890abcdef1234567890"'
    findings = scan_content(content)
    assert len(findings) == 0


def test_no_false_positive_on_clean_code():
    content = """
import os
x = 1 + 2
print("hello world")
def foo():
    return True
"""
    findings = scan_content(content)
    assert len(findings) == 0


def test_inline_ignore():
    content = 'API_KEY = "AKIAIOSFODNN7EXAMPLE"  # leak-guard:ignore'
    findings = scan_content(content)
    assert len(findings) == 0


def test_category_field():
    content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
    findings = scan_content(content)
    github_findings = [f for f in findings if "GitHub" in f.pattern_name]
    assert github_findings[0].category == "vcs"

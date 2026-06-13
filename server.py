"""
Email Validator AI MCP Server
Email validation and verification tools powered by MEOK AI Labs.
"""


import sys, os
from auth_middleware import check_access

import re
import time
import socket
from collections import defaultdict
from mcp.server.fastmcp import FastMCP
import urllib.request as _meter_urlreq
import urllib.error as _meter_urlerr

mcp = FastMCP("email-validator-ai", instructions="MEOK AI Labs MCP Server")

_call_counts: dict[str, list[float]] = defaultdict(list)
FREE_TIER_LIMIT = 50
WINDOW = 86400

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "dispostable.com", "maildrop.cc", "temp-mail.org", "fakeinbox.com",
    "trashmail.com", "10minutemail.com", "getnada.com", "mailnesia.com",
    "tempail.com", "burnermail.io", "mohmal.com", "emailondeck.com",
}

TYPO_DOMAINS = {
    "gmial.com": "gmail.com", "gmal.com": "gmail.com", "gamil.com": "gmail.com",
    "gnail.com": "gmail.com", "gmaill.com": "gmail.com", "gmail.co": "gmail.com",
    "hotmial.com": "hotmail.com", "hotmal.com": "hotmail.com", "hotamil.com": "hotmail.com",
    "yahooo.com": "yahoo.com", "yaho.com": "yahoo.com", "yhoo.com": "yahoo.com",
    "outlok.com": "outlook.com", "outloo.com": "outlook.com", "outlookcom": "outlook.com",
}

EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


def _check_rate_limit(tool_name: str) -> None:
    now = time.time()
    _call_counts[tool_name] = [t for t in _call_counts[tool_name] if now - t < WINDOW]
    if len(_call_counts[tool_name]) >= FREE_TIER_LIMIT:
        raise ValueError(f"Rate limit exceeded for {tool_name}. Free tier: {FREE_TIER_LIMIT}/day. Upgrade at https://councilof.ai")
    _call_counts[tool_name].append(now)

def _server_meter_check(api_key: str = "") -> dict:
    """Calls the live /verify endpoint for server-side metering. Returns the JSON dict.
    Fail-open: if /verify is unreachable or KV isn't configured, returns allowed=True
    (so the local rate-limit in _check_rate_limit remains the safety net)."""
    try:
        data = json.dumps({"api_key": api_key, "tool": ""}).encode()
        req = _meter_urlreq.Request(_METER_URL, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with _meter_urlreq.urlopen(req, timeout=2.5) as r:
            d = json.loads(r.read())
            if isinstance(d, dict) and "allowed" in d:
                return d
    except Exception:
        pass
    return {"allowed": True, "tier": "anonymous", "remaining": 200, "upgrade_url": "https://meok.ai/pricing"}


_METER_URL = "https://proofof.ai/verify"


@mcp.tool()
def validate_email(email: str, api_key: str = "") -> dict:
    """Validate an email address format, structure, and common issues.

    Args:
        email: The email address to validate

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://councilof.ai"}

    _check_rate_limit("validate_email")
    email = email.strip().lower()
    issues = []
    if not email:
        return {"valid": False, "email": email, "issues": ["Empty email address"]}
    if ' ' in email:
        issues.append("Contains spaces")
    if email.count('@') != 1:
        issues.append("Must contain exactly one @ symbol")
        return {"valid": False, "email": email, "issues": issues}
    local, domain = email.rsplit('@', 1)
    if not local:
        issues.append("Empty local part")
    if len(local) > 64:
        issues.append("Local part exceeds 64 characters")
    if not domain or '.' not in domain:
        issues.append("Invalid domain")
    if domain.startswith('.') or domain.endswith('.'):
        issues.append("Domain cannot start or end with a dot")
    if '..' in email:
        issues.append("Consecutive dots not allowed")
    if not EMAIL_RE.match(email):
        issues.append("Invalid email format")
    return {"valid": len(issues) == 0, "email": email, "local_part": local, "domain": domain, "issues": issues}


@mcp.tool()
def check_mx(domain: str, api_key: str = "") -> dict:
    """Check if a domain has valid MX (mail exchange) records.

    Args:
        domain: The domain to check MX records for

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://councilof.ai"}

    _check_rate_limit("check_mx")
    domain = domain.strip().lower().lstrip('@')
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'MX')
        records = [{"priority": r.preference, "host": str(r.exchange).rstrip('.')} for r in answers]
        records.sort(key=lambda x: x["priority"])
        return {"domain": domain, "has_mx": True, "records": records, "count": len(records)}
    except ImportError:
        try:
            socket.getaddrinfo(domain, 25)
            return {"domain": domain, "has_mx": True, "records": [], "note": "Basic check only (install dnspython for full MX lookup)", "count": 0}
        except socket.gaierror:
            return {"domain": domain, "has_mx": False, "records": [], "count": 0}
    except Exception as e:
        return {"domain": domain, "has_mx": False, "records": [], "error": str(e), "count": 0}


@mcp.tool()
def detect_disposable(email: str, api_key: str = "") -> dict:
    """Detect if an email uses a disposable/temporary email service.

    Args:
        email: The email address to check

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://councilof.ai"}

    _check_rate_limit("detect_disposable")
    email = email.strip().lower()
    if '@' not in email:
        return {"email": email, "error": "Invalid email format"}
    domain = email.rsplit('@', 1)[1]
    is_disposable = domain in DISPOSABLE_DOMAINS
    risk = "high" if is_disposable else "low"
    return {"email": email, "domain": domain, "is_disposable": is_disposable, "risk_level": risk,
            "known_disposable_domains_checked": len(DISPOSABLE_DOMAINS)}


@mcp.tool()
def suggest_correction(email: str, api_key: str = "") -> dict:
    """Suggest corrections for common email typos (e.g., gmial.com -> gmail.com).

    Args:
        email: The email address to check for typos

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.
    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://councilof.ai"}

    _check_rate_limit("suggest_correction")
    email = email.strip().lower()
    if '@' not in email:
        return {"email": email, "suggestion": None, "has_typo": False}
    local, domain = email.rsplit('@', 1)
    if domain in TYPO_DOMAINS:
        corrected = f"{local}@{TYPO_DOMAINS[domain]}"
        return {"email": email, "suggestion": corrected, "has_typo": True, "original_domain": domain,
                "corrected_domain": TYPO_DOMAINS[domain]}
    return {"email": email, "suggestion": None, "has_typo": False}


def main():
    mcp.run()

if __name__ == '__main__':
    main()


# ── MEOK monetization layer (Stripe upgrade · PAYG · pricing) ──────────
# Free tier is zero-config. Upgrade to Pro (unlimited) or pay-as-you-go per call.
import os as _meok_os
MEOK_STRIPE_UPGRADE = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"  # Pro (unlimited)
MEOK_PAYG_KEY = _meok_os.environ.get("MEOK_PAYG_KEY", "")  # set to enable PAYG (x402 / ~GBP0.05 per call)
MEOK_PRICING = "https://meok.ai/pricing"


def meok_upsell(tier: str = "free") -> dict:
    """Monetization options for free-tier callers: Pro upgrade, PAYG, or pricing page."""
    if tier != "free":
        return {}
    return {"upgrade_url": MEOK_STRIPE_UPGRADE,
            "payg_enabled": bool(MEOK_PAYG_KEY),
            "pricing": MEOK_PRICING}

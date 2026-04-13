"""
Email Validator AI MCP Server
Email validation and correction tools powered by MEOK AI Labs.
"""

import re
import time
import socket
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("email-validator-ai-mcp")

_call_counts: dict[str, list[float]] = defaultdict(list)
FREE_TIER_LIMIT = 50
WINDOW = 86400

def _check_rate_limit(tool_name: str) -> None:
    now = time.time()
    _call_counts[tool_name] = [t for t in _call_counts[tool_name] if now - t < WINDOW]
    if len(_call_counts[tool_name]) >= FREE_TIER_LIMIT:
        raise ValueError(f"Rate limit exceeded for {tool_name}. Free tier: {FREE_TIER_LIMIT}/day. Upgrade at https://meok.ai/pricing")
    _call_counts[tool_name].append(now)

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "dispostable.com", "mailnesia.com", "maildrop.cc", "10minutemail.com",
    "trashmail.com", "fakeinbox.com", "tempail.com", "getnada.com",
}

COMMON_TYPOS = {
    "gmial.com": "gmail.com", "gmal.com": "gmail.com", "gamil.com": "gmail.com",
    "gmaill.com": "gmail.com", "gmail.co": "gmail.com", "gnail.com": "gmail.com",
    "hotmal.com": "hotmail.com", "hotmial.com": "hotmail.com", "hotmai.com": "hotmail.com",
    "outlok.com": "outlook.com", "outllook.com": "outlook.com",
    "yahooo.com": "yahoo.com", "yaho.com": "yahoo.com", "yaoo.com": "yahoo.com",
}

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


@mcp.tool()
def validate_email(email: str) -> dict:
    """Validate an email address format and structure.

    Args:
        email: Email address to validate
    """
    _check_rate_limit("validate_email")
    email = email.strip().lower()
    issues = []
    if not email:
        return {"valid": False, "email": email, "issues": ["Empty email"]}
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
    if not EMAIL_REGEX.match(email):
        issues.append("Invalid email format")
    return {"valid": len(issues) == 0, "email": email, "local_part": local, "domain": domain, "issues": issues}


@mcp.tool()
def check_mx(domain: str) -> dict:
    """Check if a domain has valid MX records for receiving email.

    Args:
        domain: Domain name to check MX records for
    """
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
            return {"domain": domain, "has_mx": True, "records": [], "note": "Basic check only (install dnspython for full MX)", "count": 0}
        except socket.gaierror:
            return {"domain": domain, "has_mx": False, "records": [], "error": "Domain does not resolve"}
    except Exception as e:
        return {"domain": domain, "has_mx": False, "records": [], "error": str(e)}


@mcp.tool()
def detect_disposable(email: str) -> dict:
    """Detect if an email uses a disposable/temporary email service.

    Args:
        email: Email address to check
    """
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
def suggest_correction(email: str) -> dict:
    """Suggest corrections for common email typos (e.g., gmial.com -> gmail.com).

    Args:
        email: Email address to check for typos
    """
    _check_rate_limit("suggest_correction")
    email = email.strip().lower()
    if '@' not in email:
        return {"email": email, "suggestion": None, "error": "Invalid email format"}
    local, domain = email.rsplit('@', 1)
    if domain in COMMON_TYPOS:
        corrected = f"{local}@{COMMON_TYPOS[domain]}"
        return {"email": email, "suggestion": corrected, "original_domain": domain,
                "corrected_domain": COMMON_TYPOS[domain], "confidence": "high"}
    # Check for close matches
    for typo, correct in COMMON_TYPOS.items():
        if abs(len(domain) - len(typo)) <= 1:
            diff = sum(1 for a, b in zip(domain, typo) if a != b)
            if diff <= 1:
                corrected = f"{local}@{correct}"
                return {"email": email, "suggestion": corrected, "original_domain": domain,
                        "corrected_domain": correct, "confidence": "medium"}
    return {"email": email, "suggestion": None, "message": "No typos detected"}


if __name__ == "__main__":
    mcp.run()

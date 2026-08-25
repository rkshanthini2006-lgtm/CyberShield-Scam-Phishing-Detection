"""
CyberShield URL Detection Engine

Analyzes URLs for common phishing and scam indicators.
Uses multiple structural and lexical checks instead of relying
only on suspicious keywords.
"""

import re
from urllib.parse import urlparse, unquote

from risk_score import calculate_risk, apply_penalty


# ============================================================
# CONSTANTS
# ============================================================

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
}

SUSPICIOUS_TLDS = {
    "zip",
    "top",
    "click",
    "download",
    "country",
    "gq",
    "tk",
    "ml",
    "ga",
    "cf",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "confirm",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "credential",
    "payment",
    "billing",
    "bank",
    "wallet",
    "unlock",
    "recover",
    "reward",
    "winner",
    "prize",
    "gift",
    "claim",
    "refund",
    "invoice",
    "support",
    "alert",
    "suspended",
    "blocked",
}

BRAND_KEYWORDS = {
    "paypal",
    "apple",
    "microsoft",
    "google",
    "amazon",
    "netflix",
    "instagram",
    "facebook",
    "whatsapp",
    "telegram",
    "linkedin",
    "bank",
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def add_penalty(score, reasons, penalty, reason):
    """
    Apply a penalty and record the reason.
    """

    score = apply_penalty(
        score,
        penalty
    )

    if reason not in reasons:

        reasons.append(reason)

    return score


def extract_hostname(url):
    """
    Extract hostname safely from a URL.
    """

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname

        if hostname:

            return hostname.lower().strip(".")

    except Exception:

        return ""

    return ""


def is_ip_address(hostname):
    """
    Detect IPv4-style hostnames.
    """

    return bool(
        re.fullmatch(
            r"\d{1,3}(?:\.\d{1,3}){3}",
            hostname
        )
    )


# ============================================================
# MAIN URL SCANNER
# ============================================================

def scan_url(url):
    """
    Analyze a URL and return a structured risk result.
    """

    score = 100
    reasons = []

    # --------------------------------------------------------
    # EMPTY URL
    # --------------------------------------------------------

    if not url or not url.strip():

        return calculate_risk(
            0,
            ["URL cannot be empty"]
        )

    url = url.strip()

    url_lower = url.lower()

    # --------------------------------------------------------
    # DECODE URL
    # --------------------------------------------------------

    try:

        decoded_url = unquote(url_lower)

    except Exception:

        decoded_url = url_lower

    # --------------------------------------------------------
    # URL LENGTH
    # --------------------------------------------------------

    if len(url) > 120:

        score = add_penalty(
            score,
            reasons,
            10,
            "Very long URL"
        )

    elif len(url) > 75:

        score = add_penalty(
            score,
            reasons,
            5,
            "Unusually long URL"
        )

    # --------------------------------------------------------
    # URL FORMAT
    # --------------------------------------------------------

    try:

        parsed = urlparse(url)

    except Exception:

        return calculate_risk(
            0,
            ["Invalid URL format"]
        )

    hostname = extract_hostname(url)

    if not hostname:

        score = add_penalty(
            score,
            reasons,
            25,
            "Unable to identify a valid domain"
        )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    if hostname and is_ip_address(hostname):

        score = add_penalty(
            score,
            reasons,
            25,
            "IP address used instead of a domain name"
        )

    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:

        score = add_penalty(
            score,
            reasons,
            25,
            "Deceptive @ symbol detected"
        )

    # --------------------------------------------------------
    # USERNAME / PASSWORD IN URL
    # --------------------------------------------------------

    if parsed.username or parsed.password:

        score = add_penalty(
            score,
            reasons,
            20,
            "Username or password embedded in URL"
        )

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    if url_lower.startswith("http://"):

        score = add_penalty(
            score,
            reasons,
            10,
            "URL does not use HTTPS"
        )

    # --------------------------------------------------------
    # MISSING SCHEME
    # --------------------------------------------------------

    if not parsed.scheme:

        score = add_penalty(
            score,
            reasons,
            5,
            "URL scheme is missing"
        )

    # --------------------------------------------------------
    # SUSPICIOUS PORT
    # --------------------------------------------------------

    try:

        if parsed.port:

            if parsed.port not in {
                80,
                443,
                8080,
                8443
            }:

                score = add_penalty(
                    score,
                    reasons,
                    10,
                    "Unusual network port detected"
                )

    except ValueError:

        score = add_penalty(
            score,
            reasons,
            10,
            "Invalid network port"
        )

    # --------------------------------------------------------
    # URL SHORTENER
    # --------------------------------------------------------

    if hostname in SHORTENERS:

        score = add_penalty(
            score,
            reasons,
            15,
            "URL shortener detected"
        )

    # --------------------------------------------------------
    # SUSPICIOUS TLD
    # --------------------------------------------------------

    if hostname:

        hostname_parts = hostname.split(".")

        if len(hostname_parts) >= 2:

            tld = hostname_parts[-1]

            if tld in SUSPICIOUS_TLDS:

                score = add_penalty(
                    score,
                    reasons,
                    10,
                    f"Suspicious top-level domain: .{tld}"
                )

    # --------------------------------------------------------
    # EXCESSIVE SUBDOMAINS
    # --------------------------------------------------------

    if hostname:

        hostname_parts = hostname.split(".")

        if len(hostname_parts) >= 5:

            score = add_penalty(
                score,
                reasons,
                15,
                "Unusually large number of subdomains"
            )

        elif len(hostname_parts) == 4:

            score = add_penalty(
                score,
                reasons,
                5,
                "Multiple subdomains detected"
            )

    # --------------------------------------------------------
    # EXCESSIVE HYPHENS
    # --------------------------------------------------------

    if hostname:

        hyphen_count = hostname.count("-")

        if hyphen_count >= 4:

            score = add_penalty(
                score,
                reasons,
                15,
                "Excessive hyphens in domain"
            )

        elif hyphen_count >= 2:

            score = add_penalty(
                score,
                reasons,
                5,
                "Multiple hyphens in domain"
            )

    # --------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    detected_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in decoded_url:

            detected_keywords.append(
                keyword
            )

    # Avoid excessive punishment for many keywords.

    for keyword in detected_keywords[:5]:

        score = add_penalty(
            score,
            reasons,
            4,
            f"Suspicious keyword: {keyword}"
        )

    # --------------------------------------------------------
    # MULTIPLE SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    if len(detected_keywords) >= 3:

        score = add_penalty(
            score,
            reasons,
            10,
            "Multiple phishing-related indicators in URL"
        )

    # --------------------------------------------------------
    # BRAND IMPERSONATION PATTERN
    # --------------------------------------------------------

    if hostname:

        brand_hits = []

        for brand in BRAND_KEYWORDS:

            if brand in hostname:

                brand_hits.append(
                    brand
                )

        # A brand appearing in a hostname is NOT automatically
        # malicious. Only flag it when the domain structure looks
        # deceptive.

        if brand_hits:

            domain_without_www = hostname.replace(
                "www.",
                ""
            )

            parts = domain_without_www.split(".")

            if len(parts) >= 3:

                score = add_penalty(
                    score,
                    reasons,
                    10,
                    "Brand-like name combined with multiple domain levels"
                )

    # --------------------------------------------------------
    # DOMAIN LOOKALIKE PATTERNS
    # --------------------------------------------------------

    if hostname:

        if re.search(
            r"[a-z]\d[a-z]|\d[a-z]\d",
            hostname
        ):

            score = add_penalty(
                score,
                reasons,
                8,
                "Possible domain lookalike pattern detected"
            )

    # --------------------------------------------------------
    # EXCESSIVE DOTS
    # --------------------------------------------------------

    if hostname.count(".") >= 4:

        score = add_penalty(
            score,
            reasons,
            8,
            "Excessive domain separators detected"
        )

    # --------------------------------------------------------
    # ENCODED CHARACTERS
    # --------------------------------------------------------

    if "%" in url:

        score = add_penalty(
            score,
            reasons,
            8,
            "Encoded characters detected in URL"
        )

    # --------------------------------------------------------
    # DOUBLE SLASH IN PATH
    # --------------------------------------------------------

    path = parsed.path or ""

    if "//" in path:

        score = add_penalty(
            score,
            reasons,
            8,
            "Unusual double-slash path detected"
        )

    # --------------------------------------------------------
    # VERY DEEP URL PATH
    # --------------------------------------------------------

    path_parts = [
        part
        for part in path.split("/")
        if part
    ]

    if len(path_parts) >= 6:

        score = add_penalty(
            score,
            reasons,
            8,
            "Unusually deep URL path"
        )

    # --------------------------------------------------------
    # SUSPICIOUS FILE EXTENSIONS
    # --------------------------------------------------------

    suspicious_extensions = (
        ".exe",
        ".scr",
        ".zip",
        ".rar",
        ".apk",
        ".msi",
        ".bat",
        ".cmd",
        ".js"
    )

    if any(
        path.lower().endswith(extension)
        for extension in suspicious_extensions
    ):

        score = add_penalty(
            score,
            reasons,
            12,
            "Potentially dangerous file extension detected"
        )

    # --------------------------------------------------------
    # QUERY PARAMETER ABUSE
    # --------------------------------------------------------

    if parsed.query:

        query_length = len(
            parsed.query
        )

        if query_length > 200:

            score = add_penalty(
                score,
                reasons,
                8,
                "Unusually long query parameters"
            )

    # --------------------------------------------------------
    # REDIRECT PARAMETERS
    # --------------------------------------------------------

    redirect_patterns = [
        "redirect=",
        "redirect_url=",
        "return=",
        "returnurl=",
        "continue=",
        "next=",
        "url=",
    ]

    redirect_detected = any(
        pattern in decoded_url
        for pattern in redirect_patterns
    )

    if redirect_detected:

        score = add_penalty(
            score,
            reasons,
            8,
            "Potential redirect parameter detected"
        )

    # --------------------------------------------------------
    # MULTIPLE SECURITY INDICATORS
    # --------------------------------------------------------

    indicator_count = 0

    if is_ip_address(hostname):
        indicator_count += 1

    if "@" in url:
        indicator_count += 1

    if hostname in SHORTENERS:
        indicator_count += 1

    if len(detected_keywords) >= 2:
        indicator_count += 1

    if "%" in url:
        indicator_count += 1

    if len(hostname.split(".")) >= 4:
        indicator_count += 1

    if parsed.username or parsed.password:
        indicator_count += 1

    if redirect_detected:
        indicator_count += 1

    if indicator_count >= 3:

        score = add_penalty(
            score,
            reasons,
            10,
            "Multiple suspicious URL characteristics detected"
        )

    # --------------------------------------------------------
    # FINAL SCORE LIMIT
    # --------------------------------------------------------

    score = max(
        0,
        min(score, 100)
    )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    return calculate_risk(
        score,
        reasons
    )
"""
CyberShield URL Detection Engine

Analyzes URLs for common phishing and scam indicators.
"""

import re

from risk_score import calculate_risk, apply_penalty


def scan_url(url):
    """
    Analyze a URL and return a structured risk result.
    """

    score = 100
    reasons = []

    url = url.strip()
    url_lower = url.lower()

    # --------------------------------
    # Empty URL
    # --------------------------------

    if not url:

        return calculate_risk(
            0,
            ["URL cannot be empty"]
        )

    # --------------------------------
    # URL length
    # --------------------------------

    if len(url) > 75:

        score = apply_penalty(score, 10)

        reasons.append(
            "Very long URL"
        )

    # --------------------------------
    # @ symbol
    # --------------------------------

    if "@" in url:

        score = apply_penalty(score, 20)

        reasons.append(
            "@ symbol detected"
        )

    # --------------------------------
    # Excessive hyphens
    # --------------------------------

    if url.count("-") >= 3:

        score = apply_penalty(score, 10)

        reasons.append(
            "Too many hyphens"
        )

    # --------------------------------
    # IP address
    # --------------------------------

    if re.search(
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        url
    ):

        score = apply_penalty(score, 25)

        reasons.append(
            "IP address detected"
        )

    # --------------------------------
    # Suspicious keywords
    # --------------------------------

    suspicious_keywords = [

        "login",
        "verify",
        "verification",
        "bank",
        "gift",
        "winner",
        "free",
        "secure",
        "account",
        "update",
        "payment",
        "password",
        "signin",
        "confirm",
        "unlock",
        "reward"

    ]

    detected_keywords = []

    for word in suspicious_keywords:

        if word in url_lower:

            detected_keywords.append(word)

    for word in detected_keywords:

        score = apply_penalty(score, 5)

        reasons.append(
            f"Suspicious keyword: {word}"
        )

    # --------------------------------
    # HTTP instead of HTTPS
    # --------------------------------

    if url_lower.startswith("http://"):

        score = apply_penalty(score, 10)

        reasons.append(
            "URL does not use HTTPS"
        )

    # --------------------------------
    # URL shortener detection
    # --------------------------------

    shorteners = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly"

    ]

    for domain in shorteners:

        if domain in url_lower:

            score = apply_penalty(score, 15)

            reasons.append(
                "URL shortener detected"
            )

            break

    # --------------------------------
    # Excessive subdomains
    # --------------------------------

    try:

        domain_part = re.sub(
            r"^https?://",
            "",
            url_lower
        ).split("/")[0]

        domain_parts = domain_part.split(".")

        if len(domain_parts) >= 5:

            score = apply_penalty(score, 10)

            reasons.append(
                "Unusually large number of subdomains"
            )

    except Exception:

        pass

    # --------------------------------
    # Final result
    # --------------------------------

    return calculate_risk(
        score,
        reasons
    )
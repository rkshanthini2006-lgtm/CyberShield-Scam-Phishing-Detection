import re


def scan_url(url):

    score = 100
    reasons = []

    suspicious_keywords = [
        "login",
        "verify",
        "bank",
        "gift",
        "winner",
        "free",
        "secure",
        "account",
        "update",
        "payment"
    ]

    if len(url) > 75:
        score -= 10
        reasons.append("Very long URL")

    if "@" in url:
        score -= 20
        reasons.append("@ symbol detected")

    if url.count("-") >= 3:
        score -= 10
        reasons.append("Too many hyphens")

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score -= 25
        reasons.append("IP address detected")

    for word in suspicious_keywords:
        if word.lower() in url.lower():
            score -= 5
            reasons.append(f"Suspicious keyword: {word}")

    score = max(score, 0)

    if score >= 90:
        risk = "Safe"
    elif score >= 60:
        risk = "Suspicious"
    else:
        risk = "Dangerous"

    return {
        "score": score,
        "risk": risk,
        "reasons": reasons
    }
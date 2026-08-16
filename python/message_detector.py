import re


def scan_message(message):

    score = 100
    reasons = []

    suspicious_keywords = [
        "urgent",
        "verify",
        "account",
        "blocked",
        "suspended",
        "click",
        "link",
        "password",
        "otp",
        "bank",
        "payment",
        "winner",
        "prize",
        "free",
        "claim",
        "limited time",
        "immediately"
    ]

    message_lower = message.lower()

    # Check message length
    if len(message) > 300:
        score -= 10
        reasons.append("Unusually long message")

    # Check suspicious keywords
    for word in suspicious_keywords:
        if word in message_lower:
            score -= 5
            reasons.append(f"Suspicious keyword: {word}")

    # Check URLs
    if re.search(r"https?://\S+|www\.\S+", message_lower):
        score -= 15
        reasons.append("Suspicious link detected")

    # Check urgency
    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "limited time"
    ]

    for word in urgency_words:
        if word in message_lower:
            score -= 5
            reasons.append(f"Urgency indicator: {word}")

    # Check OTP requests
    if "otp" in message_lower or "one time password" in message_lower:
        score -= 10
        reasons.append("OTP request detected")

    # Prevent negative score
    score = max(score, 0)

    # Determine risk
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
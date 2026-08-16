import re


def scan_email(email):

    score = 100
    reasons = []

    email_lower = email.lower()

    # --------------------------------
    # Suspicious keywords
    # --------------------------------

    suspicious_keywords = [
        "urgent",
        "verify",
        "account",
        "suspended",
        "blocked",
        "password",
        "otp",
        "bank",
        "payment",
        "winner",
        "prize",
        "claim",
        "click",
        "limited time",
        "immediately",
        "security alert"
    ]

    for word in suspicious_keywords:

        if word in email_lower:

            score -= 5

            reasons.append(
                f"Suspicious keyword: {word}"
            )


    # --------------------------------
    # URL detection
    # --------------------------------

    if re.search(
        r"https?://\S+|www\.\S+",
        email_lower
    ):

        score -= 15

        reasons.append(
            "Link detected in email"
        )


    # --------------------------------
    # Urgency detection
    # --------------------------------

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "limited time"
    ]

    urgency_detected = False

    for word in urgency_words:

        if word in email_lower:

            urgency_detected = True

            reasons.append(
                f"Urgency indicator: {word}"
            )

    if urgency_detected:

        score -= 10


    # --------------------------------
    # OTP / credential request
    # --------------------------------

    if (
        "otp" in email_lower
        or "one time password" in email_lower
    ):

        score -= 15

        reasons.append(
            "OTP request detected"
        )


    # --------------------------------
    # Password request
    # --------------------------------

    if (
        "password" in email_lower
        or "login credentials" in email_lower
        or "credentials" in email_lower
    ):

        score -= 15

        reasons.append(
            "Credential request detected"
        )


    # --------------------------------
    # Account threat
    # --------------------------------

    if (
        "account" in email_lower
        and (
            "suspended" in email_lower
            or "blocked" in email_lower
            or "disabled" in email_lower
        )
    ):

        score -= 15

        reasons.append(
            "Account threat detected"
        )


    # --------------------------------
    # Suspicious link + verification
    # --------------------------------

    if (
        ("http://" in email_lower or "https://" in email_lower)
        and (
            "verify" in email_lower
            or "click" in email_lower
            or "account" in email_lower
        )
    ):

        score -= 15

        reasons.append(
            "Suspicious verification link detected"
        )


    # --------------------------------
    # Email address detection
    # --------------------------------

    if re.search(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        email
    ):

        reasons.append(
            "Email address detected"
        )


    # --------------------------------
    # Prevent negative score
    # --------------------------------

    score = max(score, 0)


    # --------------------------------
    # Risk classification
    # --------------------------------

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
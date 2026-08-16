"""
CyberShield Risk Score Engine
Centralized risk calculation for URL, message and email scanning.
"""


def calculate_risk(score, reasons=None):
    """
    Convert a numerical score into a risk classification.

    Score range:
        90 - 100 : Safe
        60 - 89  : Suspicious
        0  - 59  : Dangerous
    """

    if reasons is None:
        reasons = []

    # Keep score inside valid range
    score = max(0, min(100, int(score)))

    # Remove duplicate reasons while preserving order
    unique_reasons = list(dict.fromkeys(reasons))

    # Risk classification
    if score >= 90:
        risk = "Safe"

    elif score >= 60:
        risk = "Suspicious"

    else:
        risk = "Dangerous"

    return {
        "score": score,
        "risk": risk,
        "reasons": unique_reasons
    }


def apply_penalty(score, penalty):
    """
    Safely subtract a penalty from the current score.
    """

    score -= penalty

    return max(score, 0)
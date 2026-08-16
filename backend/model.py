"""
CyberShield AI Model
"""

from scanner import scan_url


def predict(url):
    """
    Predict whether a URL is safe or dangerous.
    """

    result = scan_url(url)

    return result
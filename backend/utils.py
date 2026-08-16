"""
CyberShield Utility Functions
"""

import re


def is_valid_url(url):

    pattern = re.compile(
        r"^(https?:\/\/)?([\w\-]+\.)+[a-zA-Z]{2,}(\/.*)?$"
    )

    return bool(pattern.match(url))
import re


# ==========================================
# CYBERSHIELD - EMAIL DETECTOR
# Multi-Signal Scam & Phishing Detection
# ==========================================


def scan_email(email):

    reasons = []
    risk_points = 0

    # ==========================================
    # INPUT NORMALIZATION
    # ==========================================

    if not email:

        return {
            "score": 100,
            "risk": "Safe",
            "reasons": []
        }

    email = str(email).strip()

    email_lower = email.lower()

    normalized_email = re.sub(
        r"\s+",
        " ",
        email_lower
    )


    # ==========================================
    # HELPER FUNCTION
    # ==========================================

    def add_signal(points, reason):

        nonlocal risk_points

        risk_points += points

        if reason not in reasons:

            reasons.append(reason)


    # ==========================================
    # 1. URL DETECTION
    # ==========================================

    urls = re.findall(
        r"(?:https?://|www\.)[^\s]+",
        normalized_email
    )

    if urls:

        add_signal(
            20,
            "Link detected in email"
        )


    # ==========================================
    # 2. SHORTENED URL DETECTION
    # ==========================================

    shortened_domains = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "shorturl.at",
        "rebrand.ly",
        "ow.ly"

    ]

    shortened_url_detected = False

    for domain in shortened_domains:

        if domain in normalized_email:

            shortened_url_detected = True

            add_signal(
                15,
                "URL shortening service detected"
            )

            break


    # ==========================================
    # 3. IP ADDRESS URL
    # ==========================================

    ip_url_pattern = re.search(
        r"https?://(?:\d{1,3}\.){3}\d{1,3}",
        normalized_email
    )

    ip_url_detected = False

    if ip_url_pattern:

        ip_url_detected = True

        add_signal(
            25,
            "URL uses a direct IP address"
        )


    # ==========================================
    # 4. SUSPICIOUS URL STRUCTURE
    # ==========================================

    suspicious_url_patterns = [

        r"https?://[^\s]*@",

        r"https?://[^\s]*\.(?:xyz|top|click|win|loan|download)(?:[/:?#]|$)",

        r"https?://[^\s]*-{2,}[^\s]*",

        r"https?://[^\s]*\d{4,}[^\s]*"

    ]

    suspicious_url_detected = False

    for pattern in suspicious_url_patterns:

        if re.search(
            pattern,
            normalized_email
        ):

            suspicious_url_detected = True

            add_signal(
                15,
                "Suspicious URL structure detected"
            )

            break


    # ==========================================
    # 5. URGENCY DETECTION
    # ==========================================

    urgency_patterns = [

        r"\burgent\b",
        r"\burgently\b",
        r"\bimmediately\b",
        r"\bact\s+now\b",
        r"\brespond\s+immediately\b",
        r"\bverify\s+immediately\b",
        r"\bdo\s+it\s+now\b",
        r"\bas\s+soon\s+as\s+possible\b",
        r"\bwithin\s+\d+\s+(minutes?|hours?|days?)\b",
        r"\blimited\s+time\b",
        r"\blast\s+warning\b",
        r"\btime\s+is\s+running\s+out\b"

    ]

    urgency_detected = False

    for pattern in urgency_patterns:

        if re.search(
            pattern,
            normalized_email
        ):

            urgency_detected = True

            break

    if urgency_detected:

        add_signal(
            15,
            "Urgency or pressure tactic detected"
        )


    # ==========================================
    # 6. CREDENTIAL REQUEST
    # ==========================================

    credential_patterns = [

        r"\benter\s+(your\s+)?password\b",
        r"\bprovide\s+(your\s+)?password\b",
        r"\bshare\s+(your\s+)?password\b",
        r"\bconfirm\s+(your\s+)?password\b",
        r"\bsubmit\s+(your\s+)?password\b",

        r"\benter\s+(your\s+)?pin\b",
        r"\bshare\s+(your\s+)?pin\b",

        r"\benter\s+(your\s+)?cvv\b",
        r"\bshare\s+(your\s+)?cvv\b",

        r"\benter\s+(your\s+)?card\s+(number|details)\b",
        r"\bshare\s+(your\s+)?card\s+(number|details)\b",

        r"\benter\s+(your\s+)?login\s+(details|credentials)\b",
        r"\bshare\s+(your\s+)?login\s+(details|credentials)\b",

        r"\bprovide\s+(your\s+)?login\s+(details|credentials)\b",

        r"\bverify\s+(your\s+)?identity\b",
        r"\bconfirm\s+(your\s+)?identity\b"

    ]

    credential_detected = False

    for pattern in credential_patterns:

        if re.search(
            pattern,
            normalized_email
        ):

            credential_detected = True

            break

    if credential_detected:

        add_signal(
            25,
            "Sensitive credential request detected"
        )


    # ==========================================
    # 7. OTP / VERIFICATION CODE
    # ==========================================

    otp_patterns = [

        r"\botp\b",
        r"\bone[\s-]?time[\s-]?password\b",
        r"\bverification[\s-]?code\b",
        r"\bsecurity[\s-]?code\b",
        r"\bauthentication[\s-]?code\b"

    ]

    otp_detected = False

    for pattern in otp_patterns:

        if re.search(
            pattern,
            normalized_email
        ):

            otp_detected = True

            break

    if otp_detected:

        add_signal(
            25,
            "OTP or verification code mentioned"
        )


    # ==========================================
    # 8. FINANCIAL REQUEST
    # ==========================================

    financial_patterns = [

        r"\bsend\s+(money|payment|funds)\b",
        r"\btransfer\s+(money|funds)\b",
        r"\bwire\s+(money|funds)\b",
        r"\bmake\s+a\s+payment\b",
        r"\bpayment\s+required\b",
        r"\bpayment\s+needed\b",
        r"\bpay\s+(the\s+)?fee\b",
        r"\bprocessing\s+fee\b",
        r"\brefund\s+fee\b",
        r"\bdeposit\s+(money|funds)\b",
        r"\bbank\s+transfer\b"

    ]

    financial_detected = False

    for pattern in financial_patterns:

        if re.search(
            pattern,
            normalized_email
        ):

            financial_detected = True

            break

    if financial_detected:

        add_signal(
            20,
            "Financial payment or transfer request detected"
        )


    # ==========================================
    # 9. ACCOUNT THREAT
    # ==========================================

    account_threat_patterns = [

        r"\baccount\s+has\s+been\s+suspended\b",
        r"\baccount\s+has\s+been\s+blocked\b",
        r"\baccount\s+has\s+been\s+disabled\b",
        r"\baccount\s+is\s+suspended\b",
        r"\baccount\s+is\s+blocked\b",
        r"\baccount\s+will\s+be\s+suspended\b",
        r"\baccount\s+will\s+be\s+blocked\b",
        r"\baccount\s+will\s+be\s+closed\b",
        r"\baccount\s+will\s+be\s+deleted\b",
        r"\baccount\s+termination\b",
        r"\bservice\s+will\s+be\s+terminated\b",
        r"\byour\s+access\s+will\s+be\s+removed\b"

    ]

    account_threat_detected = False

    for pattern in account_threat_patterns:

        if re.search(
            pattern,
            normalized_email
        ):

            account_threat_detected = True

            break

    if account_threat_detected:

        add_signal(
            20,
            "Account threat or negative consequence detected"
        )


    # ==========================================
    # 10. PRIZE / REWARD SCAM
    # ==========================================

    reward_patterns = [

        r"\byou\s+have\s+won\b",
        r"\byou\s+won\b",
        r"\byou\s+are\s+a\s+winner\b",
        r"\bcongratulations\b",
        r"\bclaim\s+your\s+prize\b",
        r"\bclaim\s+your\s+reward\b",
        r"\bclaim\s+your\s+gift\b",
        r"\bfree\s+gift\b",
        r"\bfree\s+money\b",
        r"\bcash\s+prize\b",
        r"\blottery\b",
        r"\bjackpot\b",
        r"\bexclusive\s+reward\b",
        r"\bcashback\s+reward\b"

    ]

    reward_detected = False

    for pattern in reward_patterns:

        if re.search(
            pattern,
            normalized_email
        ):

            reward_detected = True

            break

    if reward_detected:

        add_signal(
            20,
            "Unexpected prize or reward claim detected"
        )


    # ==========================================
    # 11. CLICK / CALL TO ACTION
    # ==========================================

    click_patterns = [

        r"\bclick\s+(here|now|below|the\s+link)\b",
        r"\bclick\s+this\s+link\b",
        r"\bopen\s+this\s+link\b",
        r"\bvisit\s+this\s+link\b",
        r"\btap\s+(here|now)\b",
        r"\buse\s+the\s+link\b",
        r"\bfollow\s+the\s+link\b"

    ]

    click_detected = False

    for pattern in click_patterns:

        if re.search(
            pattern,
            normalized_email
        ):

            click_detected = True

            break

    if click_detected:

        add_signal(
            10,
            "Suspicious call-to-action detected"
        )


    # ==========================================
    # 12. IMPERSONATION INDICATORS
    # ==========================================

    impersonation_entities = [

        "bank",
        "paypal",
        "amazon",
        "microsoft",
        "google",
        "apple",
        "netflix",
        "instagram",
        "facebook",
        "whatsapp",
        "government",
        "police",
        "tax department",
        "customs",
        "courier",
        "delivery service",
        "support team",
        "customer support"

    ]

    impersonation_detected = False

    for entity in impersonation_entities:

        if re.search(
            rf"\b{re.escape(entity)}\b",
            normalized_email
        ):

            impersonation_detected = True

            break


    # ==========================================
    # 13. LOGIN / VERIFICATION ACTION
    # ==========================================

    login_patterns = [

        r"\blog\s*in\b",
        r"\blogin\b",
        r"\bsign\s+in\b",
        r"\bverify\s+your\s+account\b",
        r"\bconfirm\s+your\s+account\b",
        r"\bupdate\s+your\s+account\b",
        r"\bsecure\s+your\s+account\b",
        r"\bvalidate\s+your\s+account\b"

    ]

    login_detected = False

    for pattern in login_patterns:

        if re.search(
            pattern,
            normalized_email
        ):

            login_detected = True

            break

    if login_detected:

        add_signal(
            10,
            "Account login or verification action requested"
        )


    # ==========================================
    # 14. SUSPICIOUS EMAIL ADDRESS
    # ==========================================

    email_addresses = re.findall(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        email
    )

    if email_addresses:

        suspicious_email_pattern = re.compile(

            r"(support|security|admin|verify|account|"
            r"billing|payment|service|alert|notification|"
            r"official|help|refund|winner|prize)",

            re.IGNORECASE
        )

        for address in email_addresses:

            local_part = address.split("@")[0]

            if suspicious_email_pattern.search(
                local_part
            ):

                add_signal(
                    10,
                    "Security-sensitive sender address detected"
                )

                break


    # ==========================================
    # 15. SUSPICIOUS DISPLAY NAME / EMAIL FORMAT
    # ==========================================

    sender_patterns = [

        r"from\s*:\s*([^\n]+)",
        r"sender\s*:\s*([^\n]+)",
        r"from\s*-\s*([^\n]+)"

    ]

    sender_text = ""

    for pattern in sender_patterns:

        match = re.search(
            pattern,
            email_lower
        )

        if match:

            sender_text = match.group(1)

            break


    if sender_text:

        if (
            ("security" in sender_text
             or "support" in sender_text
             or "admin" in sender_text
             or "bank" in sender_text)
            and email_addresses
        ):

            add_signal(
                10,
                "Security-related sender identity detected"
            )


    # ==========================================
    # 16. OBFUSCATED SENSITIVE TERMS
    # ==========================================

    obfuscation_patterns = [

        r"p[\W_]*a[\W_]*s[\W_]*s[\W_]*w[\W_]*o[\W_]*r[\W_]*d",
        r"o[\W_]*t[\W_]*p",
        r"c[\W_]*v[\W_]*v",
        r"p[\W_]*i[\W_]*n"

    ]

    obfuscation_detected = False

    for pattern in obfuscation_patterns:

        if re.search(
            pattern,
            normalized_email
        ):

            obfuscation_detected = True

            break

    if obfuscation_detected:

        add_signal(
            20,
            "Obfuscated sensitive information detected"
        )


    # ==========================================
    # 17. EXCESSIVE EXCLAMATION
    # ==========================================

    exclamation_count = email.count("!")

    if exclamation_count >= 5:

        add_signal(
            5,
            "Excessive urgency-style punctuation detected"
        )


    # ==========================================
    # 18. LARGE MESSAGE
    # ==========================================

    if len(email) > 2000:

        add_signal(
            5,
            "Unusually long email content"
        )


    # ==========================================
    # 19. COMBINATION ANALYSIS
    # ==========================================

    # Credential + urgency

    if (
        credential_detected
        and urgency_detected
    ):

        add_signal(
            15,
            "Credential request combined with urgency"
        )


    # Credential + URL

    if (
        credential_detected
        and urls
    ):

        add_signal(
            20,
            "Credential request combined with a link"
        )


    # OTP + financial activity

    if (
        otp_detected
        and financial_detected
    ):

        add_signal(
            20,
            "OTP request combined with financial activity"
        )


    # URL + click request

    if (
        urls
        and click_detected
    ):

        add_signal(
            15,
            "Link combined with a click action"
        )


    # Account threat + urgency

    if (
        account_threat_detected
        and urgency_detected
    ):

        add_signal(
            15,
            "Account threat combined with urgency"
        )


    # Reward + click

    if (
        reward_detected
        and click_detected
    ):

        add_signal(
            20,
            "Prize or reward combined with a click request"
        )


    # Reward + URL

    if (
        reward_detected
        and urls
    ):

        add_signal(
            20,
            "Prize or reward combined with a suspicious link"
        )


    # Impersonation + credential request

    if (
        impersonation_detected
        and credential_detected
    ):

        add_signal(
            20,
            "Possible impersonation combined with credential request"
        )


    # Impersonation + URL

    if (
        impersonation_detected
        and urls
    ):

        add_signal(
            15,
            "Possible impersonation combined with a link"
        )


    # Impersonation + urgency

    if (
        impersonation_detected
        and urgency_detected
    ):

        add_signal(
            10,
            "Possible impersonation combined with urgency"
        )


    # Login + URL

    if (
        login_detected
        and urls
    ):

        add_signal(
            15,
            "Login or verification request combined with a link"
        )


    # Suspicious URL + IP address

    if (
        urls
        and ip_url_detected
    ):

        add_signal(
            15,
            "Link uses a high-risk URL structure"
        )


    # ==========================================
    # 20. MULTIPLE SOCIAL ENGINEERING SIGNALS
    # ==========================================

    behavioral_signals = sum([

        bool(credential_detected),

        bool(otp_detected),

        bool(financial_detected),

        bool(urgency_detected),

        bool(account_threat_detected),

        bool(reward_detected),

        bool(urls),

        bool(click_detected),

        bool(login_detected)

    ])

    if behavioral_signals >= 4:

        add_signal(
            15,
            "Multiple social-engineering indicators detected"
        )


    # ==========================================
    # 21. FINAL SCORE
    # ==========================================

    score = 100 - risk_points

    score = max(
        0,
        min(100, score)
    )


    # ==========================================
    # 22. RISK CLASSIFICATION
    # ==========================================

    if score >= 80:

        risk = "Safe"

    elif score >= 50:

        risk = "Suspicious"

    else:

        risk = "Dangerous"


    # ==========================================
    # 23. DEFAULT REASON
    # ==========================================

    if not reasons:

        reasons.append(
            "No significant suspicious indicators detected"
        )


    # ==========================================
    # FINAL RESULT
    # ==========================================

    return {

        "score":
            score,

        "risk":
            risk,

        "reasons":
            reasons

    }
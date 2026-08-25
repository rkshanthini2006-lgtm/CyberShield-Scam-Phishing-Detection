import re


# ==========================================
# CYBERSHIELD - MESSAGE DETECTOR
# Multi-Signal Scam & Phishing Detection
# ==========================================


def scan_message(message):

    reasons = []
    risk_points = 0

    # ==========================================
    # INPUT NORMALIZATION
    # ==========================================

    if not message:
        return {
            "score": 100,
            "risk": "Safe",
            "reasons": []
        }

    message = str(message).strip()

    message_lower = message.lower()

    # Normalize excessive whitespace
    normalized_message = re.sub(
        r"\s+",
        " ",
        message_lower
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
    # 1. SUSPICIOUS URL DETECTION
    # ==========================================

    urls = re.findall(
        r"(?:https?://|www\.)[^\s]+",
        normalized_message
    )

    if urls:

        add_signal(
            20,
            "Suspicious link detected"
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

    for domain in shortened_domains:

        if domain in normalized_message:

            add_signal(
                15,
                "URL shortening service detected"
            )

            break


    # ==========================================
    # 3. IP ADDRESS URL DETECTION
    # ==========================================

    ip_url_pattern = re.search(
        r"https?://(?:\d{1,3}\.){3}\d{1,3}",
        normalized_message
    )

    if ip_url_pattern:

        add_signal(
            25,
            "URL uses a direct IP address"
        )


    # ==========================================
    # 4. CREDENTIAL REQUEST
    # ==========================================

    credential_patterns = [

        r"\benter\s+(your\s+)?password\b",
        r"\bprovide\s+(your\s+)?password\b",
        r"\bshare\s+(your\s+)?password\b",
        r"\bconfirm\s+(your\s+)?password\b",
        r"\bsubmit\s+(your\s+)?password\b",
        r"\bpassword\s+(required|needed|requested)\b",

        r"\benter\s+(your\s+)?pin\b",
        r"\bshare\s+(your\s+)?pin\b",

        r"\benter\s+(your\s+)?cvv\b",
        r"\bshare\s+(your\s+)?cvv\b",

        r"\benter\s+(your\s+)?card\s+(number|details)\b",
        r"\bshare\s+(your\s+)?card\s+(number|details)\b",

        r"\benter\s+(your\s+)?login\s+(details|credentials)\b",
        r"\bshare\s+(your\s+)?login\s+(details|credentials)\b",

        r"\bverify\s+(your\s+)?identity\b",
        r"\bverify\s+(your\s+)?account\b"

    ]

    credential_detected = False

    for pattern in credential_patterns:

        if re.search(pattern, normalized_message):

            credential_detected = True
            break

    if credential_detected:

        add_signal(
            25,
            "Sensitive credential request detected"
        )


    # ==========================================
    # 5. OTP REQUEST
    # ==========================================

    otp_patterns = [

        r"\botp\b",
        r"\bone[\s-]?time[\s-]?password\b",
        r"\bverification[\s-]?code\b",
        r"\bsecurity[\s-]?code\b",
        r"\bverification[\s-]?otp\b"

    ]

    otp_detected = False

    for pattern in otp_patterns:

        if re.search(pattern, normalized_message):

            otp_detected = True
            break

    if otp_detected:

        add_signal(
            25,
            "OTP or verification code mentioned"
        )


    # ==========================================
    # 6. FINANCIAL REQUEST
    # ==========================================

    financial_request_patterns = [

        r"\bsend\s+(money|payment|funds)\b",
        r"\btransfer\s+(money|funds)\b",
        r"\bmake\s+a\s+payment\b",
        r"\bpay\s+(the\s+)?fee\b",
        r"\bpay\s+(the\s+)?processing\s+fee\b",
        r"\brefund\s+fee\b",
        r"\bpayment\s+required\b",
        r"\bpayment\s+needed\b",
        r"\bwire\s+(money|funds)\b",
        r"\bdeposit\s+(money|funds)\b"

    ]

    financial_request_detected = False

    for pattern in financial_request_patterns:

        if re.search(pattern, normalized_message):

            financial_request_detected = True
            break

    if financial_request_detected:

        add_signal(
            20,
            "Financial payment or transfer request detected"
        )


    # ==========================================
    # 7. URGENCY / PRESSURE
    # ==========================================

    urgency_patterns = [

        r"\bact\s+now\b",
        r"\bact\s+immediately\b",
        r"\brespond\s+immediately\b",
        r"\bverify\s+immediately\b",
        r"\bdo\s+it\s+now\b",
        r"\bimmediately\b",
        r"\burgent\b",
        r"\burgently\b",
        r"\bas\s+soon\s+as\s+possible\b",
        r"\bwithin\s+\d+\s+(minutes?|hours?|days?)\b",
        r"\blimited\s+time\b",
        r"\btime\s+is\s+running\s+out\b",
        r"\blast\s+warning\b"

    ]

    urgency_detected = False

    for pattern in urgency_patterns:

        if re.search(pattern, normalized_message):

            urgency_detected = True
            break

    if urgency_detected:

        add_signal(
            15,
            "Urgency or pressure tactic detected"
        )


    # ==========================================
    # 8. ACCOUNT THREAT / CONSEQUENCE
    # ==========================================

    threat_patterns = [

        r"\baccount\s+will\s+be\s+closed\b",
        r"\baccount\s+will\s+be\s+blocked\b",
        r"\baccount\s+will\s+be\s+suspended\b",
        r"\baccount\s+has\s+been\s+suspended\b",
        r"\baccount\s+has\s+been\s+blocked\b",
        r"\baccount\s+is\s+suspended\b",
        r"\baccount\s+is\s+blocked\b",
        r"\baccount\s+termination\b",
        r"\bservice\s+will\s+be\s+terminated\b",
        r"\byour\s+access\s+will\s+be\s+removed\b",
        r"\byour\s+account\s+will\s+be\s+deleted\b"

    ]

    threat_detected = False

    for pattern in threat_patterns:

        if re.search(pattern, normalized_message):

            threat_detected = True
            break

    if threat_detected:

        add_signal(
            20,
            "Account threat or negative consequence detected"
        )


    # ==========================================
    # 9. PRIZE / REWARD SCAM
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

        if re.search(pattern, normalized_message):

            reward_detected = True
            break

    if reward_detected:

        add_signal(
            20,
            "Unexpected prize or reward claim detected"
        )


    # ==========================================
    # 10. CLICK / LINK CALL-TO-ACTION
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

        if re.search(pattern, normalized_message):

            click_detected = True
            break

    if click_detected:

        add_signal(
            10,
            "Suspicious call-to-action detected"
        )


    # ==========================================
    # 11. IMPERSONATION INDICATORS
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
            normalized_message
        ):

            impersonation_detected = True
            break


    # Do NOT mark the message risky only because an organization
    # name appears. It becomes more significant when combined
    # with other suspicious behavior.


    # ==========================================
    # 12. LOGIN / VERIFY ACTION
    # ==========================================

    login_patterns = [

        r"\blog\s*in\b",
        r"\blogin\b",
        r"\bsign\s+in\b",
        r"\bverify\s+your\s+account\b",
        r"\bconfirm\s+your\s+account\b",
        r"\bupdate\s+your\s+account\b",
        r"\bsecure\s+your\s+account\b"

    ]

    login_detected = False

    for pattern in login_patterns:

        if re.search(pattern, normalized_message):

            login_detected = True
            break

    if login_detected:

        add_signal(
            10,
            "Account login or verification action requested"
        )


    # ==========================================
    # 13. SUSPICIOUS DOMAIN CHARACTERISTICS
    # ==========================================

    suspicious_domain_patterns = [

        r"https?://[^\s]*@",
        r"https?://[^\s]*\.(?:xyz|top|click|win|loan|download)(?:[/:?#]|$)",
        r"https?://[^\s]*-{2,}[^\s]*",
        r"https?://[^\s]*\d{4,}[^\s]*"

    ]

    suspicious_domain_detected = False

    for pattern in suspicious_domain_patterns:

        if re.search(pattern, normalized_message):

            suspicious_domain_detected = True
            break

    if suspicious_domain_detected:

        add_signal(
            15,
            "Suspicious URL structure detected"
        )


    # ==========================================
    # 14. OBFUSCATED / MANIPULATED TEXT
    # ==========================================

    obfuscation_patterns = [

        r"p[\W_]*a[\W_]*s[\W_]*s[\W_]*w[\W_]*o[\W_]*r[\W_]*d",
        r"o[\W_]*t[\W_]*p",
        r"c[\W_]*v[\W_]*v",
        r"p[\W_]*i[\W_]*n"

    ]

    obfuscation_detected = False

    for pattern in obfuscation_patterns:

        if re.search(pattern, normalized_message):

            obfuscation_detected = True
            break

    if obfuscation_detected:

        add_signal(
            20,
            "Obfuscated sensitive information detected"
        )


    # ==========================================
    # 15. EXCESSIVE EXCLAMATION / PRESSURE STYLE
    # ==========================================

    exclamation_count = message.count("!")

    if exclamation_count >= 4:

        add_signal(
            5,
            "Excessive urgency-style punctuation detected"
        )


    # ==========================================
    # 16. VERY LONG MESSAGE
    # ==========================================

    if len(message) > 1000:

        add_signal(
            5,
            "Unusually long message"
        )


    # ==========================================
    # 17. COMBINATION ANALYSIS
    # ==========================================

    # Credential + urgency
    if credential_detected and urgency_detected:

        add_signal(
            15,
            "Credential request combined with urgency"
        )


    # Credential + URL
    if credential_detected and urls:

        add_signal(
            20,
            "Credential request combined with a link"
        )


    # OTP + financial request
    if otp_detected and financial_request_detected:

        add_signal(
            20,
            "OTP request combined with financial activity"
        )


    # URL + click action
    if urls and click_detected:

        add_signal(
            15,
            "Link combined with a click action"
        )


    # Account threat + urgency
    if threat_detected and urgency_detected:

        add_signal(
            15,
            "Account threat combined with urgency"
        )


    # Reward + click
    if reward_detected and click_detected:

        add_signal(
            20,
            "Prize or reward combined with a click request"
        )


    # Reward + URL
    if reward_detected and urls:

        add_signal(
            20,
            "Prize or reward combined with a suspicious link"
        )


    # Impersonation + credential request
    if impersonation_detected and credential_detected:

        add_signal(
            20,
            "Possible impersonation combined with credential request"
        )


    # Impersonation + URL
    if impersonation_detected and urls:

        add_signal(
            15,
            "Possible impersonation combined with a link"
        )


    # Impersonation + urgency
    if impersonation_detected and urgency_detected:

        add_signal(
            10,
            "Possible impersonation combined with urgency"
        )


    # Login + URL
    if login_detected and urls:

        add_signal(
            15,
            "Login or verification request combined with a link"
        )


    # ==========================================
    # 18. STRONG SOCIAL ENGINEERING COMBINATION
    # ==========================================

    behavioral_signals = sum([
        bool(credential_detected),
        bool(otp_detected),
        bool(financial_request_detected),
        bool(urgency_detected),
        bool(threat_detected),
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
    # 19. FINAL SCORE
    # ==========================================

    score = 100 - risk_points

    score = max(
        0,
        min(100, score)
    )


    # ==========================================
    # 20. FINAL RISK CLASSIFICATION
    # ==========================================

    if score >= 80:

        risk = "Safe"

    elif score >= 50:

        risk = "Suspicious"

    else:

        risk = "Dangerous"


    # ==========================================
    # 21. EMPTY REASONS
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
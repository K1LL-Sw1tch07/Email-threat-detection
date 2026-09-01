# backend/app/analyzer/content_analyzer.py

import re


URGENCY_KEYWORDS = {
    "urgent",
    "immediately",
    "immediate",
    "as soon as possible",
    "action required",
    "important",
    "warning",
}


ACCOUNT_KEYWORDS = {
    "account",
    "login",
    "sign in",
    "signin",
    "password",
    "credential",
    "verification",
    "verify",
    "security",
}


FINANCIAL_KEYWORDS = {
    "payment",
    "invoice",
    "bank",
    "transfer",
    "transaction",
    "refund",
    "credit card",
    "debit card",
}


THREAT_KEYWORDS = {
    "suspended",
    "blocked",
    "disabled",
    "locked",
    "terminated",
    "expire",
    "expired",
}


ACTION_PHRASES = {
    "click here",
    "click the link",
    "verify your account",
    "verify account",
    "confirm your account",
    "update your account",
    "reset your password",
    "sign in",
    "login",
}


def find_matches(text: str, keywords: set[str]) -> list[str]:

    text_lower = text.lower()

    matches = []

    for keyword in keywords:

        if keyword in text_lower:
            matches.append(keyword)

    return sorted(matches)


def analyze_content(body: dict, subject: str = "") -> list[dict]:
    """
    Analyze email subject and body for phishing/social-engineering signals.
    """

    indicators = []

    plain_text = body.get("plain_text", "") or ""
    html = body.get("html", "") or ""

    combined_text = f"{subject}\n{plain_text}\n{html}"

    # -----------------------------------------
    # Urgency
    # -----------------------------------------

    urgency_matches = find_matches(
        combined_text,
        URGENCY_KEYWORDS
    )

    if urgency_matches:

        indicators.append({
            "type": "URGENCY_LANGUAGE",
            "severity": "LOW",
            "description": (
                "The email uses urgency or pressure "
                "language."
            ),
            "matches": urgency_matches
        })

    # -----------------------------------------
    # Account / credential language
    # -----------------------------------------

    account_matches = find_matches(
        combined_text,
        ACCOUNT_KEYWORDS
    )

    if account_matches:

        indicators.append({
            "type": "ACCOUNT_SECURITY_LANGUAGE",
            "severity": "MEDIUM",
            "description": (
                "The email references accounts, "
                "credentials, login, or verification."
            ),
            "matches": account_matches
        })

    # -----------------------------------------
    # Financial language
    # -----------------------------------------

    financial_matches = find_matches(
        combined_text,
        FINANCIAL_KEYWORDS
    )

    if financial_matches:

        indicators.append({
            "type": "FINANCIAL_LANGUAGE",
            "severity": "MEDIUM",
            "description": (
                "The email contains financial or "
                "payment-related language."
            ),
            "matches": financial_matches
        })

    # -----------------------------------------
    # Threat / consequence language
    # -----------------------------------------

    threat_matches = find_matches(
        combined_text,
        THREAT_KEYWORDS
    )

    if threat_matches:

        indicators.append({
            "type": "THREAT_LANGUAGE",
            "severity": "MEDIUM",
            "description": (
                "The email threatens account or "
                "service consequences."
            ),
            "matches": threat_matches
        })

    # -----------------------------------------
    # Action / call-to-action phrases
    # -----------------------------------------

    action_matches = find_matches(
        combined_text,
        ACTION_PHRASES
    )

    if action_matches:

        indicators.append({
            "type": "SUSPICIOUS_CALL_TO_ACTION",
            "severity": "MEDIUM",
            "description": (
                "The email contains phrases commonly "
                "used to persuade users to perform "
                "an action."
            ),
            "matches": action_matches
        })

    # -----------------------------------------
    # Excessive exclamation marks
    # -----------------------------------------

    exclamation_count = combined_text.count("!")

    if exclamation_count >= 3:

        indicators.append({
            "type": "EXCESSIVE_EXCLAMATION",
            "severity": "LOW",
            "description": (
                "The email contains an unusually "
                "high number of exclamation marks."
            ),
            "count": exclamation_count
        })

    # -----------------------------------------
    # Credential request
    # -----------------------------------------

    credential_pattern = re.compile(
        r"\b(password|passcode|otp|one[- ]time password|"
        r"security code|verification code)\b",
        re.IGNORECASE
    )

    credential_matches = credential_pattern.findall(
        combined_text
    )

    if credential_matches:

        indicators.append({
            "type": "CREDENTIAL_REQUEST_LANGUAGE",
            "severity": "HIGH",
            "description": (
                "The email references passwords, OTPs, "
                "or other authentication credentials."
            ),
            "matches": sorted(
                set(
                    match.lower()
                    for match in credential_matches
                )
            )
        })

    return indicators
"""
Social engineering and BEC detection.

This module identifies behavioral and linguistic patterns
commonly associated with phishing, impersonation and
business email compromise.
"""


SOCIAL_ENGINEERING_INDICATORS = {
    "URGENCY_LANGUAGE",
    "ACCOUNT_SECURITY_LANGUAGE",
    "FINANCIAL_LANGUAGE",
    "THREAT_LANGUAGE",
    "SUSPICIOUS_CALL_TO_ACTION",
    "CREDENTIAL_REQUEST_LANGUAGE",
    "SUSPICIOUS_DISPLAY_NAME",
    "REPLY_TO_MISMATCH",
    "REPLY_DOMAIN_MISMATCH",
}


def analyze_social_engineering(evidence: dict) -> dict:
    """
    Analyze structured evidence for social engineering patterns.
    """

    indicators = evidence.get("indicators", [])

    matched = []

    for indicator in indicators:
        indicator_type = indicator.get("type")

        if indicator_type in SOCIAL_ENGINEERING_INDICATORS:
            matched.append(indicator)

    # ---------------------------------------------------------
    # Calculate behavioral signal
    # ---------------------------------------------------------

    severity_weights = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    signal_score = 0

    for indicator in matched:
        severity = indicator.get("severity", "LOW")
        signal_score += severity_weights.get(severity, 1)

    # ---------------------------------------------------------
    # Determine whether social engineering is present
    # ---------------------------------------------------------

    if signal_score >= 6:
        social_engineering = True
        confidence = 0.90

    elif signal_score >= 3:
        social_engineering = True
        confidence = 0.75

    else:
        social_engineering = False
        confidence = 0.80

    # ---------------------------------------------------------
    # Identify attack techniques
    # ---------------------------------------------------------

    techniques = []

    matched_types = {
        indicator.get("type")
        for indicator in matched
    }

    if "URGENCY_LANGUAGE" in matched_types:
        techniques.append("URGENCY")

    if "ACCOUNT_SECURITY_LANGUAGE" in matched_types:
        techniques.append("ACCOUNT_VERIFICATION")

    if "CREDENTIAL_REQUEST_LANGUAGE" in matched_types:
        techniques.append("CREDENTIAL_THEFT")

    if "FINANCIAL_LANGUAGE" in matched_types:
        techniques.append("FINANCIAL_FRAUD")

    if "THREAT_LANGUAGE" in matched_types:
        techniques.append("THREAT_OR_COERCION")

    if "SUSPICIOUS_CALL_TO_ACTION" in matched_types:
        techniques.append("PERSUASIVE_CALL_TO_ACTION")

    if (
        "SUSPICIOUS_DISPLAY_NAME" in matched_types
        or "REPLY_TO_MISMATCH" in matched_types
        or "REPLY_DOMAIN_MISMATCH" in matched_types
    ):
        techniques.append("IDENTITY_IMPERSONATION")

    # ---------------------------------------------------------
    # Generate explanations
    # ---------------------------------------------------------

    reasons = [
        indicator.get("description")
        for indicator in matched
        if indicator.get("description")
    ]

    return {
        "social_engineering": social_engineering,
        "confidence": round(confidence, 2),
        "signal_score": signal_score,
        "techniques": techniques,
        "reasons": reasons,
    }
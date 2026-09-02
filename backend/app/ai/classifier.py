"""
Phishing classification layer.

This module evaluates structured AI evidence and produces
an explainable phishing assessment.

The classifier does not replace forensic analysis.
It interprets evidence already produced by the backend.
"""


PHISHING_INDICATORS = {
    "SPF_FAILURE",
    "DKIM_FAILURE",
    "DMARC_FAILURE",
    "REPLY_TO_MISMATCH",
    "REPLY_DOMAIN_MISMATCH",
    "IP_BASED_URL",
    "SUSPICIOUS_URL_KEYWORD",
    "PUNYCODE_DOMAIN",
    "URL_SHORTENER",
    "CREDENTIAL_REQUEST_LANGUAGE",
    "ACCOUNT_SECURITY_LANGUAGE",
    "SUSPICIOUS_CALL_TO_ACTION",
    "URGENCY_LANGUAGE",
    "FINANCIAL_LANGUAGE",
    "THREAT_LANGUAGE",
    "DOMAIN_REPUTATION_HIGH",
    "DOMAIN_REPUTATION_SUSPICIOUS",
    "URL_REPUTATION_HIGH",
    "URL_REPUTATION_SUSPICIOUS",
    "IP_REPUTATION_HIGH",
    "IP_REPUTATION_SUSPICIOUS",
}


def classify_phishing(evidence: dict) -> dict:
    """
    Classify an email as likely phishing or non-phishing
    using structured forensic evidence.
    """

    indicators = evidence.get("indicators", [])

    matched_indicators = []

    for indicator in indicators:
        indicator_type = indicator.get("type")

        if indicator_type in PHISHING_INDICATORS:
            matched_indicators.append(indicator)

    # ---------------------------------------------------------
    # Calculate phishing signal
    # ---------------------------------------------------------

    severity_weights = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    signal_score = 0

    for indicator in matched_indicators:
        severity = indicator.get("severity", "LOW")
        signal_score += severity_weights.get(severity, 1)

    # ---------------------------------------------------------
    # Threat assessment from deterministic engine
    # ---------------------------------------------------------

    threat_assessment = evidence.get(
        "threat_assessment",
        {}
    )

    threat_score = threat_assessment.get("score", 0) or 0

    # ---------------------------------------------------------
    # Classification
    # ---------------------------------------------------------

    if threat_score >= 75 or signal_score >= 10:
        classification = "PHISHING"
        confidence = 0.90

    elif threat_score >= 50 or signal_score >= 6:
        classification = "LIKELY_PHISHING"
        confidence = 0.80

    elif threat_score >= 25 or signal_score >= 3:
        classification = "SUSPICIOUS"
        confidence = 0.65

    else:
        classification = "LIKELY_SAFE"
        confidence = 0.80

    # ---------------------------------------------------------
    # Evidence summary
    # ---------------------------------------------------------

    reasons = [
        indicator.get("description")
        for indicator in matched_indicators
        if indicator.get("description")
    ]

    return {
        "classification": classification,
        "confidence": round(confidence, 2),
        "signal_score": signal_score,
        "matched_indicators": [
            indicator.get("type")
            for indicator in matched_indicators
        ],
        "reasons": reasons,
    }
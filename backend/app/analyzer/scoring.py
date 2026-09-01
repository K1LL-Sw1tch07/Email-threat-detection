# backend/app/analyzer/scoring.py


INDICATOR_SCORES = {

    # Authentication
    "SPF_FAILURE": 20,
    "DKIM_FAILURE": 15,
    "DMARC_FAILURE": 20,

    # Identity
    "REPLY_TO_MISMATCH": 15,
    "REPLY_DOMAIN_MISMATCH": 10,

    # URL
    "IP_BASED_URL": 20,
    "UNENCRYPTED_URL": 10,
    "URL_SHORTENER": 10,
    "LONG_URL": 5,
    "SUSPICIOUS_URL_KEYWORD": 10,
    "PUNYCODE_DOMAIN": 15,
    "EXCESSIVE_SUBDOMAINS": 5,

    # Attachments
    "DANGEROUS_ATTACHMENT": 30,
    "MACRO_ENABLED_DOCUMENT": 25,
    "ARCHIVE_ATTACHMENT": 10,
    "DOUBLE_EXTENSION": 25,
    "MIME_EXTENSION_MISMATCH": 15,

    # Content / phishing
    "URGENCY_LANGUAGE": 5,
    "ACCOUNT_SECURITY_LANGUAGE": 10,
    "FINANCIAL_LANGUAGE": 10,
    "THREAT_LANGUAGE": 10,
    "SUSPICIOUS_CALL_TO_ACTION": 10,
    "EXCESSIVE_EXCLAMATION": 5,
    "CREDENTIAL_REQUEST_LANGUAGE": 20,

    # Authentication missing
    "AUTHENTICATION_UNKNOWN": 5,
}


def calculate_threat_score(indicators: list[dict]) -> dict:
    """
    Calculate an explainable threat score from detected indicators.
    """

    score = 0
    score_breakdown = []

    for indicator in indicators:

        indicator_type = indicator.get("type")

        points = INDICATOR_SCORES.get(
            indicator_type,
            0
        )

        score += points

        if points > 0:

            score_breakdown.append({
                "indicator": indicator_type,
                "points": points
            })

    # Keep score between 0 and 100
    score = min(score, 100)

    # -----------------------------------------
    # Determine risk level
    # -----------------------------------------

    if score >= 75:

        risk_level = "CRITICAL"

    elif score >= 50:

        risk_level = "HIGH"

    elif score >= 25:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # -----------------------------------------
    # Determine verdict
    # -----------------------------------------

    if score >= 75:

        verdict = "LIKELY_MALICIOUS"

    elif score >= 50:

        verdict = "SUSPICIOUS"

    elif score >= 25:

        verdict = "POTENTIALLY_SUSPICIOUS"

    else:

        verdict = "LIKELY_SAFE"

    # -----------------------------------------
    # Confidence
    # -----------------------------------------

    # Confidence is derived from the amount and
    # severity of supporting evidence.

    high_severity_count = sum(
        1
        for indicator in indicators
        if indicator.get("severity") == "HIGH"
    )

    medium_severity_count = sum(
        1
        for indicator in indicators
        if indicator.get("severity") == "MEDIUM"
    )

    evidence_count = len(indicators)

    confidence = 0.50

    confidence += min(
        high_severity_count * 0.10,
        0.30
    )

    confidence += min(
        medium_severity_count * 0.05,
        0.15
    )

    confidence += min(
        evidence_count * 0.01,
        0.05
    )

    # A very low-risk email should not receive
    # artificially high confidence.
    if score < 25:

        confidence = min(
            confidence,
            0.70
        )

    confidence = min(
        confidence,
        0.99
    )

    confidence = round(
        confidence,
        2
    )

    # -----------------------------------------
    # Generate evidence
    # -----------------------------------------

    evidence = []

    for indicator in indicators:

        description = indicator.get(
            "description"
        )

        if description:
            evidence.append(description)

    # -----------------------------------------
    # Recommended actions
    # -----------------------------------------

    recommended_actions = []

    if score >= 75:

        recommended_actions.extend([
            "Do not click links in the email.",
            "Do not open or execute attachments.",
            "Do not reply to the sender.",
            "Verify the sender through an independent channel.",
            "Quarantine the email for further investigation."
        ])

    elif score >= 50:

        recommended_actions.extend([
            "Treat the email with caution.",
            "Avoid clicking links or opening attachments.",
            "Verify the sender independently."
        ])

    elif score >= 25:

        recommended_actions.extend([
            "Review the email carefully.",
            "Verify suspicious links and sender information."
        ])

    else:

        recommended_actions.append(
            "No immediate high-risk indicators detected."
        )

    # -----------------------------------------
    # Final assessment
    # -----------------------------------------

    return {

        "score": score,

        "risk_level": risk_level,

        "verdict": verdict,

        "confidence": confidence,

        "breakdown": score_breakdown,

        "evidence": evidence,

        "recommended_actions": recommended_actions
    }
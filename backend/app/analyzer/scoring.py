# backend/app/analyzer/scoring.py

"""
Explainable threat scoring for the email forensic engine.

The scoring model is deterministic for the MVP.
Each evidence category has a bounded contribution so
related indicators cannot inflate the final score simply
because there are many of them.
"""

from collections import defaultdict


# ---------------------------------------------------------
# Individual indicator scores
# ---------------------------------------------------------

INDICATOR_SCORES = {

    # Authentication
    "SPF_FAILURE": 20,
    "DKIM_FAILURE": 15,
    "DMARC_FAILURE": 20,
    "AUTHENTICATION_UNKNOWN": 5,

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

     # Reputation / Threat Intelligence
    "IP_REPUTATION_HIGH": 10,
    "IP_REPUTATION_SUSPICIOUS": 5,
    "DOMAIN_REPUTATION_HIGH": 10,
    "DOMAIN_REPUTATION_SUSPICIOUS": 5,
    "URL_REPUTATION_HIGH": 10,
    "URL_REPUTATION_SUSPICIOUS": 5,
}


# ---------------------------------------------------------
# Maximum contribution from each evidence category
# ---------------------------------------------------------
CATEGORY_LIMITS = {
    "authentication": 25,
    "identity": 20,
    "url": 15,
    "attachment": 15,
    "content": 15,
    "reputation": 10,
}


# ---------------------------------------------------------
# Indicator → category mapping
# ---------------------------------------------------------

INDICATOR_CATEGORIES = {

    # Authentication
    "SPF_FAILURE": "authentication",
    "DKIM_FAILURE": "authentication",
    "DMARC_FAILURE": "authentication",
    "AUTHENTICATION_UNKNOWN": "authentication",

    # Identity
    "REPLY_TO_MISMATCH": "identity",
    "REPLY_DOMAIN_MISMATCH": "identity",

    # URL
    "IP_BASED_URL": "url",
    "UNENCRYPTED_URL": "url",
    "URL_SHORTENER": "url",
    "LONG_URL": "url",
    "SUSPICIOUS_URL_KEYWORD": "url",
    "PUNYCODE_DOMAIN": "url",
    "EXCESSIVE_SUBDOMAINS": "url",

    # Attachments
    "DANGEROUS_ATTACHMENT": "attachment",
    "MACRO_ENABLED_DOCUMENT": "attachment",
    "ARCHIVE_ATTACHMENT": "attachment",
    "DOUBLE_EXTENSION": "attachment",
    "MIME_EXTENSION_MISMATCH": "attachment",

    # Content
    "URGENCY_LANGUAGE": "content",
    "ACCOUNT_SECURITY_LANGUAGE": "content",
    "FINANCIAL_LANGUAGE": "content",
    "THREAT_LANGUAGE": "content",
    "SUSPICIOUS_CALL_TO_ACTION": "content",
    "EXCESSIVE_EXCLAMATION": "content",
    "CREDENTIAL_REQUEST_LANGUAGE": "content",

    # Reputation
    "IP_REPUTATION_HIGH": "reputation",
    "IP_REPUTATION_SUSPICIOUS": "reputation",
    "DOMAIN_REPUTATION_HIGH": "reputation",
    "DOMAIN_REPUTATION_SUSPICIOUS": "reputation",
    "URL_REPUTATION_HIGH": "reputation",
    "URL_REPUTATION_SUSPICIOUS": "reputation",
}


# ---------------------------------------------------------
# Helper
# ---------------------------------------------------------

def _category_for(indicator_type: str) -> str:

    return INDICATOR_CATEGORIES.get(
        indicator_type,
        "other"
    )


# ---------------------------------------------------------
# Main scoring function
# ---------------------------------------------------------

def calculate_threat_score(
    indicators: list[dict]
) -> dict:

    """
    Calculate a bounded and explainable threat score.

    Each evidence category has its own maximum contribution.
    This prevents one category from dominating the entire score.
    """

    category_totals = defaultdict(int)

    raw_breakdown = []


    # -----------------------------------------------------
    # Calculate raw indicator scores
    # -----------------------------------------------------

    for indicator in indicators:

        indicator_type = indicator.get("type")

        points = INDICATOR_SCORES.get(
            indicator_type,
            0
        )

        if points <= 0:
            continue

        category = _category_for(
            indicator_type
        )

        category_totals[category] += points

        raw_breakdown.append({
            "indicator": indicator_type,
            "points": points,
            "category": category,
        })


    # -----------------------------------------------------
    # Apply category limits
    # -----------------------------------------------------

    category_breakdown = []

    bounded_score = 0

    for category, limit in CATEGORY_LIMITS.items():

        raw_score = category_totals.get(
            category,
            0
        )

        capped_score = min(
            raw_score,
            limit
        )

        bounded_score += capped_score

        if raw_score > 0:

            category_breakdown.append({

                "category": category,

                "score": capped_score,

                "max_score": limit,

                "raw_score": raw_score,
            })


    # -----------------------------------------------------
    # Normalize to 0–100
    # -----------------------------------------------------

    score = min(
        bounded_score,
        100
    )

    


    # -----------------------------------------------------
    # Risk level
    # -----------------------------------------------------

    if score >= 75:

        risk_level = "CRITICAL"

        verdict = "LIKELY_MALICIOUS"

    elif score >= 50:

        risk_level = "HIGH"

        verdict = "SUSPICIOUS"

    elif score >= 25:

        risk_level = "MEDIUM"

        verdict = "POTENTIALLY_SUSPICIOUS"

    else:

        risk_level = "LOW"

        verdict = "LIKELY_SAFE"


    # -----------------------------------------------------
    # Confidence
    # -----------------------------------------------------

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
        high_severity_count * 0.08,
        0.24
    )


    confidence += min(
        medium_severity_count * 0.04,
        0.12
    )


    confidence += min(
        evidence_count * 0.01,
        0.05
    )


    # Low-risk emails should not receive
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


    # -----------------------------------------------------
    # Evidence
    # -----------------------------------------------------

    evidence = [

        indicator.get("description")

        for indicator in indicators

        if indicator.get("description")
    ]


    # -----------------------------------------------------
    # Recommended actions
    # -----------------------------------------------------

    if score >= 75:

        recommended_actions = [

            "Do not click links in the email.",

            "Do not open or execute attachments.",

            "Do not reply to the sender.",

            "Verify the sender through an independent channel.",

            "Quarantine the email for further investigation.",
        ]


    elif score >= 50:

        recommended_actions = [

            "Treat the email with caution.",

            "Avoid clicking links or opening attachments.",

            "Verify the sender independently.",
        ]


    elif score >= 25:

        recommended_actions = [

            "Review the email carefully.",

            "Verify suspicious links and sender information.",
        ]


    else:

        recommended_actions = [

            "No immediate high-risk indicators detected."
        ]


    # -----------------------------------------------------
    # Final assessment
    # -----------------------------------------------------

    return {

        "score": score,

        "risk_level": risk_level,

        "verdict": verdict,

        "confidence": confidence,

        "breakdown": raw_breakdown,

        "category_breakdown": category_breakdown,

        "evidence": evidence,

        "recommended_actions": recommended_actions,
    }
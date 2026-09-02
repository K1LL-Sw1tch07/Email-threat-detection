"""
Attack type classification.

This module determines the most likely attack category
from structured forensic and behavioral evidence.

It does not make independent forensic claims.
"""


def classify_attack_type(evidence: dict) -> dict:
    """
    Determine the most likely attack type.
    """

    indicators = evidence.get("indicators", [])

    indicator_types = {
        indicator.get("type")
        for indicator in indicators
    }

    phishing_assessment = evidence.get(
        "phishing_assessment",
        {}
    )

    classification = phishing_assessment.get(
        "classification"
    )

    # ---------------------------------------------------------
    # Credential phishing
    # ---------------------------------------------------------

    credential_signals = {
        "CREDENTIAL_REQUEST_LANGUAGE",
        "ACCOUNT_SECURITY_LANGUAGE",
        "SUSPICIOUS_CALL_TO_ACTION",
        "SUSPICIOUS_URL_KEYWORD",
    }

    credential_matches = (
        indicator_types & credential_signals
    )

    if len(credential_matches) >= 2:
        return {
            "attack_type": "CREDENTIAL_PHISHING",
            "confidence": 0.90,
            "evidence": list(credential_matches),
        }

    # ---------------------------------------------------------
    # Business Email Compromise
    # ---------------------------------------------------------

    bec_signals = {
        "FINANCIAL_LANGUAGE",
        "REPLY_TO_MISMATCH",
        "REPLY_DOMAIN_MISMATCH",
    }

    bec_matches = indicator_types & bec_signals

    if (
        "FINANCIAL_LANGUAGE" in indicator_types
        and len(bec_matches) >= 2
    ):
        return {
            "attack_type": "BUSINESS_EMAIL_COMPROMISE",
            "confidence": 0.85,
            "evidence": list(bec_matches),
        }

    # ---------------------------------------------------------
    # Financial fraud
    # ---------------------------------------------------------

    if "FINANCIAL_LANGUAGE" in indicator_types:
        return {
            "attack_type": "FINANCIAL_FRAUD",
            "confidence": 0.80,
            "evidence": ["FINANCIAL_LANGUAGE"],
        }

    # ---------------------------------------------------------
    # Malware delivery
    # ---------------------------------------------------------

    malware_signals = {
        "DANGEROUS_ATTACHMENT",
        "MACRO_ENABLED_DOCUMENT",
        "ARCHIVE_ATTACHMENT",
        "DOUBLE_EXTENSION",
        "MIME_EXTENSION_MISMATCH",
    }

    malware_matches = indicator_types & malware_signals

    if malware_matches:
        return {
            "attack_type": "MALWARE_DELIVERY",
            "confidence": 0.90,
            "evidence": list(malware_matches),
        }

    # ---------------------------------------------------------
    # Impersonation
    # ---------------------------------------------------------

    impersonation_signals = {
        "SUSPICIOUS_DISPLAY_NAME",
        "REPLY_TO_MISMATCH",
        "REPLY_DOMAIN_MISMATCH",
    }

    impersonation_matches = (
        indicator_types & impersonation_signals
    )

    if len(impersonation_matches) >= 2:
        return {
            "attack_type": "IMPERSONATION",
            "confidence": 0.80,
            "evidence": list(impersonation_matches),
        }

    # ---------------------------------------------------------
    # Generic phishing
    # ---------------------------------------------------------

    if classification in {
        "PHISHING",
        "LIKELY_PHISHING",
    }:
        return {
            "attack_type": "GENERIC_PHISHING",
            "confidence": 0.75,
            "evidence": [
                "PHISHING_CLASSIFICATION"
            ],
        }

    # ---------------------------------------------------------
    # Suspicious email
    # ---------------------------------------------------------

    if classification == "SUSPICIOUS":
        return {
            "attack_type": "SUSPICIOUS_EMAIL",
            "confidence": 0.65,
            "evidence": [
                "SUSPICIOUS_CLASSIFICATION"
            ],
        }

    # ---------------------------------------------------------
    # Likely safe
    # ---------------------------------------------------------

    return {
        "attack_type": "LIKELY_SAFE",
        "confidence": 0.80,
        "evidence": [],
    }
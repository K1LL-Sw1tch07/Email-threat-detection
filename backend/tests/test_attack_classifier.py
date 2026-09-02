from app.ai.attack_classifier import classify_attack_type


def test_credential_phishing():

    evidence = {
        "indicators": [
            {
                "type": "ACCOUNT_SECURITY_LANGUAGE",
                "severity": "MEDIUM",
                "description": "Account verification language detected."
            },
            {
                "type": "SUSPICIOUS_URL_KEYWORD",
                "severity": "MEDIUM",
                "description": "Login URL detected."
            },
            {
                "type": "SUSPICIOUS_CALL_TO_ACTION",
                "severity": "MEDIUM",
                "description": "Verify account action detected."
            },
        ],
        "phishing_assessment": {
            "classification": "PHISHING"
        }
    }

    result = classify_attack_type(evidence)

    assert result["attack_type"] == "CREDENTIAL_PHISHING"
    assert result["confidence"] > 0
    assert len(result["evidence"]) >= 2


def test_malware_delivery():

    evidence = {
        "indicators": [
            {
                "type": "DANGEROUS_ATTACHMENT",
                "severity": "HIGH",
                "description": "Dangerous attachment detected."
            }
        ],
        "phishing_assessment": {
            "classification": "PHISHING"
        }
    }

    result = classify_attack_type(evidence)

    assert result["attack_type"] == "MALWARE_DELIVERY"


def test_financial_fraud():

    evidence = {
        "indicators": [
            {
                "type": "FINANCIAL_LANGUAGE",
                "severity": "MEDIUM",
                "description": "Financial language detected."
            }
        ],
        "phishing_assessment": {
            "classification": "SUSPICIOUS"
        }
    }

    result = classify_attack_type(evidence)

    assert result["attack_type"] == "FINANCIAL_FRAUD"


def test_safe_email():

    evidence = {
        "indicators": [],
        "phishing_assessment": {
            "classification": "LIKELY_SAFE"
        }
    }

    result = classify_attack_type(evidence)

    assert result["attack_type"] == "LIKELY_SAFE"
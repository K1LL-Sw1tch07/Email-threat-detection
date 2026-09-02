from app.ai.classifier import classify_phishing


def test_phishing_email():

    evidence = {
        "indicators": [
            {
                "type": "SPF_FAILURE",
                "severity": "HIGH",
                "description": "SPF authentication failed."
            },
            {
                "type": "DMARC_FAILURE",
                "severity": "HIGH",
                "description": "DMARC authentication failed."
            },
            {
                "type": "REPLY_TO_MISMATCH",
                "severity": "MEDIUM",
                "description": "Reply-To domain differs from sender domain."
            },
            {
                "type": "CREDENTIAL_REQUEST_LANGUAGE",
                "severity": "HIGH",
                "description": "The email requests credentials."
            },
        ],
        "threat_assessment": {
            "score": 85
        }
    }

    result = classify_phishing(evidence)

    assert result["classification"] == "PHISHING"
    assert result["confidence"] > 0
    assert "SPF_FAILURE" in result["matched_indicators"]


def test_suspicious_email():

    evidence = {
        "indicators": [
            {
                "type": "URGENCY_LANGUAGE",
                "severity": "LOW",
                "description": "Urgent language detected."
            },
            {
                "type": "SUSPICIOUS_URL_KEYWORD",
                "severity": "MEDIUM",
                "description": "Suspicious URL keyword detected."
            },
        ],
        "threat_assessment": {
            "score": 35
        }
    }

    result = classify_phishing(evidence)

    assert result["classification"] == "SUSPICIOUS"


def test_safe_email():

    evidence = {
        "indicators": [],
        "threat_assessment": {
            "score": 10
        }
    }

    result = classify_phishing(evidence)

    assert result["classification"] == "LIKELY_SAFE"
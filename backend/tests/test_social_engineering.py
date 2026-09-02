from app.ai.social_engineering import analyze_social_engineering


def test_social_engineering_detection():

    evidence = {
        "indicators": [
            {
                "type": "URGENCY_LANGUAGE",
                "severity": "LOW",
                "description": "Urgent language detected."
            },
            {
                "type": "ACCOUNT_SECURITY_LANGUAGE",
                "severity": "MEDIUM",
                "description": "Account verification language detected."
            },
            {
                "type": "REPLY_DOMAIN_MISMATCH",
                "severity": "MEDIUM",
                "description": "Sender and Reply-To domains differ."
            },
            {
                "type": "SUSPICIOUS_CALL_TO_ACTION",
                "severity": "MEDIUM",
                "description": "Suspicious call to action detected."
            },
        ]
    }

    result = analyze_social_engineering(evidence)

    assert result["social_engineering"] is True
    assert result["confidence"] > 0
    assert "URGENCY" in result["techniques"]
    assert "ACCOUNT_VERIFICATION" in result["techniques"]
    assert "IDENTITY_IMPERSONATION" in result["techniques"]


def test_non_social_engineering_email():

    evidence = {
        "indicators": []
    }

    result = analyze_social_engineering(evidence)

    assert result["social_engineering"] is False
    assert result["techniques"] == []
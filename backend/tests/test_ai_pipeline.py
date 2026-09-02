from app.ai.pipeline import run_ai_analysis


def test_full_ai_pipeline():

    result = {
        "headers": {
            "from": "Security Team <security@example.com>",
            "to": "user@example.com",
            "reply_to": "attacker@example.net",
            "subject": "Urgent Account Verification",
        },

        "authentication": {
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
        },

        "origin_analysis": {
            "earliest_reliable_ip": None,
            "confidence": 0.0,
            "reason": "No reliable public origin IP.",
            "candidate_ips": [],
            "global_ips": [],
            "excluded_ips": [],
        },

        "domains": {
            "sender_domain": "example.com",
        },

        "urls": [
            {
                "url": "https://example.com/login",
                "domain": "example.com",
                "scheme": "https",
                "indicators": [
                    "SUSPICIOUS_URL_KEYWORD"
                ],
            }
        ],

        "ip_reputation": [],

        "domain_reputation": [],

        "url_reputation": [],

        "indicators": [
            {
                "type": "SPF_FAILURE",
                "severity": "HIGH",
                "description": "SPF authentication failed.",
            },
            {
                "type": "DKIM_FAILURE",
                "severity": "HIGH",
                "description": "DKIM authentication failed.",
            },
            {
                "type": "DMARC_FAILURE",
                "severity": "HIGH",
                "description": "DMARC authentication failed.",
            },
            {
                "type": "REPLY_TO_MISMATCH",
                "severity": "MEDIUM",
                "description": "Reply-To differs from the sender.",
            },
            {
                "type": "REPLY_DOMAIN_MISMATCH",
                "severity": "MEDIUM",
                "description": "Sender and Reply-To domains differ.",
            },
            {
                "type": "SUSPICIOUS_URL_KEYWORD",
                "severity": "MEDIUM",
                "description": "URL contains a security-sensitive keyword.",
            },
            {
                "type": "URGENCY_LANGUAGE",
                "severity": "LOW",
                "description": "Urgency language detected.",
            },
            {
                "type": "ACCOUNT_SECURITY_LANGUAGE",
                "severity": "MEDIUM",
                "description": "Account verification language detected.",
            },
            {
                "type": "SUSPICIOUS_CALL_TO_ACTION",
                "severity": "MEDIUM",
                "description": "Suspicious call-to-action detected.",
            },
        ],

        "threat_assessment": {
            "score": 70,
            "risk_level": "HIGH",
            "verdict": "SUSPICIOUS",
            "confidence": 0.91,
        },
    }

    ai_result = run_ai_analysis(result)

    assert "ai_evidence" in ai_result
    assert "phishing_assessment" in ai_result
    assert "social_engineering_assessment" in ai_result
    assert "attack_type_assessment" in ai_result
    assert "investigation_summary" in ai_result

    assert (
        ai_result["phishing_assessment"]["classification"]
        == "PHISHING"
    )

    assert (
        ai_result["social_engineering_assessment"]
        ["social_engineering"]
        is True
    )

    assert (
        ai_result["attack_type_assessment"]["attack_type"]
        == "CREDENTIAL_PHISHING"
    )

    assert (
        ai_result["investigation_summary"]["attack_type"]
        == "CREDENTIAL_PHISHING"
    )

    assert (
        ai_result["investigation_summary"]["risk_level"]
        == "HIGH"
    )
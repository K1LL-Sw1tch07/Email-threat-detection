from app.ai.summarizer import generate_investigation_summary


def test_credential_phishing_summary():

    evidence = {
        "threat_assessment": {
            "score": 70,
            "risk_level": "HIGH",
            "verdict": "SUSPICIOUS",
            "confidence": 0.91,
        },

        "phishing_assessment": {
            "classification": "PHISHING",
            "confidence": 0.90,
        },

        "social_engineering_assessment": {
            "social_engineering": True,
            "confidence": 0.90,
        },

        "attack_type_assessment": {
            "attack_type": "CREDENTIAL_PHISHING",
            "confidence": 0.90,
        },

        "indicators": [
            {
                "type": "SPF_FAILURE",
                "severity": "HIGH",
                "description": "SPF authentication failed.",
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
        ],

        "origin": {
            "earliest_reliable_ip": None,
        },

        "urls": [
            {
                "url": "https://example.com/login",
                "domain": "example.com",
            }
        ],

        "reputation": {
            "ip": [],
            "domain": [],
            "url": [],
        },
    }

    result = generate_investigation_summary(evidence)

    assert result["attack_type"] == "CREDENTIAL_PHISHING"
    assert result["risk_level"] == "HIGH"
    assert result["threat_score"] == 70
    assert result["phishing_classification"] == "PHISHING"
    assert result["social_engineering"] is True
    assert result["confidence"] == 0.90
    assert len(result["key_findings"]) > 0
    assert "credential phishing" in result["summary"].lower()


def test_malware_summary():

    evidence = {
        "threat_assessment": {
            "score": 80,
            "risk_level": "CRITICAL",
            "verdict": "LIKELY_MALICIOUS",
            "confidence": 0.95,
        },

        "phishing_assessment": {
            "classification": "PHISHING",
            "confidence": 0.90,
        },

        "attack_type_assessment": {
            "attack_type": "MALWARE_DELIVERY",
            "confidence": 0.90,
        },

        "indicators": [
            {
                "type": "DANGEROUS_ATTACHMENT",
                "severity": "HIGH",
                "description": "Dangerous attachment detected.",
            }
        ],

        "origin": {
            "earliest_reliable_ip": "198.51.100.10",
        },

        "urls": [],

        "reputation": {
            "ip": [],
            "domain": [],
            "url": [],
        },
    }

    result = generate_investigation_summary(evidence)

    assert result["attack_type"] == "MALWARE_DELIVERY"
    assert result["risk_level"] == "CRITICAL"
    assert result["threat_score"] == 80
    assert "malware delivery" in result["summary"].lower()
    assert "198.51.100.10" in result["summary"]


def test_safe_email_summary():

    evidence = {
        "threat_assessment": {
            "score": 10,
            "risk_level": "LOW",
            "verdict": "LIKELY_SAFE",
            "confidence": 0.60,
        },

        "phishing_assessment": {
            "classification": "LIKELY_SAFE",
            "confidence": 0.80,
        },

        "attack_type_assessment": {
            "attack_type": "LIKELY_SAFE",
            "confidence": 0.80,
        },

        "indicators": [],

        "origin": {
            "earliest_reliable_ip": None,
        },

        "urls": [],

        "reputation": {
            "ip": [],
            "domain": [],
            "url": [],
        },
    }

    result = generate_investigation_summary(evidence)

    assert result["attack_type"] == "LIKELY_SAFE"
    assert result["risk_level"] == "LOW"
    assert result["threat_score"] == 10
    assert result["phishing_classification"] == "LIKELY_SAFE"
    assert "no strong malicious pattern" in result["summary"].lower()
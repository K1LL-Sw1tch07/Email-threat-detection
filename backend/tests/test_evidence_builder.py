from app.ai.evidence_builder import build_ai_evidence


def test_build_ai_evidence():
    result = {
        "headers": {
            "from": "Security Team <security@example.com>",
            "to": "user@example.com",
            "reply_to": "attacker@example.net",
            "subject": "Urgent Account Verification",
        },
        "domains": {
            "sender_domain": "example.com",
        },
        "authentication": {
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
        },
        "origin_analysis": {
            "status": "NO_RELIABLE_ORIGIN",
            "earliest_reliable_ip": None,
            "country": None,
            "city": None,
            "isp": None,
        },
        "urls": [
            {
                "url": "https://example.com/login",
                "domain": "example.com",
                "scheme": "https",
                "indicators": [
                    "SUSPICIOUS_URL_KEYWORD",
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
                "description": "SPF authentication failed",
            }
        ],
        "threat_assessment": {
            "score": 70,
            "risk_level": "HIGH",
            "verdict": "SUSPICIOUS",
            "confidence": 0.91,
        },
    }

    evidence = build_ai_evidence(result)

    assert evidence["sender"] == "Security Team <security@example.com>"
    assert evidence["reply_to"] == "attacker@example.net"
    assert evidence["sender_domain"] == "example.com"

    assert evidence["authentication"]["spf"] == "fail"
    assert evidence["authentication"]["dkim"] == "fail"
    assert evidence["authentication"]["dmarc"] == "fail"

    assert len(evidence["urls"]) == 1
    assert evidence["urls"][0]["domain"] == "example.com"

    assert evidence["threat_assessment"]["score"] == 70
    assert evidence["threat_assessment"]["risk_level"] == "HIGH"

    assert evidence["indicators"][0]["type"] == "SPF_FAILURE"
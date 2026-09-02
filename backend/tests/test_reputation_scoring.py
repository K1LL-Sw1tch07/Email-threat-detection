from app.analyzer.scoring import calculate_threat_score


def test_high_ip_reputation_increases_score():
    indicators = [
        {
            "type": "IP_REPUTATION_HIGH",
            "severity": "HIGH",
            "description": "IP has high abuse reputation",
        }
    ]

    result = calculate_threat_score(indicators)

    assert result["score"] == 10
    assert result["category_breakdown"][0]["category"] == "reputation"


def test_suspicious_ip_reputation():
    indicators = [
        {
            "type": "IP_REPUTATION_SUSPICIOUS",
            "severity": "MEDIUM",
            "description": "IP has suspicious reputation",
        }
    ]

    result = calculate_threat_score(indicators)

    assert result["score"] == 5
    assert result["category_breakdown"][0]["category"] == "reputation"


def test_high_domain_reputation():
    indicators = [
        {
            "type": "DOMAIN_REPUTATION_HIGH",
            "severity": "HIGH",
            "description": "Domain has malicious reputation",
        }
    ]

    result = calculate_threat_score(indicators)

    assert result["score"] == 10
    assert result["category_breakdown"][0]["category"] == "reputation"


def test_suspicious_domain_reputation():
    indicators = [
        {
            "type": "DOMAIN_REPUTATION_SUSPICIOUS",
            "severity": "MEDIUM",
            "description": "Domain has suspicious reputation",
        }
    ]

    result = calculate_threat_score(indicators)

    assert result["score"] == 5
    assert result["category_breakdown"][0]["category"] == "reputation"


def test_high_url_reputation():
    indicators = [
        {
            "type": "URL_REPUTATION_HIGH",
            "severity": "HIGH",
            "description": "URL has malicious reputation",
        }
    ]

    result = calculate_threat_score(indicators)

    assert result["score"] == 10
    assert result["category_breakdown"][0]["category"] == "reputation"


def test_suspicious_url_reputation():
    indicators = [
        {
            "type": "URL_REPUTATION_SUSPICIOUS",
            "severity": "MEDIUM",
            "description": "URL has suspicious reputation",
        }
    ]

    result = calculate_threat_score(indicators)

    assert result["score"] == 5
    assert result["category_breakdown"][0]["category"] == "reputation"
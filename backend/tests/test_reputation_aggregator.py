from app.intelligence.reputation_aggregator import (
    aggregate_ip_reputation,
    aggregate_domain_reputation,
    aggregate_url_reputation,
    aggregate_reputation
)


def test_high_ip_reputation():

    result = aggregate_ip_reputation({
        "ip": "1.2.3.4",
        "found": True,
        "provider": "AbuseIPDB",
        "abuse_score": 90
    })

    assert len(result) == 1
    assert result[0]["type"] == "IP_REPUTATION_HIGH"
    assert result[0]["severity"] == "HIGH"


def test_suspicious_ip_reputation():

    result = aggregate_ip_reputation({
        "ip": "1.2.3.4",
        "found": True,
        "provider": "AbuseIPDB",
        "abuse_score": 60
    })

    assert len(result) == 1
    assert result[0]["type"] == "IP_REPUTATION_SUSPICIOUS"
    assert result[0]["severity"] == "MEDIUM"


def test_clean_ip_creates_no_indicator():

    result = aggregate_ip_reputation({
        "ip": "8.8.8.8",
        "found": True,
        "provider": "AbuseIPDB",
        "abuse_score": 0
    })

    assert result == []


def test_high_domain_reputation():

    result = aggregate_domain_reputation({
        "domain": "malicious.example",
        "found": True,
        "provider": "VirusTotal",
        "malicious_votes": 10,
        "suspicious_votes": 0,
        "total_engines": 90
    })

    assert len(result) == 1
    assert result[0]["type"] == "DOMAIN_REPUTATION_HIGH"


def test_suspicious_domain_reputation():

    result = aggregate_domain_reputation({
        "domain": "suspicious.example",
        "found": True,
        "provider": "VirusTotal",
        "malicious_votes": 2,
        "suspicious_votes": 0,
        "total_engines": 90
    })

    assert len(result) == 1
    assert result[0]["type"] == "DOMAIN_REPUTATION_SUSPICIOUS"


def test_clean_domain_creates_no_indicator():

    result = aggregate_domain_reputation({
        "domain": "google.com",
        "found": True,
        "provider": "VirusTotal",
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "total_engines": 90
    })

    assert result == []


def test_high_url_reputation():

    result = aggregate_url_reputation({
        "url": "https://malicious.example",
        "found": True,
        "provider": "VirusTotal",
        "malicious_votes": 8,
        "suspicious_votes": 0,
        "total_engines": 90
    })

    assert len(result) == 1
    assert result[0]["type"] == "URL_REPUTATION_HIGH"


def test_aggregate_reputation():

    result = aggregate_reputation(
        ip_results=[
            {
                "ip": "1.2.3.4",
                "found": True,
                "provider": "AbuseIPDB",
                "abuse_score": 90
            }
        ],
        domain_results=[
            {
                "domain": "malicious.example",
                "found": True,
                "provider": "VirusTotal",
                "malicious_votes": 10,
                "suspicious_votes": 0,
                "total_engines": 90
            }
        ],
        url_results=[
            {
                "url": "https://malicious.example",
                "found": True,
                "provider": "VirusTotal",
                "malicious_votes": 8,
                "suspicious_votes": 0,
                "total_engines": 90
            }
        ]
    )

    assert len(result) == 3
from io import BytesIO

from fastapi.testclient import TestClient

import app.main as main


client = TestClient(main.app)


TEST_EML = """From: Security Team <security@example.com>
To: user@example.com
Reply-To: attacker@example.net
Subject: Urgent Account Verification
Message-ID: <test123@example.com>
Received: from suspicious.example.net [8.8.8.8] by mail.example.com;
        Mon, 01 Sep 2026 10:00:00 +0000
Content-Type: text/plain; charset="utf-8"

URGENT! Your account security requires immediate verification.
Please login to verify your account.

https://example.com/login
"""


def test_reputation_flows_into_threat_assessment(monkeypatch):
    def mock_ip_reputation(ip):
        return {
            "ip": ip,
            "found": True,
            "malicious": True,
            "confidence": 95,
            "provider": "AbuseIPDB",
            "abuse_score": 95,
            "country": "US",
            "isp": "Test ISP",
            "domain": "test.example",
            "total_reports": 100,
            "last_reported_at": None,
            "error": None,
        }

    def mock_domain_reputation(domain):
        return {
            "domain": domain,
            "found": True,
            "malicious": True,
            "suspicious": False,
            "confidence": 90,
            "provider": "VirusTotal",
            "categories": {},
            "malicious_votes": 10,
            "suspicious_votes": 0,
            "total_engines": 90,
            "reputation": -10,
            "error": None,
        }

    def mock_url_reputation(url):
        return {
            "url": url,
            "found": True,
            "malicious": True,
            "suspicious": False,
            "confidence": 90,
            "provider": "VirusTotal",
            "categories": {},
            "malicious_votes": 10,
            "suspicious_votes": 0,
            "total_engines": 90,
            "reputation": -10,
            "error": None,
        }

    monkeypatch.setattr(
        main,
        "check_ip_reputation",
        mock_ip_reputation,
    )

    monkeypatch.setattr(
        main,
        "check_domain_reputation",
        mock_domain_reputation,
    )

    monkeypatch.setattr(
        main,
        "check_url_reputation",
        mock_url_reputation,
    )

    response = client.post(
        "/api/email/analyze",
        files={
            "file": (
                "reputation_test.eml",
                BytesIO(TEST_EML.encode("utf-8")),
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True

    analysis = data["analysis"]

    assert len(analysis["ip_reputation"]) > 0
    assert len(analysis["domain_reputation"]) > 0
    assert len(analysis["url_reputation"]) > 0

    reputation_types = [
        indicator["type"]
        for indicator in analysis["reputation_indicators"]
    ]

    assert "IP_REPUTATION_HIGH" in reputation_types
    assert "DOMAIN_REPUTATION_HIGH" in reputation_types
    assert "URL_REPUTATION_HIGH" in reputation_types

    assessment = analysis["threat_assessment"]

    assert assessment["score"] > 0
    assert assessment["category_breakdown"]
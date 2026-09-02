from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)

SAMPLE_EMAIL = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "samples"
    / "test_email.eml"
)


def test_analyze_valid_eml():
    with open(SAMPLE_EMAIL, "rb") as email_file:

        response = client.post(
            "/api/email/analyze",
            files={
                "file": (
                    "test_email.eml",
                    email_file,
                    "message/rfc822"
                )
            }
        )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert "analysis" in data

    analysis = data["analysis"]

    assert analysis["filename"] == "test_email.eml"
    assert "file_sha256" in analysis
    assert len(analysis["file_sha256"]) == 64


def test_analysis_contains_forensic_sections():
    with open(SAMPLE_EMAIL, "rb") as email_file:

        response = client.post(
            "/api/email/analyze",
            files={
                "file": (
                    "test_email.eml",
                    email_file,
                    "message/rfc822"
                )
            }
        )

    assert response.status_code == 200

    analysis = response.json()["analysis"]

    required_sections = [
        "headers",
        "addresses",
        "domains",
        "authentication",
        "received_chain",
        "body",
        "urls",
        "attachments",
        "all_headers",
        "domain_intelligence",
        "ip_intelligence",
        "origin_analysis",
        "correlations",
        "indicators",
        "threat_assessment"
    ]

    for section in required_sections:
        assert section in analysis


def test_threat_assessment():
    with open(SAMPLE_EMAIL, "rb") as email_file:

        response = client.post(
            "/api/email/analyze",
            files={
                "file": (
                    "test_email.eml",
                    email_file,
                    "message/rfc822"
                )
            }
        )

    assert response.status_code == 200

    assessment = response.json()["analysis"]["threat_assessment"]

    assert 0 <= assessment["score"] <= 100
    assert assessment["risk_level"] in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    assert assessment["verdict"] in {
        "LIKELY_SAFE",
        "POTENTIALLY_SUSPICIOUS",
        "SUSPICIOUS",
        "LIKELY_MALICIOUS"
    }

    assert 0.0 <= assessment["confidence"] <= 1.0

    assert isinstance(
        assessment["breakdown"],
        list
    )

    assert isinstance(
        assessment["category_breakdown"],
        list
    )

    assert isinstance(
        assessment["evidence"],
        list
    )

    assert isinstance(
        assessment["recommended_actions"],
        list
    )


def test_expected_indicators_are_detected():
    with open(SAMPLE_EMAIL, "rb") as email_file:

        response = client.post(
            "/api/email/analyze",
            files={
                "file": (
                    "test_email.eml",
                    email_file,
                    "message/rfc822"
                )
            }
        )

    assert response.status_code == 200

    indicators = response.json()["analysis"]["indicators"]

    indicator_types = {
        indicator["type"]
        for indicator in indicators
    }

    assert "SPF_FAILURE" in indicator_types
    assert "DKIM_FAILURE" in indicator_types
    assert "DMARC_FAILURE" in indicator_types
    assert "REPLY_TO_MISMATCH" in indicator_types
    assert "REPLY_DOMAIN_MISMATCH" in indicator_types
    assert "SUSPICIOUS_DISPLAY_NAME" in indicator_types


def test_origin_analysis_handles_documentation_ip():
    with open(SAMPLE_EMAIL, "rb") as email_file:

        response = client.post(
            "/api/email/analyze",
            files={
                "file": (
                    "test_email.eml",
                    email_file,
                    "message/rfc822"
                )
            }
        )

    assert response.status_code == 200

    origin = response.json()["analysis"]["origin_analysis"]

    assert origin["earliest_reliable_ip"] is None
    assert origin["confidence"] == 0.1

    assert any(
        item["reason"] == "Documentation/test IP"
        for item in origin["excluded_ips"]
    )
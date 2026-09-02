from app.intelligence.domain_reputation import (
    check_domain_reputation
)


def test_domain_reputation_returns_standard_structure():

    result = check_domain_reputation(
        "example.com"
    )

    assert isinstance(result, dict)

    required_fields = [
        "domain",
        "found",
        "malicious",
        "confidence",
        "provider",
        "categories",
        "malicious_votes",
        "suspicious_votes",
        "reputation",
        "suspicious",
        "total_engines",
        "error"
    ]

    for field in required_fields:
        assert field in result


def test_domain_is_normalized():

    result = check_domain_reputation(
        "Example.COM."
    )

    assert result["domain"] == "example.com"


def test_missing_api_key_is_handled_safely(
    monkeypatch
):

    monkeypatch.delenv(
        "VIRUSTOTAL_API_KEY",
        raising=False
    )

    result = check_domain_reputation(
        "example.com"
    )

    assert result["found"] is False
    assert result["malicious"] is False
    assert result["confidence"] == 0
    assert result["provider"] is None
    assert result["error"] is not None


def test_empty_domain_is_handled_safely():

    result = check_domain_reputation("")

    assert result["found"] is False
    assert result["malicious"] is False
    assert result["confidence"] == 0
    assert result["error"] is not None
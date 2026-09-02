from app.intelligence.ip_reputation import check_ip_reputation


def test_ip_reputation_returns_standard_structure():

    result = check_ip_reputation("8.8.8.8")

    assert isinstance(result, dict)

    required_fields = [
        "ip",
        "found",
        "malicious",
        "confidence",
        "provider",
        "abuse_score",
        "country",
        "isp",
        "domain",
        "total_reports",
        "last_reported_at",
        "error"
    ]

    for field in required_fields:
        assert field in result


def test_ip_reputation_preserves_ip():

    result = check_ip_reputation("8.8.8.8")

    assert result["ip"] == "8.8.8.8"


def test_missing_api_key_is_handled_safely(monkeypatch):

    monkeypatch.delenv(
        "ABUSEIPDB_API_KEY",
        raising=False
    )

    result = check_ip_reputation("8.8.8.8")

    assert result["found"] is False
    assert result["malicious"] is False
    assert result["confidence"] == 0
    assert result["provider"] is None
    assert result["error"] is not None


def test_empty_ip_is_handled_safely():

    result = check_ip_reputation("")

    assert result["found"] is False
    assert result["malicious"] is False
    assert result["confidence"] == 0
    assert result["error"] is not None
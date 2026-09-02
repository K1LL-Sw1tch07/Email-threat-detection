from app.intelligence.url_reputation import (
    check_url_reputation,
    _encode_url_id
)


def test_url_id_encoding():

    url = "https://example.com/login"

    encoded = _encode_url_id(url)

    assert isinstance(encoded, str)
    assert "=" not in encoded
    assert len(encoded) > 0


def test_url_reputation_returns_standard_structure():

    result = check_url_reputation(
        "https://example.com/login"
    )

    required_fields = [
        "url",
        "found",
        "malicious",
        "suspicious",
        "confidence",
        "provider",
        "malicious_votes",
        "suspicious_votes",
        "total_engines",
        "categories",
        "reputation",
        "error"
    ]

    for field in required_fields:
        assert field in result


def test_url_is_preserved():

    url = "https://example.com/login"

    result = check_url_reputation(url)

    assert result["url"] == url


def test_missing_api_key_is_handled_safely(
    monkeypatch
):

    monkeypatch.delenv(
        "VIRUSTOTAL_API_KEY",
        raising=False
    )

    result = check_url_reputation(
        "https://example.com/login"
    )

    assert result["found"] is False
    assert result["malicious"] is False
    assert result["confidence"] == 0
    assert result["provider"] is None
    assert result["error"] is not None


def test_empty_url_is_handled_safely():

    result = check_url_reputation("")

    assert result["found"] is False
    assert result["malicious"] is False
    assert result["confidence"] == 0
    assert result["error"] is not None
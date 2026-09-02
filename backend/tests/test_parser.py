from pathlib import Path

from app.parser.eml_parser import parse_eml, normalize_url


def test_parse_eml():

    sample = (
        Path(__file__).resolve().parents[2]
        / "data"
        / "samples"
        / "test_email.eml"
    )

    result = parse_eml(sample)

    assert result["headers"]["subject"] == "Urgent Account Verification"

    assert any(
        url["url"] == "https://example.com/login"
        for url in result["urls"]
    )

def test_normalize_plain_url():
    result = normalize_url("https://example.com/login")
    assert result == "https://example.com/login"


def test_normalize_markdown_url():
    result = normalize_url(
        "[Login](https://example.com/login)"
    )
    assert result == "https://example.com/login"


def test_normalize_extracted_markdown_url():
    result = normalize_url(
        "[https://example.com/login](https://example.com/login)"
    )
    assert result == "https://example.com/login"


def test_normalize_url_with_surrounding_punctuation():
    result = normalize_url(
        "<https://example.com/login>"
    )
    assert result == "https://example.com/login"


def test_normalize_empty_url():
    result = normalize_url("")
    assert result == ""
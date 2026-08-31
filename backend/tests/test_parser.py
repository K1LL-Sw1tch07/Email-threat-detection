from pathlib import Path

from app.parser.eml_parser import parse_eml


def test_parse_eml():

    sample = (
        Path(__file__).resolve().parents[2]
        / "data"
        / "samples"
        / "test_email.eml"
    )

    result = parse_eml(sample)

    assert result["headers"]["subject"] == "Urgent Account Verification"

    assert (
        "https://example.com/login"
        in result["urls"]
    )

    assert (
        "attacker@example.net"
        in result["addresses"]["reply_to"]
    )
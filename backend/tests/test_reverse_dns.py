from app.forensic.reverse_dns import reverse_dns_lookup


def test_invalid_ip():
    result = reverse_dns_lookup("not-an-ip")

    assert result["available"] is False
    assert result["hostname"] is None
    assert result["error"] == "Invalid IP address."


def test_private_ip():
    result = reverse_dns_lookup("192.168.1.10")

    assert result["available"] is False
    assert result["hostname"] is None
    assert result["error"] == "Reverse DNS skipped for non-public IP address."


def test_documentation_ip():
    result = reverse_dns_lookup("203.0.113.25")

    assert result["available"] is False
    assert result["hostname"] is None
    assert result["error"] == "Reverse DNS skipped for non-public IP address."


def test_public_ip():
    result = reverse_dns_lookup("8.8.8.8")

    assert result["available"] is True
    assert result["hostname"] is not None
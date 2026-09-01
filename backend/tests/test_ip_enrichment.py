from app.forensic.ip_enrichment import enrich_ip


def test_documentation_ip():

    result = enrich_ip("203.0.113.25")

    assert result["available"] is False
    assert result["reason"] == "Documentation/test IP."


def test_private_ip():

    result = enrich_ip("192.168.1.10")

    assert result["available"] is False
    assert result["reason"] == "Private IP address."


def test_loopback_ip():

    result = enrich_ip("127.0.0.1")

    assert result["available"] is False
    assert result["reason"] == "Loopback IP address."


def test_public_ip_maxmind():

    result = enrich_ip("8.8.8.8")

    assert result["available"] is True
    assert result["country"] == "United States"
    assert result["country_code"] == "US"
    assert result["asn"] == 15169
    assert result["organization"] == "Google LLC"
    assert result["network"] == "8.8.8.0/24"
    assert result["source"] == "MaxMind GeoLite2"


def test_invalid_ip():

    result = enrich_ip("not-an-ip")

    assert result["available"] is False
    assert result["reason"] == "Invalid IP address."
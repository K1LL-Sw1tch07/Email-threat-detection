from app.forensic.ip_intelligence import (
    analyze_ip,
    analyze_received_chain
)



def test_private_ip():
    result = analyze_ip("192.168.1.10")

    assert result["valid"] is True
    assert result["classification"] == "PRIVATE"


def test_loopback_ip():
    result = analyze_ip("127.0.0.1")

    assert result["valid"] is True
    assert result["classification"] == "LOOPBACK"


def test_public_ip():
    result = analyze_ip("8.8.8.8")

    assert result["valid"] is True
    assert result["classification"] == "PUBLIC"


def test_documentation_ip():
    result = analyze_ip("203.0.113.25")

    assert result["valid"] is True
    assert result["classification"] == "DOCUMENTATION"
    assert result["is_documentation"] is True


def test_invalid_ip():
    result = analyze_ip("999.999.999.999")

    assert result["valid"] is False
    
def test_public_ip():

    result = analyze_ip("8.8.8.8")

    assert result["valid"] is True
    assert result["version"] == 4
    assert result["is_global"] is True
    assert result["classification"] == "PUBLIC"


def test_private_ip():

    result = analyze_ip("192.168.1.10")

    assert result["valid"] is True
    assert result["is_private"] is True
    assert result["classification"] == "PRIVATE"


def test_received_chain():

    chain = [
        {
            "hop": 1,
            "ips": ["8.8.8.8"]
        }
    ]

    result = analyze_received_chain(chain)

    assert len(result) == 1
    assert result[0]["ip"] == "8.8.8.8"
    assert result[0]["hop"] == 1
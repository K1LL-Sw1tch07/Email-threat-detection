from app.forensic.domain_intelligence import (
    analyze_domain,
    analyze_dns,
    get_domain_structure,
    normalize_domain,
    query_dns,
    resolve_domain,
)

def test_null_mx_record():
    result = query_dns(
        "example.com",
        "MX"
    )

    assert result["record_type"] == "MX"
    assert result["available"] is True
    assert isinstance(result["records"], list)

    if result["records"]:
        mx = result["records"][0]

        assert mx["preference"] == 0

        if mx["exchange"] == ".":
            assert mx["null_mx"] is True

def test_normalize_domain():
    assert normalize_domain(
        "HTTPS://Example.COM/"
    ) == "example.com"

    assert normalize_domain(
        "example.com."
    ) == "example.com"


def test_domain_structure():

    result = get_domain_structure(
        "login.example.com"
    )

    assert result["valid"] is True
    assert result["domain"] == "login.example.com"
    assert result["label_count"] == 3
    assert result["tld"] == "com"


def test_punycode_detection():

    result = analyze_domain(
        "xn--example-9za.com"
    )

    assert result["structure"]["valid"] is True

    indicator_types = [
        indicator["type"]
        for indicator in result["indicators"]
    ]

    assert "PUNYCODE_DOMAIN" in indicator_types


def test_resolve_domain():

    result = resolve_domain(
        "example.com"
    )

    assert result["domain"] == "example.com"

    assert "resolved_ips" in result

    assert isinstance(
        result["resolved_ips"],
        list
    )


def test_dns_query():

    result = query_dns(
        "example.com",
        "A"
    )

    assert result["record_type"] == "A"
    assert "records" in result
    assert isinstance(
        result["records"],
        list
    )


def test_dns_analysis():

    result = analyze_dns(
        "example.com"
    )

    assert result["domain"] == "example.com"

    assert "records" in result

    for record_type in [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
    ]:
        assert record_type in result["records"]


def test_analyze_domain():

    result = analyze_domain(
        "example.com"
    )

    assert result["domain"] == "example.com"
    assert "structure" in result
    assert "dns" in result
    assert "dns_records" in result
    assert "indicators" in result
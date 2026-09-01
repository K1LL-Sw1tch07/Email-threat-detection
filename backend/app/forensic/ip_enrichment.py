import ipaddress

from app.forensic.providers.maxmind_provider import (
    enrich_ip_with_maxmind,
)


DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def is_documentation_ip(address) -> bool:
    return any(
        address in network
        for network in DOCUMENTATION_NETWORKS
    )


def enrich_ip(ip: str) -> dict:
    """
    Enrich a publicly routable IP address.

    Documentation, private, loopback, link-local,
    and reserved addresses are not sent to the
    GeoIP/ASN database lookup.
    """

    result = {
        "ip": ip,
        "available": False,
        "country": None,
        "country_code": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "organization": None,
        "network": None,
        "provider": None,
        "source": None,
        "reason": None,
    }

    try:
        address = ipaddress.ip_address(ip)

    except ValueError:
        result["reason"] = "Invalid IP address."
        return result

    if is_documentation_ip(address):
        result["reason"] = "Documentation/test IP."
        return result

    if address.is_loopback:
        result["reason"] = "Loopback IP address."
        return result

    if address.is_private:
        result["reason"] = "Private IP address."
        return result

    if address.is_link_local:
        result["reason"] = "Link-local IP address."
        return result

    if address.is_reserved:
        result["reason"] = "Reserved IP address."
        return result

    if not address.is_global:
        result["reason"] = "IP is not publicly routable."
        return result

    # -----------------------------------------------------
    # REAL GEOIP + ASN ENRICHMENT
    # -----------------------------------------------------

    enrichment = enrich_ip_with_maxmind(ip)

    result.update(
        {
            "available": enrichment["available"],
            "country": enrichment["country"],
            "country_code": enrichment["country_code"],
            "city": enrichment["city"],
            "latitude": enrichment["latitude"],
            "longitude": enrichment["longitude"],
            "asn": enrichment["asn"],
            "organization": enrichment["organization"],
            "network": enrichment["network"],
            "provider": enrichment["provider"],
            "source": enrichment["source"],
        }
    )

    if not enrichment["available"]:
        result["reason"] = "IP not found in GeoIP/ASN database."

    return result
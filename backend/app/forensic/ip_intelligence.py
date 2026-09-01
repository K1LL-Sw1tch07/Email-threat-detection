import ipaddress

from app.forensic.geolocation import geolocate_ip
from app.forensic.ip_enrichment import enrich_ip


DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def is_documentation_ip(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> bool:
    """
    Check whether an IP belongs to an RFC documentation/test network.
    """

    return any(
        address in network
        for network in DOCUMENTATION_NETWORKS
    )


def analyze_ip(ip: str) -> dict:
    """
    Perform local classification of an IP address.
    """

    try:
        address = ipaddress.ip_address(ip)

    except ValueError:
        return {
            "ip": ip,
            "valid": False,
            "error": "Invalid IP address."
        }

    is_documentation = is_documentation_ip(address)

    result = {
        "ip": ip,
        "valid": True,
        "version": address.version,
        "is_private": address.is_private,
        "is_global": address.is_global,
        "is_loopback": address.is_loopback,
        "is_reserved": address.is_reserved,
        "is_link_local": address.is_link_local,
        "is_documentation": is_documentation,
    }

    # =====================================================
    # CLASSIFICATION
    # =====================================================

    if is_documentation:
        classification = "DOCUMENTATION"

    elif address.is_loopback:
        classification = "LOOPBACK"

    elif address.is_private:
        classification = "PRIVATE"

    elif address.is_link_local:
        classification = "LINK_LOCAL"

    elif address.is_reserved:
        classification = "RESERVED"

    elif address.is_global:
        classification = "PUBLIC"

    else:
        classification = "UNKNOWN"

    result["classification"] = classification

    # =====================================================
    # EVIDENCE
    # =====================================================

    evidence = []

    if is_documentation:
        evidence.append(
            "IP address belongs to an RFC documentation/test network."
        )

    if address.is_private and not is_documentation:
        evidence.append(
            "IP address belongs to a private network range."
        )

    if address.is_loopback:
        evidence.append(
            "IP address is a loopback address."
        )

    if address.is_reserved:
        evidence.append(
            "IP address belongs to a reserved range."
        )

    if address.is_link_local:
        evidence.append(
            "IP address belongs to a link-local range."
        )

    if address.is_global:
        evidence.append(
            "IP address is publicly routable."
        )

    result["evidence"] = evidence

    return result


def analyze_received_chain(
    received_chain: list[dict]
) -> list[dict]:
    """
    Analyze IP addresses extracted from Received headers.

    Each unique IP receives:
    - local IP classification
    - geolocation information
    - enrichment information
    - originating hop
    """

    results = []
    seen_ips = set()

    for hop in received_chain:

        for ip in hop.get("ips", []):

            if ip in seen_ips:
                continue

            seen_ips.add(ip)

            # ---------------------------------------------
            # LOCAL IP ANALYSIS
            # ---------------------------------------------

            analysis = analyze_ip(ip)

            # ---------------------------------------------
            # HOP INFORMATION
            # ---------------------------------------------

            analysis["hop"] = hop.get("hop")

            # ---------------------------------------------
            # GEOLOCATION
            # ---------------------------------------------

            analysis["geolocation"] = geolocate_ip(ip)

            # ---------------------------------------------
            # IP ENRICHMENT
            # ---------------------------------------------

            analysis["enrichment"] = enrich_ip(ip)

            results.append(analysis)

    return results
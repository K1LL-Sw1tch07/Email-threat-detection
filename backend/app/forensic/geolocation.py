import ipaddress


def geolocate_ip(ip: str) -> dict:
    """
    Geolocate an IP address.

    External geolocation provider will be integrated later.
    Private, loopback, link-local, and documentation IPs
    are intentionally not sent for geolocation.
    """

    base_result = {
        "ip": ip,
        "available": False,
        "country": None,
        "country_code": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "organization": None,
        "provider": None,
    }

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        base_result["error"] = "Invalid IP address."
        return base_result

    # RFC 5737 documentation/test networks
    documentation_networks = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]

    if any(address in network for network in documentation_networks):
        base_result["reason"] = "Documentation/test IP."
        return base_result

    if address.is_private:
        base_result["reason"] = "Private IP address."
        return base_result

    if address.is_loopback:
        base_result["reason"] = "Loopback IP address."
        return base_result

    if address.is_link_local:
        base_result["reason"] = "Link-local IP address."
        return base_result

    if address.is_reserved:
        base_result["reason"] = "Reserved IP address."
        return base_result

    # Public IP reached.
    # External geolocation provider will be added here.
    base_result["reason"] = "Public IP; geolocation provider not configured."

    return base_result
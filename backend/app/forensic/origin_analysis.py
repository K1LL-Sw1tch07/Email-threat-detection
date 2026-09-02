import ipaddress


def analyze_origin(received_chain: list[dict]) -> dict:
    """
    Determine reliable origin-IP candidates from a Received header chain.

    This function interprets already-parsed Received headers.
    It does not perform geolocation, DNS, or external reputation lookups.
    """

    candidate_ips = []
    global_ips = []
    excluded_ips = []

    seen_ips = set()

    for hop in received_chain:
        hop_number = hop.get("hop")

        for ip in hop.get("ips", []):
            if ip in seen_ips:
                continue

            seen_ips.add(ip)

            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                excluded_ips.append({
                    "ip": ip,
                    "hop": hop_number,
                    "reason": "Invalid IP address"
                })
                continue

            # Documentation / test networks
            if (
                address in ipaddress.ip_network("192.0.2.0/24")
                or address in ipaddress.ip_network("198.51.100.0/24")
                or address in ipaddress.ip_network("203.0.113.0/24")
            ):
                excluded_ips.append({
                    "ip": ip,
                    "hop": hop_number,
                    "reason": "Documentation/test IP"
                })
                continue

            # Private addresses
            if address.is_private:
                excluded_ips.append({
                    "ip": ip,
                    "hop": hop_number,
                    "reason": "Private IP"
                })
                continue

            # Loopback
            if address.is_loopback:
                excluded_ips.append({
                    "ip": ip,
                    "hop": hop_number,
                    "reason": "Loopback IP"
                })
                continue

            # Link-local
            if address.is_link_local:
                excluded_ips.append({
                    "ip": ip,
                    "hop": hop_number,
                    "reason": "Link-local IP"
                })
                continue

            # Reserved
            if address.is_reserved:
                excluded_ips.append({
                    "ip": ip,
                    "hop": hop_number,
                    "reason": "Reserved IP"
                })
                continue

            # Global/public candidate
            if address.is_global:
                global_ips.append({
                    "ip": ip,
                    "hop": hop_number
                })

                candidate_ips.append(ip)

    # Received headers are represented in the order extracted from
    # the EML. Select the lowest hop number among reliable public IPs.
    earliest_reliable_ip = None

    if global_ips:
        earliest = min(
            global_ips,
            key=lambda item: item["hop"]
        )

        earliest_reliable_ip = earliest["ip"]

    # Confidence is intentionally conservative.
    if earliest_reliable_ip:
        confidence = 0.80
        reason = (
            "Earliest globally routable IP found in the "
            "Received header chain."
        )
    elif candidate_ips:
        confidence = 0.50
        reason = (
            "Public IP candidates were found, but origin "
            "confidence is limited."
        )
    else:
        confidence = 0.10
        reason = (
            "No reliable publicly routable origin IP was "
            "identified from the Received chain."
        )

    return {
        "candidate_ips": list(dict.fromkeys(candidate_ips)),
        "global_ips": global_ips,
        "excluded_ips": excluded_ips,
        "earliest_reliable_ip": earliest_reliable_ip,
        "confidence": confidence,
        "reason": reason
    }
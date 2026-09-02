from __future__ import annotations

from urllib.parse import urlparse


def normalize_domain(domain: str | None) -> str | None:
    if not domain:
        return None

    return domain.strip().lower().rstrip(".")


def extract_url_domain(url: str) -> str | None:
    try:
        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            return None

        return normalize_domain(hostname)

    except Exception:
        return None


def correlate_email(result: dict) -> dict:
    """
    Correlate existing email analysis results.

    This function does not determine maliciousness.
    It identifies relationships between email entities
    such as sender domains, reply-to domains, URL domains,
    resolved IPs, received IPs, and ASN information.
    """

    correlations = []

    domains = result.get("domains", {})

    sender_domain = normalize_domain(
        domains.get("sender_domain")
    )

    reply_to_domain = normalize_domain(
        domains.get("reply_to_domain")
    )

    # --------------------------------------------------
    # Sender ↔ Reply-To
    # --------------------------------------------------

    if sender_domain and reply_to_domain:

        relationship = (
            "SAME_DOMAIN"
            if sender_domain == reply_to_domain
            else "DIFFERENT_DOMAINS"
        )

        correlations.append(
            {
                "type": "SENDER_REPLY_TO_RELATIONSHIP",
                "relationship": relationship,
                "sender_domain": sender_domain,
                "reply_to_domain": reply_to_domain,
            }
        )

    # --------------------------------------------------
    # URL domain relationships
    # --------------------------------------------------

    url_domains = set()

    for url_data in result.get("urls", []):

        url = url_data.get("url")

        if not url:
            continue

        domain = normalize_domain(
            url_data.get("domain")
        )

        if not domain:
            domain = extract_url_domain(url)

        if domain:
            url_domains.add(domain)

    for url_domain in sorted(url_domains):

        if sender_domain:

            relationship = (
                "SAME_DOMAIN"
                if url_domain == sender_domain
                else "DIFFERENT_DOMAIN"
            )

            correlations.append(
                {
                    "type": "SENDER_URL_RELATIONSHIP",
                    "relationship": relationship,
                    "sender_domain": sender_domain,
                    "url_domain": url_domain,
                }
            )

        if reply_to_domain:

            relationship = (
                "SAME_DOMAIN"
                if url_domain == reply_to_domain
                else "DIFFERENT_DOMAIN"
            )

            correlations.append(
                {
                    "type": "REPLY_TO_URL_RELATIONSHIP",
                    "relationship": relationship,
                    "reply_to_domain": reply_to_domain,
                    "url_domain": url_domain,
                }
            )

    # --------------------------------------------------
    # URL domain ↔ resolved IP relationships
    # --------------------------------------------------

    domain_intelligence = result.get(
        "domain_intelligence",
        []
    )

    received_ips = set()

    for ip_data in result.get(
        "ip_intelligence",
        []
    ):

        ip = ip_data.get("ip")

        if ip:
            received_ips.add(ip)

    for domain_data in domain_intelligence:

        domain = normalize_domain(
            domain_data.get("domain")
        )

        if not domain:
            continue

        dns = domain_data.get("dns", {})

        resolved_ips = set(
            dns.get("resolved_ips", [])
        )

        if not resolved_ips:
            continue

        matching_ips = sorted(
            resolved_ips.intersection(received_ips)
        )

        if matching_ips:

            correlations.append(
                {
                    "type": "DOMAIN_RECEIVED_IP_RELATIONSHIP",
                    "relationship": "MATCH",
                    "domain": domain,
                    "received_ips": matching_ips,
                }
            )

        else:

            correlations.append(
                {
                    "type": "DOMAIN_RECEIVED_IP_RELATIONSHIP",
                    "relationship": "NO_MATCH",
                    "domain": domain,
                    "resolved_ips": sorted(resolved_ips),
                    "received_ips": sorted(received_ips),
                }
            )

    return {
        "count": len(correlations),
        "relationships": correlations,
    }
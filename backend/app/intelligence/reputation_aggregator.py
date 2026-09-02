from typing import Any


def aggregate_ip_reputation(
    reputation: dict[str, Any]
) -> list[dict[str, Any]]:

    indicators = []

    if not reputation.get("found"):
        return indicators

    provider = reputation.get(
        "provider",
        "Unknown"
    )

    abuse_score = reputation.get(
        "abuse_score"
    )

    if abuse_score is None:
        return indicators

    if abuse_score >= 80:

        indicators.append({
            "type": "IP_REPUTATION_HIGH",
            "severity": "HIGH",
            "description": (
                f"IP address has a high abuse "
                f"confidence score ({abuse_score}%) "
                f"according to {provider}."
            ),
            "source": provider,
            "ip": reputation.get("ip"),
            "abuse_score": abuse_score
        })

    elif abuse_score >= 50:

        indicators.append({
            "type": "IP_REPUTATION_SUSPICIOUS",
            "severity": "MEDIUM",
            "description": (
                f"IP address has a suspicious abuse "
                f"confidence score ({abuse_score}%) "
                f"according to {provider}."
            ),
            "source": provider,
            "ip": reputation.get("ip"),
            "abuse_score": abuse_score
        })

    return indicators


def aggregate_domain_reputation(
    reputation: dict[str, Any]
) -> list[dict[str, Any]]:

    indicators = []

    if not reputation.get("found"):
        return indicators

    provider = reputation.get(
        "provider",
        "Unknown"
    )

    malicious_votes = reputation.get(
        "malicious_votes",
        0
    )

    suspicious_votes = reputation.get(
        "suspicious_votes",
        0
    )

    domain = reputation.get(
        "domain"
    )

    if malicious_votes >= 5:

        indicators.append({
            "type": "DOMAIN_REPUTATION_HIGH",
            "severity": "HIGH",
            "description": (
                f"Domain has {malicious_votes} "
                f"malicious detections across "
                f"{reputation.get('total_engines', 0)} "
                f"VirusTotal engines."
            ),
            "source": provider,
            "domain": domain,
            "malicious_votes": malicious_votes
        })

    elif malicious_votes > 0:

        indicators.append({
            "type": "DOMAIN_REPUTATION_SUSPICIOUS",
            "severity": "MEDIUM",
            "description": (
                f"Domain has {malicious_votes} "
                f"malicious detection(s) across "
                f"{reputation.get('total_engines', 0)} "
                f"VirusTotal engines."
            ),
            "source": provider,
            "domain": domain,
            "malicious_votes": malicious_votes
        })

    elif suspicious_votes > 0:

        indicators.append({
            "type": "DOMAIN_REPUTATION_SUSPICIOUS",
            "severity": "MEDIUM",
            "description": (
                f"Domain has {suspicious_votes} "
                f"suspicious detection(s) across "
                f"{reputation.get('total_engines', 0)} "
                f"VirusTotal engines."
            ),
            "source": provider,
            "domain": domain,
            "suspicious_votes": suspicious_votes
        })

    return indicators


def aggregate_url_reputation(
    reputation: dict[str, Any]
) -> list[dict[str, Any]]:

    indicators = []

    if not reputation.get("found"):
        return indicators

    provider = reputation.get(
        "provider",
        "Unknown"
    )

    malicious_votes = reputation.get(
        "malicious_votes",
        0
    )

    suspicious_votes = reputation.get(
        "suspicious_votes",
        0
    )

    url = reputation.get(
        "url"
    )

    if malicious_votes >= 5:

        indicators.append({
            "type": "URL_REPUTATION_HIGH",
            "severity": "HIGH",
            "description": (
                f"URL has {malicious_votes} "
                f"malicious detections across "
                f"{reputation.get('total_engines', 0)} "
                f"VirusTotal engines."
            ),
            "source": provider,
            "url": url,
            "malicious_votes": malicious_votes
        })

    elif malicious_votes > 0:

        indicators.append({
            "type": "URL_REPUTATION_SUSPICIOUS",
            "severity": "MEDIUM",
            "description": (
                f"URL has {malicious_votes} "
                f"malicious detection(s) across "
                f"{reputation.get('total_engines', 0)} "
                f"VirusTotal engines."
            ),
            "source": provider,
            "url": url,
            "malicious_votes": malicious_votes
        })

    elif suspicious_votes > 0:

        indicators.append({
            "type": "URL_REPUTATION_SUSPICIOUS",
            "severity": "MEDIUM",
            "description": (
                f"URL has {suspicious_votes} "
                f"suspicious detection(s) across "
                f"{reputation.get('total_engines', 0)} "
                f"VirusTotal engines."
            ),
            "source": provider,
            "url": url,
            "suspicious_votes": suspicious_votes
        })

    return indicators


def aggregate_reputation(
    ip_results: list[dict[str, Any]] | None = None,
    domain_results: list[dict[str, Any]] | None = None,
    url_results: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:

    indicators = []

    for result in ip_results or []:
        indicators.extend(
            aggregate_ip_reputation(result)
        )

    for result in domain_results or []:
        indicators.extend(
            aggregate_domain_reputation(result)
        )

    for result in url_results or []:
        indicators.extend(
            aggregate_url_reputation(result)
        )

    return indicators
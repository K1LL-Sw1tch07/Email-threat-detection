import os
from typing import Any

import httpx


VIRUSTOTAL_DOMAIN_URL = (
    "https://www.virustotal.com/api/v3/domains"
)


def _neutral_result(
    domain: str,
    error: str | None = None
) -> dict[str, Any]:

    return {
        "domain": domain,
        "found": False,
        "malicious": False,
        "suspicious": False,
        "confidence": 0,
        "provider": None,
        "categories": [],
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "total_engines": 0,
        "reputation": None,
        "error": error
    }


def check_domain_reputation(
    domain: str
) -> dict[str, Any]:
    """
    Check a domain against VirusTotal.

    Returns a provider-independent standardized result.
    """

    if not domain:
        return _neutral_result(
            domain,
            "No domain provided"
        )

    normalized_domain = (
        domain.strip()
        .lower()
        .rstrip(".")
    )

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return _neutral_result(
            normalized_domain,
            "VIRUSTOTAL_API_KEY is not configured"
        )

    url = f"{VIRUSTOTAL_DOMAIN_URL}/{normalized_domain}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = httpx.get(
            url,
            headers=headers,
            timeout=10.0
        )

        response.raise_for_status()

        payload = response.json()

        data = payload.get("data", {})
        attributes = data.get("attributes", {})

        last_analysis_stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        malicious_votes = int(
            last_analysis_stats.get(
                "malicious",
                0
            )
        )

        suspicious_votes = int(
            last_analysis_stats.get(
                "suspicious",
                0
            )
        )

        total_engines = sum(
            int(value)
            for value in last_analysis_stats.values()
            if isinstance(value, int)
        )

        # One or a few detections should not
        # automatically classify a domain as malicious.
        malicious = malicious_votes >= 5

        suspicious = (
            malicious_votes > 0
            and malicious_votes < 5
        )

        confidence = 0

        if total_engines > 0:
            confidence = round(
                (
                    malicious_votes
                    / total_engines
                ) * 100
            )

        categories = attributes.get(
            "categories",
            {}
        )

        if isinstance(categories, dict):
            categories = list(
                dict.fromkeys(
                    str(value)
                    for value in categories.values()
                    if value
                )
            )
        else:
            categories = []

        reputation = attributes.get(
            "reputation"
        )

        return {
            "domain": normalized_domain,
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "confidence": confidence,
            "provider": "VirusTotal",
            "categories": categories,
            "malicious_votes": malicious_votes,
            "suspicious_votes": suspicious_votes,
            "total_engines": total_engines,
            "reputation": reputation,
            "error": None
        }

    except httpx.HTTPStatusError as exc:

        return _neutral_result(
            normalized_domain,
            (
                "VirusTotal HTTP error: "
                f"{exc.response.status_code}"
            )
        )

    except httpx.RequestError as exc:

        return _neutral_result(
            normalized_domain,
            f"VirusTotal request failed: {str(exc)}"
        )

    except (
        ValueError,
        TypeError
    ):

        return _neutral_result(
            normalized_domain,
            "Invalid response from VirusTotal"
        )
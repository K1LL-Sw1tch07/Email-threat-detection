import base64
import os
from typing import Any

import httpx


VIRUSTOTAL_URL_API = (
    "https://www.virustotal.com/api/v3/urls"
)


def _neutral_result(
    url: str,
    error: str | None = None
) -> dict[str, Any]:

    return {
        "url": url,
        "found": False,
        "malicious": False,
        "suspicious": False,
        "confidence": 0,
        "provider": None,
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "total_engines": 0,
        "categories": [],
        "reputation": None,
        "error": error
    }


def _encode_url_id(url: str) -> str:
    """
    Convert a URL into the identifier expected
    by the VirusTotal URL endpoint.
    """

    encoded = base64.urlsafe_b64encode(
        url.encode()
    ).decode()

    return encoded.rstrip("=")


def check_url_reputation(
    url: str
) -> dict[str, Any]:
    """
    Check a URL against VirusTotal.

    Returns a provider-independent standardized result.
    """

    if not url:
        return _neutral_result(
            url,
            "No URL provided"
        )

    normalized_url = url.strip()

    api_key = os.getenv(
        "VIRUSTOTAL_API_KEY"
    )

    if not api_key:
        return _neutral_result(
            normalized_url,
            "VIRUSTOTAL_API_KEY is not configured"
        )

    url_id = _encode_url_id(
        normalized_url
    )

    endpoint = (
        f"{VIRUSTOTAL_URL_API}/{url_id}"
    )

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:

        response = httpx.get(
            endpoint,
            headers=headers,
            timeout=10.0
        )

        response.raise_for_status()

        payload = response.json()

        data = payload.get(
            "data",
            {}
        )

        attributes = data.get(
            "attributes",
            {}
        )

        analysis_stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        malicious_votes = int(
            analysis_stats.get(
                "malicious",
                0
            )
        )

        suspicious_votes = int(
            analysis_stats.get(
                "suspicious",
                0
            )
        )

        total_engines = sum(
            int(value)
            for value in analysis_stats.values()
            if isinstance(value, int)
        )

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

        if isinstance(
            categories,
            dict
        ):

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
            "url": normalized_url,
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "confidence": confidence,
            "provider": "VirusTotal",
            "malicious_votes": malicious_votes,
            "suspicious_votes": suspicious_votes,
            "total_engines": total_engines,
            "categories": categories,
            "reputation": reputation,
            "error": None
        }

    except httpx.HTTPStatusError as exc:

        return _neutral_result(
            normalized_url,
            (
                "VirusTotal HTTP error: "
                f"{exc.response.status_code}"
            )
        )

    except httpx.RequestError as exc:

        return _neutral_result(
            normalized_url,
            f"VirusTotal request failed: {str(exc)}"
        )

    except (
        ValueError,
        TypeError
    ):

        return _neutral_result(
            normalized_url,
            "Invalid response from VirusTotal"
        )
import os
from typing import Any

import httpx


ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"


def _neutral_result(
    ip: str,
    error: str | None = None
) -> dict[str, Any]:
    return {
        "ip": ip,
        "found": False,
        "malicious": False,
        "confidence": 0,
        "provider": None,
        "abuse_score": None,
        "country": None,
        "isp": None,
        "domain": None,
        "total_reports": None,
        "last_reported_at": None,
        "error": error
    }


def check_ip_reputation(ip: str) -> dict[str, Any]:
    """
    Check an IP address against AbuseIPDB.

    Returns a provider-independent standardized result.
    """

    if not ip:
        return _neutral_result(
            ip,
            "No IP address provided"
        )

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return _neutral_result(
            ip,
            "ABUSEIPDB_API_KEY is not configured"
        )

    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = httpx.get(
            ABUSEIPDB_API_URL,
            headers=headers,
            params=params,
            timeout=10.0
        )

        response.raise_for_status()

        payload = response.json()
        data = payload.get("data", {})

        abuse_score = data.get(
            "abuseConfidenceScore",
            0
        )

        return {
            "ip": ip,
            "found": True,
            "malicious": abuse_score >= 50,
            "confidence": abuse_score,
            "provider": "AbuseIPDB",
            "abuse_score": abuse_score,
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "error": None
        }

    except httpx.HTTPStatusError as exc:
        return _neutral_result(
            ip,
            f"AbuseIPDB HTTP error: {exc.response.status_code}"
        )

    except httpx.RequestError as exc:
        return _neutral_result(
            ip,
            f"AbuseIPDB request failed: {str(exc)}"
        )

    except (ValueError, TypeError):
        return _neutral_result(
            ip,
            "Invalid response from AbuseIPDB"
        )
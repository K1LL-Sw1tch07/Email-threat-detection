from urllib.parse import urlparse
import ipaddress


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "password",
    "credential",
    "account",
    "security",
    "update",
    "confirm",
    "signin",
    "bank",
    "payment",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "goo.gl",
    "ow.ly",
}


def _is_ip_address(hostname: str) -> bool:
    """Return True if hostname is a valid IPv4 or IPv6 address."""

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_url_shortener(domain: str) -> bool:
    """Return True if domain is a known URL-shortening service."""

    domain = domain.lower().rstrip(".")

    return (
        domain in SHORTENER_DOMAINS
        or any(domain.endswith("." + shortener) for shortener in SHORTENER_DOMAINS)
    )


def analyze_urls(urls: list[dict]) -> list[dict]:
    """
    Analyze extracted URLs for suspicious characteristics.

    The analyzer produces forensic indicators while preserving
    the existing indicator names used by the scoring engine.
    """

    indicators = []

    for url_data in urls:
        url = url_data.get("url", "")
        domain = url_data.get("domain")

        if not url:
            continue

        parsed = urlparse(url)

        # Prefer hostname extracted from the parsed URL.
        hostname = parsed.hostname

        if hostname:
            hostname = hostname.lower().rstrip(".")

        # If parser did not provide hostname, fall back to extracted domain.
        if not hostname and domain:
            hostname = domain.lower().rstrip(".")

        # ---------------------------------------------
        # IP address used instead of domain
        # ---------------------------------------------

        if hostname and _is_ip_address(hostname):
            indicators.append({
                "type": "IP_BASED_URL",
                "severity": "HIGH",
                "description": (
                    "The URL uses an IP address instead "
                    "of a normal domain name."
                ),
                "url": url,
                "ip": hostname,
            })

        # ---------------------------------------------
        # HTTP instead of HTTPS
        # ---------------------------------------------

        if parsed.scheme.lower() == "http":
            indicators.append({
                "type": "UNENCRYPTED_URL",
                "severity": "MEDIUM",
                "description": (
                    "The URL uses HTTP instead of HTTPS."
                ),
                "url": url,
            })

        # ---------------------------------------------
        # URL shortener
        # ---------------------------------------------

        if hostname and _is_url_shortener(hostname):
            indicators.append({
                "type": "URL_SHORTENER",
                "severity": "MEDIUM",
                "description": (
                    "The URL uses a known URL-shortening service."
                ),
                "url": url,
                "domain": hostname,
            })

        # ---------------------------------------------
        # Excessively long URL
        # ---------------------------------------------

        if len(url) > 200:
            indicators.append({
                "type": "LONG_URL",
                "severity": "LOW",
                "description": (
                    "The URL is unusually long."
                ),
                "url": url,
                "length": len(url),
            })

        # ---------------------------------------------
        # Suspicious keywords
        # ---------------------------------------------

        url_lower = url.lower()

        matched_keywords = [
            keyword
            for keyword in SUSPICIOUS_KEYWORDS
            if keyword in url_lower
        ]

        if matched_keywords:
            indicators.append({
                "type": "SUSPICIOUS_URL_KEYWORD",
                "severity": "MEDIUM",
                "description": (
                    "The URL contains security-sensitive "
                    "keywords."
                ),
                "url": url,
                "keywords": sorted(matched_keywords),
            })

        # ---------------------------------------------
        # Punycode / IDN
        # ---------------------------------------------

        if hostname:
            labels = hostname.split(".")

            if any(label.startswith("xn--") for label in labels):
                indicators.append({
                    "type": "PUNYCODE_DOMAIN",
                    "severity": "MEDIUM",
                    "description": (
                        "The domain uses Punycode, which can "
                        "sometimes be associated with lookalike "
                        "or homograph domains."
                    ),
                    "domain": hostname,
                })

        # ---------------------------------------------
        # Excessive subdomains
        # ---------------------------------------------

        if hostname and not _is_ip_address(hostname):
            labels = hostname.split(".")

            if len(labels) >= 5:
                indicators.append({
                    "type": "EXCESSIVE_SUBDOMAINS",
                    "severity": "LOW",
                    "description": (
                        "The URL contains an unusually large "
                        "number of domain labels."
                    ),
                    "domain": hostname,
                    "label_count": len(labels),
                })

    return indicators
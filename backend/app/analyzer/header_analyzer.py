from email.utils import parseaddr


def analyze_headers(parsed_email: dict) -> list[dict]:
    """
    Detect basic suspicious email header indicators.
    """

    indicators = []

    headers = parsed_email.get("headers", {})
    authentication = parsed_email.get(
        "authentication",
        {}
    )

    addresses = parsed_email.get(
        "addresses",
        {}
    )

    domains = parsed_email.get(
        "domains",
        {}
    )

    # -------------------------------------------------
    # SPF
    # -------------------------------------------------

    spf = authentication.get("spf")

    if spf in {"fail", "softfail", "permerror"}:

        indicators.append({
            "type": "SPF_FAILURE",
            "severity": "HIGH",
            "description": f"SPF authentication result is {spf}."
        })

    # -------------------------------------------------
    # DKIM
    # -------------------------------------------------

    dkim = authentication.get("dkim")

    if dkim in {"fail", "permerror", "temperror"}:

        indicators.append({
            "type": "DKIM_FAILURE",
            "severity": "HIGH",
            "description": f"DKIM authentication result is {dkim}."
        })

    # -------------------------------------------------
    # DMARC
    # -------------------------------------------------

    dmarc = authentication.get("dmarc")

    if dmarc in {"fail", "permerror", "temperror"}:

        indicators.append({
            "type": "DMARC_FAILURE",
            "severity": "HIGH",
            "description": f"DMARC authentication result is {dmarc}."
        })

    # -------------------------------------------------
    # Reply-To mismatch
    # -------------------------------------------------

    from_addresses = addresses.get(
        "from",
        []
    )

    reply_to_addresses = addresses.get(
        "reply_to",
        []
    )

    if from_addresses and reply_to_addresses:

        from_email = from_addresses[0].lower()
        reply_email = reply_to_addresses[0].lower()

        if from_email != reply_email:

            indicators.append({
                "type": "REPLY_TO_MISMATCH",
                "severity": "MEDIUM",
                "description": (
                    "The Reply-To address differs from the "
                    "sender address."
                ),
                "from": from_email,
                "reply_to": reply_email
            })

    # -------------------------------------------------
    # Domain mismatch
    # -------------------------------------------------

    sender_domain = domains.get(
        "sender_domain"
    )

    reply_domain = domains.get(
        "reply_to_domain"
    )

    if (
        sender_domain
        and reply_domain
        and sender_domain != reply_domain
    ):

        indicators.append({
            "type": "REPLY_DOMAIN_MISMATCH",
            "severity": "MEDIUM",
            "description": (
                "The sender domain and Reply-To domain "
                "are different."
            ),
            "sender_domain": sender_domain,
            "reply_to_domain": reply_domain
        })

    # -------------------------------------------------
    # Missing authentication
    # -------------------------------------------------

    if (
        spf == "unknown"
        and dkim == "unknown"
        and dmarc == "unknown"
    ):

        indicators.append({
            "type": "AUTHENTICATION_UNKNOWN",
            "severity": "LOW",
            "description": (
                "No SPF, DKIM or DMARC authentication "
                "results were found."
            )
        })

    return indicators
from email.utils import parseaddr


def analyze_headers(parsed_email: dict) -> list[dict]:
    """
    Detect suspicious email header indicators.
    """

    indicators = []

    headers = parsed_email.get("headers", {})
    authentication = parsed_email.get("authentication", {})
    addresses = parsed_email.get("addresses", {})
    domains = parsed_email.get("domains", {})

    # -------------------------------------------------
    # Authentication results
    # -------------------------------------------------

    spf = authentication.get("spf")

    if spf in {"fail", "softfail", "permerror"}:
        indicators.append({
            "type": "SPF_FAILURE",
            "severity": "HIGH",
            "description": f"SPF authentication result is {spf}."
        })

    dkim = authentication.get("dkim")

    if dkim in {"fail", "permerror", "temperror"}:
        indicators.append({
            "type": "DKIM_FAILURE",
            "severity": "HIGH",
            "description": f"DKIM authentication result is {dkim}."
        })

    dmarc = authentication.get("dmarc")

    if dmarc in {"fail", "permerror", "temperror"}:
        indicators.append({
            "type": "DMARC_FAILURE",
            "severity": "HIGH",
            "description": f"DMARC authentication result is {dmarc}."
        })

    # -------------------------------------------------
    # Addresses
    # -------------------------------------------------

    from_addresses = addresses.get("from", [])
    reply_to_addresses = addresses.get("reply_to", [])

    # -------------------------------------------------
    # Reply-To mismatch
    # -------------------------------------------------

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
    # Return-Path mismatch
    # -------------------------------------------------

    return_path = headers.get("return_path")

    if return_path and from_addresses:

        return_path_email = parseaddr(return_path)[1].lower()
        from_email = from_addresses[0].lower()

        if (
            return_path_email
            and return_path_email != from_email
        ):

            indicators.append({
                "type": "RETURN_PATH_MISMATCH",
                "severity": "MEDIUM",
                "description": (
                    "The Return-Path address differs from "
                    "the visible sender address."
                ),
                "from": from_email,
                "return_path": return_path_email
            })

    # -------------------------------------------------
    # Display-name impersonation
    # -------------------------------------------------

    from_header = headers.get("from")

    if from_header:

        display_name, from_email = parseaddr(from_header)

        suspicious_names = {
            "security",
            "security team",
            "administrator",
            "admin",
            "it support",
            "support",
            "microsoft",
            "google",
            "apple",
            "bank",
            "accounts",
            "finance",
            "payroll",
            "hr",
            "human resources"
        }

        normalized_name = display_name.strip().lower()

        if normalized_name in suspicious_names:

            indicators.append({
                "type": "SUSPICIOUS_DISPLAY_NAME",
                "severity": "LOW",
                "description": (
                    "The sender uses a display name commonly "
                    "associated with trusted organizational "
                    "or service identities."
                ),
                "display_name": display_name,
                "email": from_email
            })

    # -------------------------------------------------
    # Domain mismatch
    # -------------------------------------------------

    sender_domain = domains.get("sender_domain")
    reply_domain = domains.get("reply_to_domain")

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
    # Message-ID domain mismatch
    # -------------------------------------------------

    message_id = headers.get("message_id")

    if message_id and sender_domain:

        message_id_address = parseaddr(message_id)[1]

        if "@" in message_id_address:

            message_id_domain = (
                message_id_address
                .rsplit("@", 1)[1]
                .lower()
                .rstrip(".")
            )

            if message_id_domain != sender_domain:

                indicators.append({
                    "type": "MESSAGE_ID_DOMAIN_MISMATCH",
                    "severity": "LOW",
                    "description": (
                        "The Message-ID domain differs from "
                        "the visible sender domain."
                    ),
                    "sender_domain": sender_domain,
                    "message_id_domain": message_id_domain
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
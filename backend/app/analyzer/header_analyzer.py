from email.utils import parseaddr

def get_organizational_domain(domain: str | None) -> str | None:
    """
    Return a simple organizational domain for comparison.

    This allows legitimate subdomains such as:
    em7877.tm.openai.com
    to be treated as belonging to:
    tm.openai.com
    """

    if not domain:
        return None

    domain = domain.lower().strip(".")

    parts = domain.split(".")

    if len(parts) < 2:
        return domain

    return ".".join(parts[-2:])

# -------------------------------------------------
# Brand impersonation detection
# -------------------------------------------------

KNOWN_BRANDS = {
    "microsoft": {
        "domains": {
            "microsoft.com",
            "microsoftonline.com",
            "office.com",
            "live.com",
        }
    },
    "google": {
        "domains": {
            "google.com",
            "googlemail.com",
        }
    },
    "apple": {
        "domains": {
            "apple.com",
            "icloud.com",
        }
    },
    "openai": {
        "domains": {
            "openai.com",
        }
    },
}


def _detect_brand_impersonation(
    display_name: str,
    sender_domain: str | None,
) -> dict | None:
    """
    Detect obvious brand impersonation based on the sender
    display name and sender domain.
    """

    if not sender_domain:
        return None

    normalized_name = display_name.strip().lower()
    normalized_domain = sender_domain.lower().strip(".")

    for brand, data in KNOWN_BRANDS.items():

        if brand not in normalized_name:
            continue

        legitimate_domains = data["domains"]

        if any(
            normalized_domain == domain
            or normalized_domain.endswith("." + domain)
            for domain in legitimate_domains
        ):
            return None

        return {
            "type": "BRAND_IMPERSONATION",
            "severity": "HIGH",
            "description": (
                f"The sender appears to impersonate {brand.title()} "
                "but the sender domain is not an authorized "
                "organizational domain."
            ),
            "brand": brand.title(),
            "sender_domain": normalized_domain,
        }

    return None

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

        from_domain = (
            from_email.rsplit("@", 1)[1]
            if "@" in from_email
            else None
        )

        return_path_domain = (
            return_path_email.rsplit("@", 1)[1]
            if "@" in return_path_email
            else None
        )

        from_org_domain = get_organizational_domain(
            from_domain
        )

        return_path_org_domain = get_organizational_domain(
            return_path_domain
        )

        if (
            return_path_email
            and from_org_domain
            and return_path_org_domain
            and from_org_domain != return_path_org_domain
        ):
            indicators.append({
                "type": "RETURN_PATH_MISMATCH",
                "severity": "MEDIUM",
                "description": (
                    "The Return-Path address belongs to a "
                    "different organizational domain than "
                    "the visible sender."
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

        sender_domain = domains.get("sender_domain")

        brand_indicator = _detect_brand_impersonation(
            display_name,
            sender_domain,
        )

        if brand_indicator:
            indicators.append(brand_indicator)

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

    # Message-ID mismatch
    #
    # Message-ID values may contain internal mail-server identifiers
    # that are not internet domains, for example:
    #
    # <abc123@geopod-ismtpd-0>
    #
    # Do not treat such infrastructure identifiers as suspicious
    # domain mismatches.

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

            # Only compare Message-ID domains when the value
            # looks like a real DNS-style domain.
            message_id_labels = message_id_domain.split(".")

            is_dns_style_domain = (
                len(message_id_labels) >= 2
                and all(
                    label
                    and label[0].isalnum()
                    and label[-1].isalnum()
                    for label in message_id_labels
                )
            )

            if (
                is_dns_style_domain
                and message_id_domain != sender_domain
            ):
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
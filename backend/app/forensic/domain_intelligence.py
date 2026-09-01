import ipaddress
import socket
from urllib.parse import urlparse

import dns.resolver


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain name for analysis.
    """

    if not domain:
        return ""

    domain = domain.strip().lower()

    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.hostname or ""

    return domain.rstrip(".")


def is_ip_address(value: str) -> bool:
    """
    Return True if the supplied value is an IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


def get_domain_structure(domain: str) -> dict:
    """
    Analyze basic structural properties of a domain.
    """

    domain = normalize_domain(domain)

    if not domain:
        return {
            "valid": False,
            "domain": domain,
            "error": "Empty domain."
        }

    if is_ip_address(domain):
        return {
            "valid": False,
            "domain": domain,
            "error": "IP address supplied instead of domain."
        }

    labels = domain.split(".")

    suspicious_labels = []

    for label in labels:

        if label.startswith("xn--"):
            suspicious_labels.append({
                "type": "PUNYCODE_LABEL",
                "label": label
            })

        if len(label) > 30:
            suspicious_labels.append({
                "type": "LONG_DOMAIN_LABEL",
                "label": label
            })

        if label.count("-") >= 3:
            suspicious_labels.append({
                "type": "EXCESSIVE_HYPHENS",
                "label": label
            })

    return {
        "valid": True,
        "domain": domain,
        "label_count": len(labels),
        "labels": labels,
        "tld": labels[-1] if labels else None,
        "suspicious_labels": suspicious_labels,
    }


def resolve_domain(domain: str) -> dict:
    """
    Resolve A and AAAA records using the local system resolver.
    """

    domain = normalize_domain(domain)

    result = {
        "domain": domain,
        "available": False,
        "ipv4": [],
        "ipv6": [],
        "resolved_ips": [],
        "error": None,
    }

    if not domain:
        result["error"] = "Empty domain."
        return result

    if is_ip_address(domain):
        result["error"] = "IP address supplied instead of domain."
        return result

    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            type=socket.SOCK_STREAM
        )

    except socket.gaierror as error:
        result["error"] = str(error)
        return result

    ipv4 = set()
    ipv6 = set()

    for entry in addresses:

        address = entry[4][0]

        try:
            parsed_ip = ipaddress.ip_address(address)

        except ValueError:
            continue

        if parsed_ip.version == 4:
            ipv4.add(address)

        else:
            ipv6.add(address)

    result["ipv4"] = sorted(ipv4)
    result["ipv6"] = sorted(ipv6)
    result["resolved_ips"] = sorted(ipv4 | ipv6)
    result["available"] = bool(result["resolved_ips"])

    return result


def query_dns(domain: str, record_type: str) -> dict:
    """
    Query a DNS record type using dnspython.

    Supported:

        A
        AAAA
        MX
        NS
        TXT
        CNAME
    """

    result = {
        "record_type": record_type,
        "records": [],
        "available": False,
        "error": None,
    }

    try:
        answers = dns.resolver.resolve(
            domain,
            record_type
        )

        records = []

        for answer in answers:

            # -------------------------
            # MX RECORD
            # -------------------------
            if record_type == "MX":

                exchange = str(answer.exchange)

                # "." represents a Null MX record.
                #
                # It means the domain explicitly
                # does not accept email.
                if exchange == ".":

                    records.append({
                        "preference": int(answer.preference),
                        "exchange": ".",
                        "null_mx": True
                    })

                else:

                    records.append({
                        "preference": int(answer.preference),
                        "exchange": exchange.rstrip("."),
                        "null_mx": False
                    })

            # -------------------------
            # TXT RECORD
            # -------------------------
            elif record_type == "TXT":

                records.append(
                    "".join(
                        part.decode()
                        if isinstance(part, bytes)
                        else part
                        for part in answer.strings
                    )
                )

            # -------------------------
            # OTHER RECORD TYPES
            # -------------------------
            else:

                records.append(
                    str(answer).rstrip(".")
                )

        result["records"] = records
        result["available"] = bool(records)

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ) as error:

        result["error"] = error.__class__.__name__

    except Exception as error:

        result["error"] = str(error)

    return result


def analyze_dns(domain: str) -> dict:
    """
    Perform DNS intelligence analysis.
    """

    domain = normalize_domain(domain)

    if not domain:
        return {
            "domain": domain,
            "available": False,
            "records": {},
            "error": "Empty domain."
        }

    if is_ip_address(domain):
        return {
            "domain": domain,
            "available": False,
            "records": {},
            "error": "IP address supplied instead of domain."
        }

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
    ]

    records = {}

    for record_type in record_types:

        records[record_type] = query_dns(
            domain,
            record_type
        )

    available = any(
        record["available"]
        for record in records.values()
    )

    return {
        "domain": domain,
        "available": available,
        "records": records,
    }


def analyze_domain(domain: str) -> dict:
    """
    Perform passive/local domain intelligence analysis.
    """

    domain = normalize_domain(domain)

    structure = get_domain_structure(domain)

    resolution = resolve_domain(domain)

    dns = analyze_dns(domain)

    result = {
        "domain": domain,
        "structure": structure,
        "dns": resolution,
        "dns_records": dns,
    }

    indicators = []

    # =====================================================
    # DOMAIN STRUCTURE INDICATORS
    # =====================================================

    for suspicious in structure.get(
        "suspicious_labels",
        []
    ):

        indicator_type = suspicious["type"]

        # -------------------------
        # PUNYCODE
        # -------------------------
        if indicator_type == "PUNYCODE_LABEL":

            indicators.append({
                "type": "PUNYCODE_DOMAIN",
                "severity": "MEDIUM",
                "description": (
                    "The domain contains a Punycode label, "
                    "which can sometimes be used in lookalike "
                    "or homograph domains."
                ),
                "domain": domain,
                "label": suspicious["label"],
            })

        # -------------------------
        # LONG LABEL
        # -------------------------
        elif indicator_type == "LONG_DOMAIN_LABEL":

            indicators.append({
                "type": "LONG_DOMAIN_LABEL",
                "severity": "LOW",
                "description": (
                    "The domain contains an unusually long label."
                ),
                "domain": domain,
                "label": suspicious["label"],
            })

        # -------------------------
        # EXCESSIVE HYPHENS
        # -------------------------
        elif indicator_type == "EXCESSIVE_HYPHENS":

            indicators.append({
                "type": "EXCESSIVE_HYPHENS",
                "severity": "LOW",
                "description": (
                    "The domain contains a label with an "
                    "unusually high number of hyphens."
                ),
                "domain": domain,
                "label": suspicious["label"],
            })

    # =====================================================
    # MX INTELLIGENCE
    # =====================================================

    mx_records = dns["records"].get(
        "MX",
        {}
    )

    # -------------------------
    # NO MX RECORD
    # -------------------------
    if not mx_records.get("available"):

        indicators.append({
            "type": "NO_MX_RECORD",
            "severity": "LOW",
            "description": (
                "The domain does not expose an MX record "
                "through the current DNS resolver."
            ),
            "domain": domain,
        })

    # -------------------------
    # NULL MX RECORD
    # -------------------------
    else:

        mx_entries = mx_records.get(
            "records",
            []
        )

        for mx in mx_entries:

            if mx.get("null_mx") is True:

                indicators.append({
                    "type": "NULL_MX_RECORD",
                    "severity": "LOW",
                    "description": (
                        "The domain publishes a Null MX record, "
                        "indicating that it does not accept email."
                    ),
                    "domain": domain,
                })

    # =====================================================
    # FINAL RESULT
    # =====================================================

    result["indicators"] = indicators

    return result
from email import policy
from email.parser import BytesParser
from email.message import Message
from email.utils import getaddresses
from pathlib import Path
import hashlib
import ipaddress
import re
from urllib.parse import urlparse



def normalize_url(url: str) -> str:
    """
    Normalize a URL extracted from plain text, HTML, or Markdown-like content.
    """

    if not url:
        return ""

    # Find the first HTTP/HTTPS URL.
    match = re.search(
        r"https?://[^\s<>\[\]()\"']+",
        url,
        re.IGNORECASE
    )

    if not match:
        return ""

    normalized_url = match.group(0)

    # Remove common trailing punctuation.
    normalized_url = normalized_url.rstrip(".,;:!?")

    return normalized_url
# ---------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


# ---------------------------------------------------------
# Basic utilities
# ---------------------------------------------------------

def calculate_sha256(data: bytes) -> str:
    """Calculate SHA-256 hash."""

    return hashlib.sha256(data).hexdigest()


def extract_urls(text: str) -> list[str]:
    """
    Extract and normalize unique HTTP/HTTPS URLs.
    """

    if not text:
        return []

    raw_urls = URL_PATTERN.findall(text)

    normalized_urls = []

    for raw_url in raw_urls:
        normalized_url = normalize_url(raw_url)

        if normalized_url:
            normalized_urls.append(normalized_url)

    return list(dict.fromkeys(normalized_urls))


def extract_ips(text: str) -> list[str]:
    """Extract valid IPv4 addresses."""

    if not text:
        return []

    candidates = IP_PATTERN.findall(text)
    valid_ips = []

    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            valid_ips.append(candidate)
        except ValueError:
            pass

    return list(dict.fromkeys(valid_ips))


def get_addresses(header_value: str | None) -> list[str]:
    """Extract email addresses from a header."""

    if not header_value:
        return []

    return [
        address
        for _, address in getaddresses([header_value])
        if address
    ]


# ---------------------------------------------------------
# Header analysis
# ---------------------------------------------------------

def extract_authentication_results(message: Message) -> dict:
    """
    Extract SPF, DKIM and DMARC results from
    Authentication-Results and related headers.
    """

    authentication_headers = []

    for key, value in message.items():

        key_lower = key.lower()

        if key_lower in {
            "authentication-results",
            "received-spf"
        }:
            authentication_headers.append({
                "name": key,
                "value": value
            })

    combined_text = " ".join(
        item["value"]
        for item in authentication_headers
    ).lower()

    result = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "raw": authentication_headers
    }

    # SPF
    if re.search(r"\bspf\s*=\s*pass\b", combined_text):
        result["spf"] = "pass"
    elif re.search(r"\bspf\s*=\s*(fail|softfail|neutral|temperror|permerror)\b", combined_text):
        match = re.search(
            r"\bspf\s*=\s*(fail|softfail|neutral|temperror|permerror)\b",
            combined_text
        )
        result["spf"] = match.group(1)

    # DKIM
    if re.search(r"\bdkim\s*=\s*pass\b", combined_text):
        result["dkim"] = "pass"
    elif re.search(r"\bdkim\s*=\s*(fail|neutral|temperror|permerror|none)\b", combined_text):
        match = re.search(
            r"\bdkim\s*=\s*(fail|neutral|temperror|permerror|none)\b",
            combined_text
        )
        result["dkim"] = match.group(1)

    # DMARC
    if re.search(r"\bdmarc\s*=\s*pass\b", combined_text):
        result["dmarc"] = "pass"
    elif re.search(r"\bdmarc\s*=\s*(fail|temperror|permerror|none)\b", combined_text):
        match = re.search(
            r"\bdmarc\s*=\s*(fail|temperror|permerror|none)\b",
            combined_text
        )
        result["dmarc"] = match.group(1)

    return result


def extract_received_headers(message: Message) -> list[dict]:
    """Extract Received headers and useful information."""

    received = []

    for index, value in enumerate(
        message.get_all("Received", [])
    ):

        received.append({
            "hop": index + 1,
            "raw": value,
            "ips": extract_ips(value)
        })

    return received


# ---------------------------------------------------------
# Body extraction
# ---------------------------------------------------------

def extract_body(message: Message) -> tuple[str, str]:
    """Extract plain-text and HTML bodies."""

    plain_text = ""
    html_text = ""

    if message.is_multipart():

        for part in message.walk():

            if part.is_multipart():
                continue

            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            if disposition == "attachment":
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if content_type == "text/plain":
                plain_text += str(content)

            elif content_type == "text/html":
                html_text += str(content)

    else:

        try:
            content = message.get_content()
        except Exception:
            content = ""

        if message.get_content_type() == "text/plain":
            plain_text = str(content)

        elif message.get_content_type() == "text/html":
            html_text = str(content)

    return plain_text.strip(), html_text.strip()


# ---------------------------------------------------------
# Attachment extraction
# ---------------------------------------------------------

def extract_attachments(message: Message) -> list[dict]:
    """Extract attachment metadata."""

    attachments = []

    for part in message.walk():

        if part.is_multipart():
            continue

        filename = part.get_filename()

        if not filename:
            continue

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        attachments.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": calculate_sha256(payload)
        })

    return attachments


# ---------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------

def extract_domain(email_address: str | None) -> str | None:
    """Extract domain from an email address."""

    if not email_address or "@" not in email_address:
        return None

    return email_address.rsplit("@", 1)[1].lower()


# ---------------------------------------------------------
# Main parser
# ---------------------------------------------------------

def parse_eml(file_path: str | Path) -> dict:
    """Parse an EML file into structured forensic data."""

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    raw_data = file_path.read_bytes()

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_data)

    # -------------------------
    # Body
    # -------------------------

    plain_text, html_text = extract_body(message)

    # -------------------------
    # URLs
    # -------------------------

    urls = extract_urls(
        plain_text + "\n" + html_text
    )

    url_details = []

    for url in urls:

        parsed_url = urlparse(url)

        domain = (
             parsed_url.hostname.lower().rstrip(".")
             if parsed_url.hostname
             else None
    )

        url_details.append({
             "url": url,
             "domain": domain
    })

    # -------------------------
    # Headers
    # -------------------------

    headers = {
        "from": message.get("From"),
        "to": message.get("To"),
        "cc": message.get("Cc"),
        "bcc": message.get("Bcc"),
        "reply_to": message.get("Reply-To"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "message_id": message.get("Message-ID"),
        "return_path": message.get("Return-Path")
    }

    # -------------------------
    # Addresses
    # -------------------------

    from_addresses = get_addresses(
        message.get("From")
    )

    to_addresses = get_addresses(
        message.get("To")
    )

    cc_addresses = get_addresses(
        message.get("Cc")
    )

    reply_to_addresses = get_addresses(
        message.get("Reply-To")
    )

    # -------------------------
    # All headers
    # -------------------------

    all_headers = [
        {
            "name": key,
            "value": value
        }
        for key, value in message.items()
    ]

    # -------------------------
    # Authentication
    # -------------------------

    authentication = extract_authentication_results(
        message
    )

    # -------------------------
    # Received chain
    # -------------------------

    received_headers = extract_received_headers(
        message
    )

    # -------------------------
    # Attachments
    # -------------------------

    attachments = extract_attachments(
        message
    )

    # -------------------------
    # Domains
    # -------------------------

    sender_domain = None

    if from_addresses:
        sender_domain = extract_domain(
            from_addresses[0]
        )

    reply_to_domain = None

    if reply_to_addresses:
        reply_to_domain = extract_domain(
            reply_to_addresses[0]
        )

    # -------------------------
    # Final structured result
    # -------------------------

    return {

        "filename": file_path.name,

        "headers": headers,

        "addresses": {
            "from": from_addresses,
            "to": to_addresses,
            "cc": cc_addresses,
            "reply_to": reply_to_addresses
        },

        "domains": {
            "sender_domain": sender_domain,
            "reply_to_domain": reply_to_domain
        },

        "authentication": authentication,

        "received_chain": received_headers,

        "body": {
            "plain_text": plain_text,
            "html": html_text
        },

        "urls": url_details,

        "attachments": attachments,

        "all_headers": all_headers
    }
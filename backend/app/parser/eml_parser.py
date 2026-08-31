from email import policy
from email.parser import BytesParser
from email.message import Message
from email.utils import getaddresses
from pathlib import Path
import hashlib
import re


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)


def extract_urls(text: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from text."""

    if not text:
        return []

    urls = URL_PATTERN.findall(text)

    # Remove duplicates while preserving order
    return list(dict.fromkeys(urls))


def calculate_sha256(data: bytes) -> str:
    """Calculate SHA-256 hash of bytes."""

    return hashlib.sha256(data).hexdigest()


def get_addresses(header_value: str | None) -> list[str]:
    """Extract email addresses from a header."""

    if not header_value:
        return []

    return [
        address
        for _, address in getaddresses([header_value])
        if address
    ]


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

            # Ignore attachments
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

        attachment = {
            "filename": filename,
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": calculate_sha256(payload),
        }

        attachments.append(attachment)

    return attachments


def parse_eml(file_path: str | Path) -> dict:
    """Parse an EML file and return structured email information."""

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    raw_data = file_path.read_bytes()

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_data)

    plain_text, html_text = extract_body(message)

    # Collect URLs from both body formats
    urls = extract_urls(
        plain_text + "\n" + html_text
    )

    # Preserve all headers
    headers = [
        {
            "name": key,
            "value": value
        }
        for key, value in message.items()
    ]

    received_headers = [
        value
        for key, value in message.items()
        if key.lower() == "received"
    ]

    result = {
        "filename": file_path.name,

        "headers": {
            "from": message.get("From"),
            "to": message.get("To"),
            "cc": message.get("Cc"),
            "bcc": message.get("Bcc"),
            "reply_to": message.get("Reply-To"),
            "subject": message.get("Subject"),
            "date": message.get("Date"),
            "message_id": message.get("Message-ID"),
            "return_path": message.get("Return-Path"),
        },

        "addresses": {
            "from": get_addresses(message.get("From")),
            "to": get_addresses(message.get("To")),
            "cc": get_addresses(message.get("Cc")),
            "reply_to": get_addresses(message.get("Reply-To")),
        },

        "received_headers": received_headers,

        "all_headers": headers,

        "body": {
            "plain_text": plain_text,
            "html": html_text,
        },

        "urls": urls,

        "attachments": extract_attachments(message),
    }

    return result
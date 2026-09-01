# backend/app/analyzer/attachment_analyzer.py

from pathlib import Path


# File extensions that commonly require extra caution
DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".dll",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".ps1",
    ".hta",
}


# Extensions commonly associated with macro-enabled Office files
MACRO_EXTENSIONS = {
    ".docm",
    ".xlsm",
    ".pptm",
}


# Extensions commonly used for archives
ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
}


def analyze_attachments(attachments: list[dict]) -> list[dict]:
    """
    Analyze attachment metadata without executing or opening files.
    """

    indicators = []

    for attachment in attachments:

        filename = attachment.get("filename", "")
        content_type = attachment.get("content_type", "")

        if not filename:
            continue

        extension = Path(filename).suffix.lower()

        # -----------------------------------------
        # Dangerous executable extensions
        # -----------------------------------------

        if extension in DANGEROUS_EXTENSIONS:

            indicators.append({
                "type": "DANGEROUS_ATTACHMENT",
                "severity": "HIGH",
                "description": (
                    "The attachment uses a file extension "
                    "that can execute code or scripts."
                ),
                "filename": filename,
                "extension": extension
            })

        # -----------------------------------------
        # Macro-enabled Office files
        # -----------------------------------------

        if extension in MACRO_EXTENSIONS:

            indicators.append({
                "type": "MACRO_ENABLED_DOCUMENT",
                "severity": "HIGH",
                "description": (
                    "The attachment is a macro-enabled "
                    "Office document."
                ),
                "filename": filename,
                "extension": extension
            })

        # -----------------------------------------
        # Archive files
        # -----------------------------------------

        if extension in ARCHIVE_EXTENSIONS:

            indicators.append({
                "type": "ARCHIVE_ATTACHMENT",
                "severity": "MEDIUM",
                "description": (
                    "The attachment is an archive and "
                    "may contain additional files."
                ),
                "filename": filename,
                "extension": extension
            })

        # -----------------------------------------
        # Double extension
        # -----------------------------------------

        name_parts = filename.lower().split(".")

        if len(name_parts) >= 3:

            final_extension = "." + name_parts[-1]

            previous_extension = "." + name_parts[-2]

            if (
                final_extension in DANGEROUS_EXTENSIONS
                or previous_extension in DANGEROUS_EXTENSIONS
            ):

                indicators.append({
                    "type": "DOUBLE_EXTENSION",
                    "severity": "HIGH",
                    "description": (
                        "The filename contains multiple "
                        "extensions and may be disguising "
                        "a dangerous file type."
                    ),
                    "filename": filename
                })

        # -----------------------------------------
        # MIME type mismatch
        # -----------------------------------------

        if content_type:

            if (
                extension == ".pdf"
                and "pdf" not in content_type.lower()
            ):

                indicators.append({
                    "type": "MIME_EXTENSION_MISMATCH",
                    "severity": "MEDIUM",
                    "description": (
                        "The attachment extension and MIME "
                        "type appear inconsistent."
                    ),
                    "filename": filename,
                    "content_type": content_type
                })

    return indicators
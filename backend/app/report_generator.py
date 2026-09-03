from html import escape
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def _safe(value):
    if value is None:
        return "None"

    if isinstance(value, (dict, list)):
        return escape(str(value))

    return escape(str(value))


def generate_forensic_report(analysis: dict) -> BytesIO:
    """
    Generate a PDF forensic report from an email analysis result.
    """

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Email Forensic Report",
        author="Email Threat Detection",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=12,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
    )

    story = []

    # --------------------------------------------------
    # Title
    # --------------------------------------------------

    story.append(
        Paragraph(
            "EMAIL FORENSIC ANALYSIS REPORT",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Email Threat Detection & Threat Intelligence Platform",
            ParagraphStyle(
                "Subtitle",
                parent=body_style,
                alignment=TA_CENTER,
                fontSize=9,
            ),
        )
    )

    story.append(Spacer(1, 8))

    # --------------------------------------------------
    # Threat assessment
    # --------------------------------------------------

    threat = analysis.get("threat_assessment", {})

    score = threat.get("score", 0)
    risk_level = threat.get("risk_level", "UNKNOWN")
    verdict = threat.get("verdict", "UNKNOWN")
    confidence = threat.get("confidence", 0)

    story.append(
        Paragraph("Threat Assessment", heading_style)
    )

    assessment_data = [
        ["Threat Score", f"{score}/100"],
        ["Risk Level", _safe(risk_level)],
        ["Verdict", _safe(verdict)],
        ["Confidence", f"{round(confidence * 100)}%"],
    ]

    table = Table(
        assessment_data,
        colWidths=[55 * mm, 110 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(table)
    story.append(Spacer(1, 8))

    # --------------------------------------------------
    # Email details
    # --------------------------------------------------

    story.append(
        Paragraph("Email Details", heading_style)
    )

    headers = analysis.get("headers", {})

    email_data = [
        ["Filename", _safe(analysis.get("filename"))],
        ["SHA-256", _safe(analysis.get("file_sha256"))],
        ["From", _safe(headers.get("from"))],
        ["To", _safe(headers.get("to"))],
        ["CC", _safe(headers.get("cc"))],
        ["Reply-To", _safe(headers.get("reply_to"))],
        ["Subject", _safe(headers.get("subject"))],
        ["Date", _safe(headers.get("date"))],
    ]

    table = Table(
        email_data,
        colWidths=[35 * mm, 130 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.append(table)

    # --------------------------------------------------
    # Authentication
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Email Authentication",
            heading_style,
        )
    )

    authentication = analysis.get(
        "authentication",
        {},
    )

    auth_data = [
        ["SPF", _safe(authentication.get("spf"))],
        ["DKIM", _safe(authentication.get("dkim"))],
        ["DMARC", _safe(authentication.get("dmarc"))],
    ]

    table = Table(
        auth_data,
        colWidths=[45 * mm, 120 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.append(table)

    # --------------------------------------------------
    # Threat indicators
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Threat Indicators",
            heading_style,
        )
    )

    indicators = analysis.get(
        "indicators",
        [],
    )

    if not indicators:
        story.append(
            Paragraph(
                "No threat indicators detected.",
                body_style,
            )
        )
    else:
        for indicator in indicators:
            indicator_type = indicator.get(
                "type",
                "UNKNOWN",
            )

            severity = indicator.get(
                "severity",
                "UNKNOWN",
            )

            description = indicator.get(
                "description",
                "",
            )

            story.append(
                Paragraph(
                    f"<b>{_safe(indicator_type)}</b> "
                    f"— {_safe(severity)}",
                    body_style,
                )
            )

            story.append(
                Paragraph(
                    _safe(description),
                    small_style,
                )
            )

            story.append(Spacer(1, 3))

    # --------------------------------------------------
    # URLs
    # --------------------------------------------------

    story.append(
        Paragraph(
            "URL Intelligence",
            heading_style,
        )
    )

    urls = analysis.get("urls", [])

    if not urls:
        story.append(
            Paragraph(
                "No URLs detected.",
                body_style,
            )
        )
    else:
        url_data = [
            ["URL", "Domain"]
        ]

        for url in urls:
            url_data.append(
                [
                    _safe(url.get("url")),
                    _safe(url.get("domain")),
                ]
            )

        table = Table(
            url_data,
            colWidths=[110 * mm, 55 * mm],
            repeatRows=1,
        )

        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )

        story.append(table)

    # --------------------------------------------------
    # Attachments
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Attachments",
            heading_style,
        )
    )

    attachments = analysis.get(
        "attachments",
        [],
    )

    if not attachments:
        story.append(
            Paragraph(
                "No attachments detected.",
                body_style,
            )
        )
    else:
        for attachment in attachments:
            story.append(
                Paragraph(
                    _safe(attachment),
                    small_style,
                )
            )

    # --------------------------------------------------
    # Evidence
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Evidence",
            heading_style,
        )
    )

    evidence = threat.get(
        "evidence",
        [],
    )

    if not evidence:
        story.append(
            Paragraph(
                "No additional evidence recorded.",
                body_style,
            )
        )
    else:
        for item in evidence:
            story.append(
                Paragraph(
                    f"• {_safe(item)}",
                    body_style,
                )
            )

    # --------------------------------------------------
    # Recommended actions
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Recommended Actions",
            heading_style,
        )
    )

    actions = threat.get(
        "recommended_actions",
        [],
    )

    if not actions:
        story.append(
            Paragraph(
                "No specific actions recorded.",
                body_style,
            )
        )
    else:
        for action in actions:
            story.append(
                Paragraph(
                    f"• {_safe(action)}",
                    body_style,
                )
            )

    # --------------------------------------------------
    # AI Investigation
    # --------------------------------------------------

    llm = analysis.get(
        "llm_investigation",
        {},
    )

    if llm.get("enabled") and llm.get("analysis"):
        ai_analysis = llm.get("analysis", {})

        story.append(
            PageBreak()
        )

        story.append(
            Paragraph(
                "AI Investigation",
                heading_style,
            )
        )

        executive = ai_analysis.get(
            "executive_assessment"
        )

        if executive:
            story.append(
                Paragraph(
                    "<b>Executive Assessment</b>",
                    body_style,
                )
            )

            story.append(
                Paragraph(
                    _safe(executive),
                    body_style,
                )
            )

        key_evidence = ai_analysis.get(
            "key_evidence",
            [],
        )

        if key_evidence:
            story.append(
                Paragraph(
                    "<b>Key Evidence</b>",
                    body_style,
                )
            )

            for item in key_evidence:
                story.append(
                    Paragraph(
                        f"• {_safe(item)}",
                        body_style,
                    )
                )

        recommendations = ai_analysis.get(
            "recommended_actions",
            [],
        )

        if recommendations:
            story.append(
                Paragraph(
                    "<b>AI Recommended Actions</b>",
                    body_style,
                )
            )

            for item in recommendations:
                story.append(
                    Paragraph(
                        f"• {_safe(item)}",
                        body_style,
                    )
                )

    # --------------------------------------------------
    # Footer
    # --------------------------------------------------

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "Generated by Email Threat Detection — Forensic Analysis Platform",
            small_style,
        )
    )

    document.build(story)

    buffer.seek(0)

    return buffer
"""
Investigation summary generation.

This module converts structured forensic evidence into
a concise investigator-friendly summary.

It does not invent facts or perform independent forensic analysis.
"""


def generate_investigation_summary(evidence: dict) -> dict:
    """
    Generate a structured investigation summary from forensic evidence.
    """

    threat_assessment = evidence.get("threat_assessment", {})
    phishing_assessment = evidence.get("phishing_assessment", {})
    social_engineering = evidence.get(
        "social_engineering_assessment",
        {}
    )
    attack_assessment = evidence.get(
        "attack_type_assessment",
        {}
    )

    indicators = evidence.get("indicators", [])
    origin = evidence.get("origin", {})
    urls = evidence.get("urls", [])
    reputation = evidence.get("reputation", {})

    score = threat_assessment.get("score")
    risk_level = threat_assessment.get("risk_level")
    verdict = threat_assessment.get("verdict")

    attack_type = attack_assessment.get(
        "attack_type",
        "UNKNOWN"
    )

    phishing_classification = phishing_assessment.get(
        "classification"
    )

    # ---------------------------------------------------------
    # Build opening assessment
    # ---------------------------------------------------------

    if attack_type == "CREDENTIAL_PHISHING":
        opening = (
            "This email shows multiple indicators consistent "
            "with credential phishing."
        )

    elif attack_type == "BUSINESS_EMAIL_COMPROMISE":
        opening = (
            "This email shows indicators consistent with "
            "business email compromise."
        )

    elif attack_type == "FINANCIAL_FRAUD":
        opening = (
            "This email contains indicators consistent with "
            "financial fraud."
        )

    elif attack_type == "MALWARE_DELIVERY":
        opening = (
            "This email contains indicators associated with "
            "potential malware delivery."
        )

    elif attack_type == "IMPERSONATION":
        opening = (
            "This email contains indicators consistent with "
            "sender impersonation."
        )

    elif phishing_classification in {
        "PHISHING",
        "LIKELY_PHISHING",
    }:
        opening = (
            "This email contains multiple indicators consistent "
            "with phishing."
        )

    elif risk_level == "MEDIUM":
        opening = (
            "This email contains several suspicious indicators "
            "that require further investigation."
        )

    else:
        opening = (
            "No strong malicious pattern was identified from "
            "the available forensic evidence."
        )

    # ---------------------------------------------------------
    # Key findings
    # ---------------------------------------------------------

    findings = []

    for indicator in indicators:
        description = indicator.get("description")

        if description:
            findings.append(description)

    # Keep the summary concise.
    findings = findings[:8]

    # ---------------------------------------------------------
    # Origin finding
    # ---------------------------------------------------------

    earliest_ip = origin.get("earliest_reliable_ip")

    if earliest_ip:
        findings.append(
            f"The earliest reliable public origin IP identified "
            f"was {earliest_ip}."
        )
    else:
        findings.append(
            "No reliable public origin IP could be established "
            "from the available headers."
        )

    # ---------------------------------------------------------
    # URL finding
    # ---------------------------------------------------------

    if urls:
        findings.append(
            f"{len(urls)} URL(s) were identified in the email."
        )

    # ---------------------------------------------------------
    # Reputation findings
    # ---------------------------------------------------------

    malicious_reputation_count = 0

    for category in ("ip", "domain", "url"):
        for item in reputation.get(category, []):
            if item.get("malicious") is True:
                malicious_reputation_count += 1

    if malicious_reputation_count:
        findings.append(
            f"{malicious_reputation_count} reputation source(s) "
            "reported malicious activity."
        )

    # ---------------------------------------------------------
    # Social engineering finding
    # ---------------------------------------------------------

    if social_engineering.get("social_engineering") is True:
        findings.append(
            "The email contains social-engineering indicators "
            "intended to influence or pressure the recipient."
        )

    # Remove duplicates while preserving order.
    unique_findings = []

    for finding in findings:
        if finding not in unique_findings:
            unique_findings.append(finding)

    # ---------------------------------------------------------
    # Final summary text
    # ---------------------------------------------------------

    summary_parts = [opening]

    if unique_findings:
        summary_parts.append(
            "Key findings: "
            + " ".join(unique_findings)
        )

    assessment_sentence = (
        f"Overall assessment: {risk_level or 'UNKNOWN'} risk"
    )

    if score is not None:
        assessment_sentence += f" with a threat score of {score}/100"

    if verdict:
        assessment_sentence += f" ({verdict})"

    assessment_sentence += "."

    summary_parts.append(assessment_sentence)

    # ---------------------------------------------------------
    # Structured response
    # ---------------------------------------------------------

    return {
        "summary": " ".join(summary_parts),
        "key_findings": unique_findings,
        "risk_level": risk_level,
        "threat_score": score,
        "verdict": verdict,
        "attack_type": attack_type,
        "phishing_classification": phishing_classification,
        "social_engineering": social_engineering.get(
            "social_engineering"
        ),
        "confidence": (
            attack_assessment.get("confidence")
            or phishing_assessment.get("confidence")
            or threat_assessment.get("confidence")
        ),
    }
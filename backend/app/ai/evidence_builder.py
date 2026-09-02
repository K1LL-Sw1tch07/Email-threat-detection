"""
Build a clean evidence package for the AI/NLP layer.

The AI receives structured forensic evidence rather than
the complete raw EML or internal backend state.
"""


def build_ai_evidence(result: dict) -> dict:
    """
    Convert forensic analysis into a compact AI-ready evidence package.
    """

    headers = result.get("headers", {})
    authentication = result.get("authentication", {})
    origin = result.get("origin_analysis", {})
    domains = result.get("domains", {})
    threat_assessment = result.get("threat_assessment", {})

    # ---------------------------------------------------------
    # Authentication evidence
    # ---------------------------------------------------------

    authentication_evidence = {
        "spf": authentication.get("spf"),
        "dkim": authentication.get("dkim"),
        "dmarc": authentication.get("dmarc"),
    }

    # ---------------------------------------------------------
    # URL evidence
    # ---------------------------------------------------------

    urls = []

    for url_data in result.get("urls", []):
        urls.append({
            "url": url_data.get("url"),
            "domain": url_data.get("domain"),
            "scheme": url_data.get("scheme"),
            "indicators": url_data.get("indicators", []),
        })

    # ---------------------------------------------------------
    # Reputation evidence
    # ---------------------------------------------------------

    reputation = {
        "ip": [],
        "domain": [],
        "url": [],
    }

    for item in result.get("ip_reputation", []):
        reputation["ip"].append({
            "ip": item.get("ip"),
            "provider": item.get("provider"),
            "malicious": item.get("malicious"),
            "confidence": item.get("confidence"),
            "abuse_score": item.get("abuse_score"),
        })

    for item in result.get("domain_reputation", []):
        reputation["domain"].append({
            "domain": item.get("domain"),
            "provider": item.get("provider"),
            "malicious": item.get("malicious"),
            "suspicious": item.get("suspicious"),
            "confidence": item.get("confidence"),
            "malicious_votes": item.get("malicious_votes"),
            "suspicious_votes": item.get("suspicious_votes"),
        })

    for item in result.get("url_reputation", []):
        reputation["url"].append({
            "url": item.get("url"),
            "provider": item.get("provider"),
            "malicious": item.get("malicious"),
            "suspicious": item.get("suspicious"),
            "confidence": item.get("confidence"),
            "malicious_votes": item.get("malicious_votes"),
            "suspicious_votes": item.get("suspicious_votes"),
        })

    # ---------------------------------------------------------
    # Indicator evidence
    # ---------------------------------------------------------

    indicators = []

    for indicator in result.get("indicators", []):
        indicators.append({
            "type": indicator.get("type"),
            "severity": indicator.get("severity"),
            "description": indicator.get("description"),
        })

    # ---------------------------------------------------------
    # Origin evidence
    # ---------------------------------------------------------

    origin_evidence = {
        "earliest_reliable_ip": origin.get("earliest_reliable_ip"),
        "confidence": origin.get("confidence"),
        "reason": origin.get("reason"),
        "candidate_ips": origin.get("candidate_ips", []),
        "global_ips": origin.get("global_ips", []),
        "excluded_ips": origin.get("excluded_ips", []),
    }

    # ---------------------------------------------------------
    # Final AI evidence package
    # ---------------------------------------------------------

    return {
        "sender": headers.get("from"),
        "recipient": headers.get("to"),
        "reply_to": headers.get("reply_to"),
        "subject": headers.get("subject"),

        "sender_domain": domains.get("sender_domain"),

        "authentication": authentication_evidence,

        "origin": origin_evidence,

        "urls": urls,

        "reputation": reputation,

        "indicators": indicators,

        "threat_assessment": {
            "score": threat_assessment.get("score"),
            "risk_level": threat_assessment.get("risk_level"),
            "verdict": threat_assessment.get("verdict"),
            "confidence": threat_assessment.get("confidence"),
        },
    }
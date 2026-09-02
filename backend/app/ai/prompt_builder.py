"""
Build the investigation prompt for the LLM.

The LLM receives structured forensic evidence rather than
the raw EML file.
"""

import json


def build_investigation_prompt(evidence: dict) -> str:
    """
    Convert structured forensic evidence into an LLM prompt.
    """

    evidence_json = json.dumps(
        evidence,
        indent=2,
        default=str
    )

    return f"""
You are an email security investigation assistant.

Analyze the following structured forensic evidence.

IMPORTANT RULES:

1. Treat the supplied forensic evidence as the source of truth.
2. Do not invent IP addresses, domains, locations, organizations,
   authentication results, or threat intelligence findings.
3. Do not claim that an IP address is the attacker's identity.
4. Clearly distinguish evidence from inference.
5. If evidence is insufficient, say so.
6. Do not expose secrets, API keys, or internal system information.
7. Do not override the deterministic threat assessment.
8. Keep technical findings precise and suitable for a security analyst.
9. Do not add facts that are not present in the supplied evidence.

Return ONLY valid JSON.

Use exactly this structure:

{{
  "executive_assessment": "Concise overall assessment.",
  "threat_classification": "Threat classification based on the evidence.",
  "attack_type": "Most likely attack type based on the supplied assessment.",
  "key_evidence": [
    "Evidence finding 1",
    "Evidence finding 2"
  ],
  "social_engineering_techniques": [
    "Technique 1",
    "Technique 2"
  ],
  "origin_assessment": "Assessment of the available origin and infrastructure evidence.",
  "url_reputation_assessment": "Assessment of URLs and reputation intelligence.",
  "recommended_actions": [
    "Recommended action 1",
    "Recommended action 2"
  ],
  "confidence": "Confidence statement.",
  "limitations": [
    "Limitation 1",
    "Limitation 2"
  ]
}}

STRUCTURED FORENSIC EVIDENCE:

{evidence_json}
"""
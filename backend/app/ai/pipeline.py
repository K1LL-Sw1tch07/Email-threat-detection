"""
Unified AI analysis pipeline.

This module connects the individual AI/evidence-based
analysis components into one consistent workflow.
"""

from app.ai.evidence_builder import build_ai_evidence
from app.ai.classifier import classify_phishing
from app.ai.social_engineering import analyze_social_engineering
from app.ai.attack_classifier import classify_attack_type
from app.ai.summarizer import generate_investigation_summary
from app.ai.llm_investigator import investigate_with_llm


def run_ai_analysis(result: dict) -> dict:
    """
    Run the complete AI analysis pipeline.

    The pipeline uses forensic evidence as its source of truth.
    """

    # ---------------------------------------------------------
    # 1. Build structured evidence
    # ---------------------------------------------------------

    evidence = build_ai_evidence(result)

    # ---------------------------------------------------------
    # 2. Phishing classification
    # ---------------------------------------------------------

    phishing_assessment = classify_phishing(evidence)

    evidence["phishing_assessment"] = phishing_assessment

    # ---------------------------------------------------------
    # 3. Social engineering analysis
    # ---------------------------------------------------------

    social_engineering_assessment = analyze_social_engineering(
        evidence
    )

    evidence["social_engineering_assessment"] = (
        social_engineering_assessment
    )

    # ---------------------------------------------------------
    # 4. Attack type classification
    # ---------------------------------------------------------

    attack_type_assessment = classify_attack_type(
        evidence
    )

    evidence["attack_type_assessment"] = (
        attack_type_assessment
    )

    # ---------------------------------------------------------
    # 5. Investigation summary
    # ---------------------------------------------------------

    investigation_summary = generate_investigation_summary(
        evidence
    )
    llm_investigation = investigate_with_llm(
        evidence
)

    # ---------------------------------------------------------
    # Final result
    # ---------------------------------------------------------

    return {
        "ai_evidence": evidence,
        "phishing_assessment": phishing_assessment,
        "social_engineering_assessment": (
            social_engineering_assessment
        ),
        "attack_type_assessment": (
            attack_type_assessment
        ),
        "investigation_summary": investigation_summary,
        "llm_investigation": llm_investigation,
    }
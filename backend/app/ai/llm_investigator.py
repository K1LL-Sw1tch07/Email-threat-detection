"""
LLM-powered email investigation.

The LLM interprets structured forensic evidence.
It does not replace deterministic forensic analysis.
"""

from app.ai.prompt_builder import build_investigation_prompt
from app.ai.llm_client import run_llm_analysis


def investigate_with_llm(evidence: dict) -> dict:
    """
    Run an LLM investigation using structured forensic evidence.
    """

    prompt = build_investigation_prompt(evidence)

    llm_result = run_llm_analysis(prompt)

    return {
        "enabled": llm_result.get("success", False),
        "provider": llm_result.get("provider"),
        "model": llm_result.get("model"),
        "analysis": llm_result.get("response"),
        "error": llm_result.get("error"),
    }
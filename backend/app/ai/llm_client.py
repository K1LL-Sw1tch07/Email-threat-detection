"""
Gemini-powered LLM client.

The LLM interprets structured forensic evidence.
It does not replace deterministic forensic analysis.
"""

import json
import os

from google import genai

from app import config


def get_gemini_client():
    """
    Create a Gemini client using the API key
    loaded from the project's environment.
    """

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return None

    return genai.Client(api_key=api_key)


def run_llm_analysis(prompt: str) -> dict:
    """
    Send an investigation prompt to Gemini.

    Gemini is instructed to return structured JSON.
    The function safely handles API failures and malformed
    model responses.
    """

    client = get_gemini_client()

    model = os.getenv(
        "GEMINI_MODEL",
        "gemini-3.5-flash-lite"
    )

    if client is None:
        return {
            "success": False,
            "provider": "google_gemini",
            "model": model,
            "response": None,
            "error": "GEMINI_API_KEY is not configured."
        }

    try:
        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config={
                "response_mime_type": "application/json"
            }
        )

        response_text = response.text

        if not response_text:
            return {
                "success": False,
                "provider": "google_gemini",
                "model": model,
                "response": None,
                "error": "Gemini returned an empty response."
            }

        try:
            parsed_response = json.loads(response_text)
        except json.JSONDecodeError:
            return {
                "success": False,
                "provider": "google_gemini",
                "model": model,
                "response": None,
                "error": "Gemini returned invalid JSON."
            }

        return {
            "success": True,
            "provider": "google_gemini",
            "model": model,
            "response": parsed_response,
            "error": None
        }

    except Exception as error:
        return {
            "success": False,
            "provider": "google_gemini",
            "model": model,
            "response": None,
            "error": str(error)
        }
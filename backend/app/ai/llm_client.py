"""
Gemini-powered LLM client.

The LLM interprets structured forensic evidence.
It does not replace deterministic forensic analysis.

Includes automatic model fallback so temporary model
availability/rate-limit failures do not disable AI
explanation completely.
"""

import json
import os

from google import genai


# Models are tried in this order.
# The first model can be overridden through GEMINI_MODEL.
DEFAULT_MODELS = [
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-flash-lite-latest",
]


def get_gemini_client():
    """
    Create a Gemini client using the API key
    loaded from the project's environment.
    """

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return None

    return genai.Client(api_key=api_key)


def get_model_list():
    """
    Build the model fallback list.

    GEMINI_MODEL, when configured, is attempted first.
    Duplicate models are removed automatically.
    """

    configured_model = os.getenv("GEMINI_MODEL")

    models = []

    if configured_model:
        models.append(configured_model)

    models.extend(DEFAULT_MODELS)

    # Remove duplicates while preserving order
    return list(dict.fromkeys(models))


def run_llm_analysis(prompt: str) -> dict:
    """
    Send an investigation prompt to Gemini.

    Models are attempted sequentially. If a model is
    temporarily unavailable, rate-limited, times out,
    or otherwise fails, the next model is attempted.

    Gemini is instructed to return structured JSON.
    The LLM does not replace deterministic forensic analysis.
    """

    client = get_gemini_client()

    models = get_model_list()

    if client is None:
        return {
            "success": False,
            "provider": "google_gemini",
            "model": None,
            "response": None,
            "fallback_used": False,
            "attempted_models": [],
            "error": "GEMINI_API_KEY is not configured."
        }

    attempted_models = []
    errors = []

    for model in models:

        attempted_models.append(model)

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
                errors.append(
                    f"{model}: Gemini returned an empty response."
                )
                continue

            try:
                parsed_response = json.loads(response_text)

            except json.JSONDecodeError:
                errors.append(
                    f"{model}: Gemini returned invalid JSON."
                )
                continue

            return {
                "success": True,
                "provider": "google_gemini",
                "model": model,
                "response": parsed_response,
                "fallback_used": len(attempted_models) > 1,
                "attempted_models": attempted_models,
                "error": None
            }

        except Exception as error:

            errors.append(
                f"{model}: {str(error)}"
            )

            # Try the next model
            continue

    return {
        "success": False,
        "provider": "google_gemini",
        "model": None,
        "response": None,
        "fallback_used": len(attempted_models) > 1,
        "attempted_models": attempted_models,
        "error": "All Gemini models failed.",
        "model_errors": errors
    }
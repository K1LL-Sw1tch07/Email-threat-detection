from app.ai.llm_investigator import investigate_with_llm


def test_llm_investigator_success(monkeypatch):
    def mock_run_llm_analysis(prompt):
        return {
            "success": True,
            "provider": "google_gemini",
            "model": "gemini-3.5-flash-lite",
            "response": "Test Gemini investigation",
            "error": None,
        }

    monkeypatch.setattr(
        "app.ai.llm_investigator.run_llm_analysis",
        mock_run_llm_analysis,
    )

    evidence = {
        "threat_assessment": {
            "score": 70,
            "risk_level": "HIGH",
            "verdict": "SUSPICIOUS",
        }
    }

    result = investigate_with_llm(evidence)

    assert result["enabled"] is True
    assert result["provider"] == "google_gemini"
    assert result["model"] == "gemini-3.5-flash-lite"
    assert result["analysis"] == "Test Gemini investigation"
    assert result["error"] is None


def test_llm_investigator_failure(monkeypatch):
    def mock_run_llm_analysis(prompt):
        return {
            "success": False,
            "provider": "google_gemini",
            "model": "gemini-3.5-flash-lite",
            "response": None,
            "error": "API quota exceeded",
        }

    monkeypatch.setattr(
        "app.ai.llm_investigator.run_llm_analysis",
        mock_run_llm_analysis,
    )

    evidence = {
        "threat_assessment": {
            "score": 70,
            "risk_level": "HIGH",
            "verdict": "SUSPICIOUS",
        }
    }

    result = investigate_with_llm(evidence)

    assert result["enabled"] is False
    assert result["provider"] == "google_gemini"
    assert result["analysis"] is None
    assert result["error"] == "API quota exceeded"


def test_llm_investigator_handles_missing_api_key(monkeypatch):
    def mock_run_llm_analysis(prompt):
        return {
            "success": False,
            "provider": "google_gemini",
            "model": "gemini-3.5-flash-lite",
            "response": None,
            "error": "GEMINI_API_KEY is not configured.",
        }

    monkeypatch.setattr(
        "app.ai.llm_investigator.run_llm_analysis",
        mock_run_llm_analysis,
    )

    result = investigate_with_llm({})

    assert result["enabled"] is False
    assert result["analysis"] is None
    assert result["error"] == "GEMINI_API_KEY is not configured."
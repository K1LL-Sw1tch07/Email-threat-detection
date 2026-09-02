from app.ai.llm_client import run_llm_analysis


class MockResponse:
    text = "this is not valid json"


class MockModels:
    def generate_content(self, **kwargs):
        return MockResponse()


class MockClient:
    models = MockModels()


def test_llm_client_rejects_invalid_json(monkeypatch):
    monkeypatch.setenv(
        "GEMINI_API_KEY",
        "test-key"
    )

    monkeypatch.setenv(
        "GEMINI_MODEL",
        "gemini-3.5-flash-lite"
    )

    monkeypatch.setattr(
        "app.ai.llm_client.get_gemini_client",
        lambda: MockClient()
    )

    result = run_llm_analysis(
        "test investigation prompt"
    )

    assert result["success"] is False
    assert result["response"] is None
    assert result["error"] == "Gemini returned invalid JSON."
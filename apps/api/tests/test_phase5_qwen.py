import pytest

from nope_api import ai
from nope_api.config import Settings
from nope_api.models import Confidence, Evidence, Finding, Severity


def sample_finding() -> Finding:
    return Finding(
        fingerprint="phase5-secret",
        title="Hardcoded API key",
        description="A secret-looking token appears in source.",
        severity=Severity.high,
        confidence=Confidence.medium,
        category="Secrets",
        affected_file="app/api/route.ts",
        remediation="Move the secret to a managed secret store and rotate it.",
        scanner_sources=["NOPE rules"],
        evidence=[
            Evidence(
                source="NOPE rules",
                file="app/api/route.ts",
                line=3,
                message="Found api_key=sk-test-phase5-secret-value in source.",
                snippet='const api_key = "sk-test-phase5-secret-value";',
            )
        ],
    )


def qwen_settings() -> Settings:
    return Settings(
        ai_provider="llama.cpp",
        qwen_endpoint="http://nope-ai:8080",
        ai_runtime_url="http://nope-ai:8080",
        qwen_gpu_layers=20,
        ai_gpu_layers=20,
        qwen_gpu_memory_target_mb=5000,
        ai_gpu_memory_target_mb=5000,
    )


def test_retrieved_context_is_focused_and_redacted():
    context = ai.retrieve_context([sample_finding()], 4)
    dumped = ai.context_as_prompt(context)

    assert "Hardcoded API key" in dumped
    assert "sk-test-phase5-secret-value" not in dumped
    assert "[REDACTED]" in dumped
    assert "app/api/route.ts" in dumped


@pytest.mark.asyncio
async def test_structured_completion_validates_qwen_json(monkeypatch):
    async def fake_completion(settings, *, system, user, json_mode=False):
        assert json_mode is True
        assert "Focused graph-aware evidence JSON" in user
        return {
            "content": """
            {
              "summary": "The evidence supports a hardcoded secret finding.",
              "evidence": ["NOPE rules reported a redacted token in app/api/route.ts."],
              "reasoning": "A secret-like token appears in source evidence.",
              "recommendation": "Rotate the token and move it to managed secrets.",
              "confidence": "high",
              "risk": "high"
            }
            """,
            "raw": {},
        }

    monkeypatch.setattr(ai, "llama_chat_completion", fake_completion)

    result = await ai.structured_completion(qwen_settings(), "explain", sample_finding())

    assert result.summary.startswith("The evidence supports")
    assert result.confidence == "high"
    assert result.risk == "high"


@pytest.mark.asyncio
async def test_structured_completion_rejects_invalid_json(monkeypatch):
    async def fake_completion(settings, *, system, user, json_mode=False):
        return {"content": "not json", "raw": {}}

    monkeypatch.setattr(ai, "llama_chat_completion", fake_completion)

    with pytest.raises(RuntimeError, match="Structured Qwen output failed validation"):
        await ai.structured_completion(qwen_settings(), "fix", sample_finding())


@pytest.mark.asyncio
async def test_ai_review_failure_preserves_deterministic_scan(monkeypatch):
    async def fake_health(settings):
        return {"status": "ok", "message": "ok"}

    async def failing_structured(settings, action, finding):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(ai, "check_ai_health", fake_health)
    monkeypatch.setattr(ai, "structured_completion", failing_structured)

    review = await ai.run_ai_review(qwen_settings(), [sample_finding()])

    assert review.status == "Failed"
    assert "deterministic scan results were preserved" in review.message
    assert review.evidence_provided


def test_gpu_target_is_capped_to_5000_mb():
    settings = Settings(qwen_gpu_memory_target_mb=6000, ai_gpu_memory_target_mb=5120)

    assert settings.effective_qwen_gpu_memory_target_mb == 5000

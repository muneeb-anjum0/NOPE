import httpx

from nope_api.config import Settings
from nope_api.models import AIReview, Confidence, Finding


def retrieve_context(findings: list[Finding], max_chunks: int) -> list[str]:
    chunks: list[str] = []
    for finding in findings[:max_chunks]:
        evidence = finding.evidence[0] if finding.evidence else None
        chunks.append(
            "\n".join(
                [
                    f"Finding: {finding.title}",
                    f"Severity: {finding.severity.value}",
                    f"File: {finding.affected_file or 'n/a'}",
                    f"Route: {finding.affected_route or 'n/a'}",
                    f"Evidence: {evidence.message if evidence else 'n/a'}",
                    f"Snippet: {evidence.snippet if evidence else 'n/a'}",
                ]
            )
        )
    return chunks


async def run_ai_review(settings: Settings, findings: list[Finding]) -> AIReview:
    if settings.ai_provider == "none":
        return AIReview(
            status="Not tested",
            provider="none",
            message="AI provider is disabled. Deterministic scanning completed without AI reasoning.",
        )
    context = retrieve_context(findings, settings.ai_max_retrieved_chunks)
    if not context:
        return AIReview(status="Not tested", provider=settings.ai_provider, model=settings.ai_model_name, message="No findings required AI review.")
    try:
        async with httpx.AsyncClient(timeout=settings.ai_timeout_seconds) as client:
            health_url = settings.ai_runtime_url.rstrip("/") + "/api/tags"
            response = await client.get(health_url)
            response.raise_for_status()
        return AIReview(
            status="Partial",
            provider=settings.ai_provider,
            model=settings.ai_model_name,
            evidence_provided=context,
            confidence=Confidence.medium,
            missing_context=["Structured challenge generation is configured but runtime-specific generation is not enabled in local MVP."],
            message="AI runtime is reachable; deterministic findings were prepared for focused review.",
        )
    except Exception as exc:
        return AIReview(
            status="Failed",
            provider=settings.ai_provider,
            model=settings.ai_model_name,
            evidence_provided=context,
            message=f"AI runtime check failed: {exc}",
        )

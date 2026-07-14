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
        health = await check_ai_health(settings)
        if health["status"] != "ok":
            raise RuntimeError(health["message"])
        return AIReview(
            status="Complete" if settings.ai_provider == "llama.cpp" else "Partial",
            provider=settings.ai_provider,
            model=settings.ai_model_name,
            evidence_provided=context,
            confidence=Confidence.medium,
            missing_context=[],
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


async def check_ai_health(settings: Settings) -> dict:
    if settings.ai_provider == "none":
        return {"status": "disabled", "message": "AI provider is disabled."}
    try:
        async with httpx.AsyncClient(timeout=min(settings.ai_timeout_seconds, 10)) as client:
            if settings.ai_provider == "llama.cpp":
                response = await client.get(settings.ai_runtime_url.rstrip() + "/health")
            else:
                response = await client.get(settings.ai_runtime_url.rstrip("/") + "/api/tags")
            response.raise_for_status()
        return {"status": "ok", "message": "AI runtime is reachable."}
    except Exception as exc:
        return {"status": "failed", "message": str(exc)}


async def explain_finding(settings: Settings, finding: Finding) -> dict:
    context = retrieve_context([finding], settings.ai_max_retrieved_chunks)
    if settings.ai_provider == "none":
        return {"status": "Not tested", "message": "AI provider is disabled.", "explanation": None}
    if settings.ai_provider != "llama.cpp":
        return {"status": "Failed", "message": f"Unsupported provider for explanation: {settings.ai_provider}", "explanation": None}

    prompt = (
        "You are NOPE, an application security analysis layer. Explain this finding with evidence, "
        "technical impact, and a safe remediation. Do not claim certainty beyond the evidence.\n\n"
        + "\n\n".join(context)
    )
    payload = {
        "prompt": prompt,
        "n_predict": settings.ai_max_output_tokens,
        "temperature": settings.ai_temperature,
        "top_p": settings.ai_top_p,
        "stop": ["</s>"],
    }
    try:
        async with httpx.AsyncClient(timeout=settings.ai_timeout_seconds) as client:
            response = await client.post(settings.ai_runtime_url.rstrip("/") + "/completion", json=payload)
            response.raise_for_status()
        data = response.json()
        return {
            "status": "Complete",
            "message": "llama.cpp completion returned successfully.",
            "model": settings.ai_model_name,
            "explanation": data.get("content") or data.get("completion") or "",
        }
    except Exception as exc:
        return {"status": "Failed", "message": str(exc), "explanation": None}

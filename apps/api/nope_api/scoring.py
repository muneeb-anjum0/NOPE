from nope_api.models import CoverageRecord, CoverageStatus, Finding, Severity


SEVERITY_WEIGHTS = {
    Severity.critical: 35,
    Severity.high: 20,
    Severity.medium: 10,
    Severity.low: 4,
    Severity.info: 1,
}


def calculate_score(findings: list[Finding], coverage: list[CoverageRecord]) -> int:
    penalty = sum(SEVERITY_WEIGHTS[finding.severity] for finding in findings)
    untested_penalty = sum(5 for record in coverage if record.status in {CoverageStatus.not_tested, CoverageStatus.failed})
    return max(0, min(100, 100 - penalty - untested_penalty))


def coverage_percent(coverage: list[CoverageRecord]) -> int:
    if not coverage:
        return 0
    values = {
        CoverageStatus.verified: 1.0,
        CoverageStatus.partial: 0.5,
        CoverageStatus.not_applicable: 1.0,
        CoverageStatus.not_tested: 0.0,
        CoverageStatus.failed: 0.0,
    }
    return round(sum(values[record.status] for record in coverage) / len(coverage) * 100)


def verdict(score: int, coverage: int, findings: list[Finding]) -> str:
    if any(f.severity == Severity.critical for f in findings) or score < 35:
        return "NOPE. Do not ship this."
    if score < 65:
        return "Probably not. You have work to do."
    if coverage < 70:
        return "Maybe. Coverage is incomplete."
    if score < 90:
        return "Fine. Ship with the documented risks."
    return "...okay. Nothing serious was found in the tested scope."

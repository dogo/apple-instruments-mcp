from __future__ import annotations

from apple_instruments_mcp.analysis.models import AnalysisQuality


def assess_xml_quality(xml_content: str, evidence_found: bool, parser_name: str) -> AnalysisQuality:
    warnings: list[str] = []
    if not xml_content.strip():
        warnings.append("xctrace export produced no XML content for this parser.")
    elif not evidence_found:
        warnings.append(f"No recognizable {parser_name} data was found in the exported XML.")

    return AnalysisQuality(confidence="low" if warnings else "high", warnings=warnings)


def format_quality(quality: AnalysisQuality) -> str:
    if quality.confidence == "high":
        return ""

    lines = ["\n## Analysis Quality", f"- Confidence: **{quality.confidence}**"]
    lines.extend(f"- {warning}" for warning in quality.warnings)
    return "\n".join(lines)

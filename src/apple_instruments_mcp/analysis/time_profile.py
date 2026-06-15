from __future__ import annotations

from apple_instruments_mcp.analysis.models import (
    HotMethod,
    TimeProfileAnalysis,
)
from apple_instruments_mcp.analysis.severity import (
    format_delta,
    get_hot_method_suggestion,
    get_severity,
    get_status,
)
from apple_instruments_mcp.analysis.xml_helpers import parse_time_profile_xml

XPATH_TIME_PROFILE = '/trace-toc/run/data/table[@schema="time-profile"]'


def has_time_profiler_evidence(xml_content: str) -> bool:
    if 'schema name="time-profile"' in xml_content or "<tagged-backtrace" in xml_content:
        return True
    frames, total_ms = parse_time_profile_xml(xml_content)
    return bool(frames) or total_ms > 0


def parse_time_profiler(
    xml_content: str,
    *,
    total_good_ms: float = 16,
    total_critical_ms: float = 100,
    method_warning_ms: float = 50,
    method_critical_ms: float = 200,
) -> TimeProfileAnalysis:
    frames, total_ms = parse_time_profile_xml(xml_content)
    hot_methods: list[HotMethod] = []

    for frame in frames:
        if frame.self_ms < 5:
            continue
        hot_methods.append(
            HotMethod(
                symbol=frame.symbol,
                self_time_ms=round(frame.self_ms),
                total_time_ms=round(frame.total_ms),
                percent=round((frame.self_ms / total_ms) * 100) if total_ms > 0 else 0,
                severity=get_severity(frame.self_ms, method_critical_ms, method_warning_ms),
                suggestion=get_hot_method_suggestion(frame.symbol),
            )
        )

    hot_methods.sort(key=lambda method: method.self_time_ms, reverse=True)
    status = get_status(total_ms, total_good_ms, total_critical_ms)

    if status == "good":
        summary = "✅ CPU profile looks healthy - no dominant hot methods."
    elif status == "warning":
        summary = "⚠️ Some methods consuming significant CPU. Review top offenders."
    else:
        summary = "🔴 Heavy CPU usage detected. Main thread likely blocked - users will feel jank."

    recommendations: list[str] = []
    if any(method.severity == "critical" for method in hot_methods):
        recommendations.append("Move critical hot methods off the main thread using async/await or DispatchQueue.")
    recommendations.append("Use Instruments Time Profiler regularly during UI stress tests.")
    recommendations.append("Target < 16ms per frame (60fps) or < 8ms (120fps ProMotion) for main thread work.")

    return TimeProfileAnalysis(
        total_duration_ms=round(total_ms),
        status=status,
        hot_methods=hot_methods[:15],
        summary=summary,
        recommendations=recommendations,
    )


def format_time_profiler(analysis: TimeProfileAnalysis, bundle_id: str) -> str:
    lines = [
        f"# Time Profiler - {bundle_id}",
        f"\n{analysis.summary}",
        f"\n**Duration profiled:** {analysis.total_duration_ms}ms",
        "\n## Hot Methods",
    ]
    if not analysis.hot_methods:
        lines.append("No hot methods found.")
    else:
        for method in analysis.hot_methods:
            icon = "🔴" if method.severity == "critical" else "🟡" if method.severity == "warning" else "🟢"
            lines.append(f"\n{icon} `{method.symbol}`")
            lines.append(f"   Self: **{method.self_time_ms}ms** | Total: {method.total_time_ms}ms | {method.percent}% of CPU")
            if method.suggestion:
                lines.append(f"   💡 {method.suggestion}")

    lines.append("\n## Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in analysis.recommendations)
    return "\n".join(lines)


def compare_time_profile_analyses(
    baseline: TimeProfileAnalysis, candidate: TimeProfileAnalysis, target_name: str
) -> str:
    duration_delta = candidate.total_duration_ms - baseline.total_duration_ms
    baseline_methods = {method.symbol: method.self_time_ms for method in baseline.hot_methods}
    candidate_methods = {method.symbol: method.self_time_ms for method in candidate.hot_methods}
    changed_methods = sorted(
        set(baseline_methods) | set(candidate_methods),
        key=lambda symbol: abs(candidate_methods.get(symbol, 0) - baseline_methods.get(symbol, 0)),
        reverse=True,
    )[:10]

    lines = [
        f"# CPU Trace Comparison - {target_name}",
        "",
        f"**Baseline duration:** {baseline.total_duration_ms}ms",
        f"**Candidate duration:** {candidate.total_duration_ms}ms",
        f"**Duration delta:** {format_delta(duration_delta, 'ms')}",
        "",
        "## Changed Hot Methods",
    ]
    if not changed_methods:
        lines.append("No comparable hot methods found.")
    else:
        for symbol in changed_methods:
            before = baseline_methods.get(symbol, 0)
            after = candidate_methods.get(symbol, 0)
            lines.append(f"- `{symbol}`: {before}ms -> {after}ms ({format_delta(after - before, 'ms')})")
    return "\n".join(lines)

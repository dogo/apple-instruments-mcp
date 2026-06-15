from __future__ import annotations

from collections import defaultdict

from apple_instruments_mcp.analysis.models import (
    LaunchAnalysis,
    LaunchOffender,
    LaunchPhase,
    LaunchPhaseName,
)
from apple_instruments_mcp.analysis.severity import (
    format_delta,
    get_launch_suggestion,
    get_severity,
    get_status,
)
from apple_instruments_mcp.analysis.xml_helpers import parse_time_profile_xml

XPATH_APP_LAUNCH = '/trace-toc/run/data/table[@schema="time-profile"]'

_PRE_MAIN_MARKERS = (
    "dyld",
    "_dyld_",
    "ImageLoader",
    "MachO",
    "mach_o::",
    "PatchTable",
    "swift_",  # swift_conformsToProtocol, swift_class_, swift_demangle, ...
    "_swift_",
    "swift::",  # Swift runtime namespace
    "_objc_init",
    "objc_initialize",
    "load_images",
    "initializeMainExecutable",
    "Static Initializer",
    "Apply Fixups",
    "Map Image",
    "thread_start",
    "_pthread_start",
    "_pthread_workqueue",
    "getContextDescriptor",
    "MetadataCache",
    "+initialize",
)

_LAUNCH_PHASE_LABELS: dict[LaunchPhaseName, str] = {
    "pre-main": "pre-main (dyld + static init)",
    "post-main": "post-main (AppDelegate + UI)",
    "unknown": "uncategorized",
}


def _classify_launch_phase(symbol: str) -> LaunchPhaseName:
    if any(marker in symbol for marker in _PRE_MAIN_MARKERS):
        return "pre-main"
    if (
        symbol.startswith("-[")
        or "AppDelegate" in symbol
        or "SceneDelegate" in symbol
        or "UIApplication" in symbol
        or "applicationDidFinishLaunching" in symbol
        or "didFinishLaunchingWithOptions" in symbol
    ):
        return "post-main"
    return "unknown"


def has_launch_evidence(xml_content: str) -> bool:
    if 'schema name="time-profile"' in xml_content or "<tagged-backtrace" in xml_content:
        return True
    frames, total_ms = parse_time_profile_xml(xml_content)
    return bool(frames) or total_ms > 0


def parse_app_launch(
    xml_content: str,
    bundle_id: str,
    *,
    launch_good_ms: float = 400,
    launch_critical_ms: float = 1000,
    offender_warning_ms: float = 100,
    offender_critical_ms: float = 300,
) -> LaunchAnalysis:
    """Parse an App Launch trace's time-profile export.

    The App Launch xctrace template exports the same `time-profile` schema that Time
    Profiler does, so we reuse the same call-tree parser. We then classify each frame
    into pre-main (dyld / static init / Swift runtime) vs post-main (AppDelegate /
    UIApplication) by symbol heuristic to produce phase totals and per-offender phase
    tags. Note: total_launch_ms here is CPU-active launch time, not wall-clock — the
    xctrace export does not expose a clean "app became active" marker we can read.
    """
    frames, total_ms = parse_time_profile_xml(xml_content)

    phase_self_ms: dict[LaunchPhaseName, float] = defaultdict(float)
    for frame in frames:
        phase_self_ms[_classify_launch_phase(frame.symbol)] += frame.self_ms

    offenders: list[LaunchOffender] = []
    for frame in sorted(frames, key=lambda candidate: candidate.self_ms, reverse=True):
        if frame.self_ms < 5:
            continue
        if len(offenders) >= 15:
            break
        phase = _classify_launch_phase(frame.symbol)
        offenders.append(
            LaunchOffender(
                symbol=frame.symbol,
                self_time_ms=round(frame.self_ms),
                total_time_ms=round(frame.total_ms),
                percent=round((frame.self_ms / total_ms) * 100) if total_ms > 0 else 0,
                phase=phase,
                severity=get_severity(frame.self_ms, offender_critical_ms, offender_warning_ms),
                suggestion=get_launch_suggestion(frame.symbol, phase),
            )
        )

    phases: list[LaunchPhase] = []
    if total_ms > 0:
        for phase_name in ("pre-main", "post-main", "unknown"):
            duration = phase_self_ms.get(phase_name, 0.0)
            if duration <= 0:
                continue
            phases.append(
                LaunchPhase(
                    name=_LAUNCH_PHASE_LABELS[phase_name],
                    duration_ms=round(duration),
                    percent=round((duration / total_ms) * 100),
                )
            )

    critical_count = sum(1 for offender in offenders if offender.severity == "critical")
    warning_count = sum(1 for offender in offenders if offender.severity == "warning")
    recommendations: list[str] = []
    if critical_count > 0:
        recommendations.append(
            f"Fix {critical_count} critical offender(s) - each adds {offender_critical_ms:g}ms+ to launch."
        )
    if warning_count > 0:
        recommendations.append(
            f"{warning_count} method(s) between {offender_warning_ms:g}-{offender_critical_ms:g}ms - worth deferring to background."
        )
    if phase_self_ms.get("pre-main", 0) > phase_self_ms.get("post-main", 0):
        recommendations.append(
            "Pre-main dominates: reduce static initializers, +load / +initialize, and Swift protocol conformance scans."
        )
    recommendations.append(
        f"Target: launch CPU under {launch_good_ms:g}ms. Add XCTest performance tests to catch regressions."
    )

    status = get_status(total_ms, launch_good_ms, launch_critical_ms)
    if status == "good":
        summary = f"✅ Launch CPU {round(total_ms)}ms - within target."
    elif status == "warning":
        summary = f"⚠️ Launch CPU {round(total_ms)}ms - above {launch_good_ms:g}ms target. Users may notice the delay."
    else:
        summary = f"🔴 Launch CPU {round(total_ms)}ms - heavy startup work. Apple may flag this in App Store review."

    return LaunchAnalysis(
        total_launch_ms=round(total_ms),
        status=status,
        phases=phases,
        offenders=offenders,
        summary=summary,
        recommendations=recommendations,
    )


def format_launch(analysis: LaunchAnalysis, bundle_id: str) -> str:
    lines = [f"# App Launch Analysis - {bundle_id}", f"\n{analysis.summary}", f"\n**Total:** {analysis.total_launch_ms}ms"]
    if analysis.phases:
        lines.append("\n## Phases")
        for phase in analysis.phases:
            lines.append(f"- **{phase.name}:** {phase.duration_ms}ms ({phase.percent}%)")

    lines.append("\n## Top Offenders")
    if not analysis.offenders:
        lines.append("No significant offenders.")
    else:
        for offender in analysis.offenders:
            icon = "🔴" if offender.severity == "critical" else "🟡" if offender.severity == "warning" else "🟢"
            lines.append(f"\n{icon} `{offender.symbol}` [{offender.phase}]")
            lines.append(f"   Self: **{offender.self_time_ms}ms** | Total: {offender.total_time_ms}ms | {offender.percent}%")
            if offender.suggestion:
                lines.append(f"   💡 {offender.suggestion}")

    lines.append("\n## Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in analysis.recommendations)
    return "\n".join(lines)


def compare_launch_analyses(baseline: LaunchAnalysis, candidate: LaunchAnalysis, target_name: str) -> str:
    delta_ms = candidate.total_launch_ms - baseline.total_launch_ms
    baseline_offenders = {offender.symbol: offender.self_time_ms for offender in baseline.offenders}
    candidate_offenders = {offender.symbol: offender.self_time_ms for offender in candidate.offenders}
    changed_symbols = sorted(
        set(baseline_offenders) | set(candidate_offenders),
        key=lambda symbol: abs(candidate_offenders.get(symbol, 0) - baseline_offenders.get(symbol, 0)),
        reverse=True,
    )[:10]

    lines = [
        f"# Launch Trace Comparison - {target_name}",
        "",
        f"**Baseline:** {baseline.total_launch_ms}ms",
        f"**Candidate:** {candidate.total_launch_ms}ms",
        f"**Delta:** {format_delta(delta_ms, 'ms')}",
        "",
        "## Changed Offenders",
    ]
    if not changed_symbols:
        lines.append("No comparable offenders found.")
    else:
        for symbol in changed_symbols:
            before = baseline_offenders.get(symbol, 0)
            after = candidate_offenders.get(symbol, 0)
            lines.append(f"- `{symbol}`: {before}ms -> {after}ms ({format_delta(after - before, 'ms')})")
    return "\n".join(lines)

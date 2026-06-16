from __future__ import annotations

from collections import defaultdict

from apple_instruments_mcp.analysis.models import (
    HotMethod,
    MainThreadStats,
    ScopeInfo,
    TimeProfileAnalysis,
    TimeProfileSample,
)
from apple_instruments_mcp.analysis.severity import (
    format_delta,
    get_hot_method_suggestion,
    get_severity,
    get_status,
)
from apple_instruments_mcp.analysis.xml_helpers import (
    parse_time_profile_samples,
    parse_time_profile_xml,
)

XPATH_TIME_PROFILE = '/trace-toc/run/data/table[@schema="time-profile"]'

_NS_PER_MS = 1_000_000


def has_time_profiler_evidence(xml_content: str) -> bool:
    if 'schema name="time-profile"' in xml_content or "<tagged-backtrace" in xml_content:
        return True
    frames, total_ms = parse_time_profile_xml(xml_content)
    return bool(frames) or total_ms > 0


def _scope_samples(
    samples: list[TimeProfileSample], start_ms: int | None, end_ms: int | None
) -> tuple[list[TimeProfileSample], ScopeInfo | None]:
    if start_ms is None and end_ms is None:
        return samples, None
    lo_ms = max(start_ms, 0) if start_ms is not None else 0
    hi_ms = end_ms if end_ms is not None and end_ms > 0 else 0
    in_scope: list[TimeProfileSample] = []
    for sample in samples:
        if sample.time_ns <= 0:
            # No timestamp on this row — can't tell if it's in scope. Drop it
            # rather than guess; partial-data is worse than fewer samples.
            continue
        ms = sample.time_ns // _NS_PER_MS
        if ms < lo_ms:
            continue
        if hi_ms and ms > hi_ms:
            continue
        in_scope.append(sample)
    return in_scope, ScopeInfo(start_ms=lo_ms, end_ms=hi_ms, samples_in_scope=len(in_scope))


def _aggregate_methods(
    samples: list[TimeProfileSample],
    *,
    total_ms: float,
    method_warning_ms: float,
    method_critical_ms: float,
    user_binaries: frozenset[str],
) -> list[HotMethod]:
    self_ns: dict[str, int] = defaultdict(int)
    total_ns: dict[str, int] = defaultdict(int)
    binary_for: dict[str, str] = {}

    for sample in samples:
        leaf = sample.frames[0]
        self_ns[leaf.symbol] += sample.weight_ns
        binary_for.setdefault(leaf.symbol, leaf.binary)
        seen: set[str] = set()
        for frame in sample.frames:
            if frame.symbol in seen:
                continue
            seen.add(frame.symbol)
            total_ns[frame.symbol] += sample.weight_ns
            binary_for.setdefault(frame.symbol, frame.binary)

    methods: list[HotMethod] = []
    for symbol in set(self_ns) | set(total_ns):
        self_ms = self_ns.get(symbol, 0) / _NS_PER_MS
        if self_ms < 5:
            continue
        binary = binary_for.get(symbol, "")
        methods.append(
            HotMethod(
                symbol=symbol,
                self_time_ms=round(self_ms),
                total_time_ms=round(total_ns.get(symbol, 0) / _NS_PER_MS),
                percent=round((self_ms / total_ms) * 100) if total_ms > 0 else 0,
                severity=get_severity(self_ms, method_critical_ms, method_warning_ms),
                suggestion=get_hot_method_suggestion(symbol),
                binary=binary,
                is_user=_is_user_binary(binary, user_binaries),
            )
        )
    methods.sort(key=lambda m: m.self_time_ms, reverse=True)
    return methods


def _is_user_binary(binary: str, user_binaries: frozenset[str]) -> bool:
    if not binary:
        return False
    if not user_binaries:
        return False
    return binary in user_binaries


def _main_thread_stats(
    samples: list[TimeProfileSample], total_ms: float, hang_threshold_ms: int
) -> MainThreadStats | None:
    main_samples = [s for s in samples if s.is_main_thread]
    if not main_samples:
        return None
    threshold = max(hang_threshold_ms, 1)
    main_weight_ns = sum(s.weight_ns for s in main_samples)

    timestamped = sorted(
        (s.time_ns for s in main_samples if s.time_ns > 0), reverse=False
    )
    max_gap_ms = 0
    stalls = 0
    for prev, curr in zip(timestamped, timestamped[1:], strict=False):
        gap_ms = (curr - prev) // _NS_PER_MS
        if gap_ms > max_gap_ms:
            max_gap_ms = int(gap_ms)
        if gap_ms >= threshold:
            stalls += 1

    weight_pct = round(main_weight_ns / _NS_PER_MS / total_ms * 100, 1) if total_ms > 0 else 0.0
    return MainThreadStats(
        samples=len(main_samples),
        weight_ms=round(main_weight_ns / _NS_PER_MS),
        weight_pct=weight_pct,
        max_gap_ms=max_gap_ms,
        gap_threshold_ms=threshold,
        candidate_stalls=stalls,
    )


def parse_time_profiler(
    xml_content: str,
    *,
    total_good_ms: float = 16,
    total_critical_ms: float = 100,
    method_warning_ms: float = 50,
    method_critical_ms: float = 200,
    start_ms: int | None = None,
    end_ms: int | None = None,
    hang_threshold_ms: int = 250,
    user_binaries: tuple[str, ...] = (),
) -> TimeProfileAnalysis:
    samples, total_ms_unscoped = parse_time_profile_samples(xml_content)
    scoped_samples, scope = _scope_samples(samples, start_ms, end_ms)
    total_ms = (
        sum(s.weight_ns for s in scoped_samples) / _NS_PER_MS
        if scope is not None
        else total_ms_unscoped
    )

    binaries = frozenset(b for b in user_binaries if b)
    all_methods = _aggregate_methods(
        scoped_samples,
        total_ms=total_ms,
        method_warning_ms=method_warning_ms,
        method_critical_ms=method_critical_ms,
        user_binaries=binaries,
    )
    user_methods = [m for m in all_methods if m.is_user][:15] if binaries else []

    status = get_status(total_ms, total_good_ms, total_critical_ms)
    if status == "good":
        summary = "✅ CPU profile looks healthy - no dominant hot methods."
    elif status == "warning":
        summary = "⚠️ Some methods consuming significant CPU. Review top offenders."
    else:
        summary = "🔴 Heavy CPU usage detected. Main thread likely blocked - users will feel jank."

    recommendations: list[str] = []
    if any(method.severity == "critical" for method in all_methods):
        recommendations.append("Move critical hot methods off the main thread using async/await or DispatchQueue.")
    recommendations.append("Use Instruments Time Profiler regularly during UI stress tests.")
    recommendations.append("Target < 16ms per frame (60fps) or < 8ms (120fps ProMotion) for main thread work.")

    main_thread = _main_thread_stats(scoped_samples, total_ms, hang_threshold_ms)
    if main_thread is not None and main_thread.candidate_stalls > 0:
        recommendations.append(
            f"Main thread shows {main_thread.candidate_stalls} gap(s) ≥ {main_thread.gap_threshold_ms}ms — "
            "investigate as candidate stalls (confirm with the Hangs instrument)."
        )

    return TimeProfileAnalysis(
        total_duration_ms=round(total_ms),
        status=status,
        hot_methods=all_methods[:15],
        summary=summary,
        recommendations=recommendations,
        user_methods=user_methods,
        main_thread=main_thread,
        scope=scope,
    )


def _format_method(method: HotMethod) -> list[str]:
    icon = "🔴" if method.severity == "critical" else "🟡" if method.severity == "warning" else "🟢"
    header = f"{icon} `{method.symbol}`"
    if method.binary:
        header += f"  _{method.binary}_"
    body = f"   Self: **{method.self_time_ms}ms** | Total: {method.total_time_ms}ms | {method.percent}% of CPU"
    out = ["", header, body]
    if method.suggestion:
        out.append(f"   💡 {method.suggestion}")
    return out


def format_time_profiler(analysis: TimeProfileAnalysis, bundle_id: str) -> str:
    lines = [
        f"# Time Profiler - {bundle_id}",
        f"\n{analysis.summary}",
        f"\n**Duration profiled:** {analysis.total_duration_ms}ms",
    ]
    if analysis.scope is not None:
        scope = analysis.scope
        end_text = f"{scope.end_ms}ms" if scope.end_ms else "end"
        lines.append(
            f"**Scope:** {scope.start_ms}ms – {end_text} "
            f"({scope.samples_in_scope} samples in window)"
        )
    if analysis.main_thread is not None:
        mt = analysis.main_thread
        lines.append("\n## Main Thread")
        lines.append(
            f"- Samples: **{mt.samples}** "
            f"(~{mt.weight_ms}ms, {mt.weight_pct}% of analyzed CPU)"
        )
        lines.append(
            f"- Max gap between consecutive samples: **{mt.max_gap_ms}ms** "
            f"(threshold: {mt.gap_threshold_ms}ms)"
        )
        stalls_label = "🔴" if mt.candidate_stalls > 0 else "🟢"
        lines.append(
            f"- {stalls_label} Candidate stalls (gaps ≥ threshold): **{mt.candidate_stalls}**"
        )

    if analysis.user_methods:
        lines.append("\n## Top User Methods")
        for method in analysis.user_methods:
            lines.extend(_format_method(method))

    lines.append("\n## Hot Methods")
    if not analysis.hot_methods:
        lines.append("No hot methods found.")
    else:
        for method in analysis.hot_methods:
            lines.extend(_format_method(method))

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

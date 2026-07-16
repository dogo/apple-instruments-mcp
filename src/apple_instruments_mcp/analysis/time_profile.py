from __future__ import annotations

from collections import defaultdict

from apple_instruments_mcp.analysis.models import (
    HotMethod,
    MainThreadStats,
    ScopeInfo,
    Status,
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
_MS_PER_SECOND = 1_000


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
        if sample.time_ns is None:
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

    timestamped = sorted(s.time_ns for s in main_samples if s.time_ns is not None)
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


def _cpu_load(
    samples: list[TimeProfileSample], total_cpu_ms: float
) -> tuple[int | None, float | None]:
    """Return observed wall span and normalized CPU-active milliseconds/second.

    Time Profiler weights are cumulative CPU-active time across threads. Comparing
    that total directly with a frame budget (16ms/100ms) makes longer recordings
    look critical by construction. When timestamped samples are available, divide
    cumulative CPU time by the observed wall-clock span instead.
    """
    timestamped = [
        (sample.time_ns, sample.weight_ns)
        for sample in samples
        if sample.time_ns is not None
    ]
    if len(timestamped) < 2:
        return None, None

    started_ns = min(time_ns for time_ns, _ in timestamped)
    finished_ns = max(time_ns + weight_ns for time_ns, weight_ns in timestamped)
    span_ms = (finished_ns - started_ns) / _NS_PER_MS
    if span_ms <= 0:
        return None, None

    cpu_ms_per_second = total_cpu_ms / span_ms * _MS_PER_SECOND
    return round(span_ms), round(cpu_ms_per_second, 1)


def _profile_status(
    methods: list[HotMethod],
    main_thread: MainThreadStats | None,
    cpu_ms_per_second: float | None,
    *,
    total_good_ms: float,
    total_critical_ms: float,
) -> Status:
    if cpu_ms_per_second is not None:
        status = get_status(cpu_ms_per_second, total_good_ms, total_critical_ms)
        if status == "good" and any(method.severity != "good" for method in methods):
            status = "warning"
    elif any(method.severity == "critical" for method in methods):
        status = "critical"
    elif any(method.severity == "warning" for method in methods):
        status = "warning"
    else:
        status = "good"

    if main_thread is not None and main_thread.candidate_stalls > 0 and status == "good":
        return "warning"
    return status


def build_time_profile_analysis(
    samples: list[TimeProfileSample],
    total_ms_unscoped: float,
    *,
    total_good_ms: float = 100,
    total_critical_ms: float = 500,
    method_warning_ms: float = 50,
    method_critical_ms: float = 200,
    start_ms: int | None = None,
    end_ms: int | None = None,
    hang_threshold_ms: int = 250,
    user_binaries: tuple[str, ...] = (),
) -> TimeProfileAnalysis:
    """Aggregate pre-parsed samples into a TimeProfileAnalysis.

    Split out of `parse_time_profiler` so the orchestrator can run an async
    symbolication pass between `parse_time_profile_samples` and aggregation.
    """
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

    profile_span_ms, cpu_ms_per_second = _cpu_load(scoped_samples, total_ms)
    main_thread = _main_thread_stats(scoped_samples, total_ms, hang_threshold_ms)
    status = _profile_status(
        all_methods,
        main_thread,
        cpu_ms_per_second,
        total_good_ms=total_good_ms,
        total_critical_ms=total_critical_ms,
    )
    if status == "good":
        summary = "✅ CPU profile looks healthy - no dominant hot methods."
    elif status == "warning":
        summary = "⚠️ CPU load, hot methods, or candidate stalls merit review."
    else:
        summary = "🔴 Sustained CPU load or dominant hot methods detected. Investigate before shipping."

    recommendations: list[str] = []
    if any(method.severity == "critical" for method in all_methods):
        recommendations.append(
            "Optimize critical hot methods; if they run on the main thread, move suitable work off it."
        )
    recommendations.append("Use Instruments Time Profiler regularly during UI stress tests.")
    recommendations.append("Target < 16ms per frame (60fps) or < 8ms (120fps ProMotion) for main thread work.")

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
        profile_span_ms=profile_span_ms,
        cpu_ms_per_second=cpu_ms_per_second,
    )


def parse_time_profiler(
    xml_content: str,
    *,
    total_good_ms: float = 100,
    total_critical_ms: float = 500,
    method_warning_ms: float = 50,
    method_critical_ms: float = 200,
    start_ms: int | None = None,
    end_ms: int | None = None,
    hang_threshold_ms: int = 250,
    user_binaries: tuple[str, ...] = (),
) -> TimeProfileAnalysis:
    samples, total_ms_unscoped = parse_time_profile_samples(xml_content)
    return build_time_profile_analysis(
        samples,
        total_ms_unscoped,
        total_good_ms=total_good_ms,
        total_critical_ms=total_critical_ms,
        method_warning_ms=method_warning_ms,
        method_critical_ms=method_critical_ms,
        start_ms=start_ms,
        end_ms=end_ms,
        hang_threshold_ms=hang_threshold_ms,
        user_binaries=user_binaries,
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
        f"\n**CPU-active time:** {analysis.total_duration_ms}ms",
    ]
    if analysis.profile_span_ms is not None and analysis.cpu_ms_per_second is not None:
        one_core_percent = analysis.cpu_ms_per_second / 10
        lines.append(
            f"**Observed span:** {analysis.profile_span_ms}ms | "
            f"**Average CPU load:** {analysis.cpu_ms_per_second:g} CPU-ms/s "
            f"(~{one_core_percent:.1f}% of one core)"
        )
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
    ]
    if baseline.cpu_ms_per_second is not None and candidate.cpu_ms_per_second is not None:
        load_delta = round(candidate.cpu_ms_per_second - baseline.cpu_ms_per_second, 1)
        lines.extend(
            [
                f"**Baseline average CPU load:** {baseline.cpu_ms_per_second:g} CPU-ms/s",
                f"**Candidate average CPU load:** {candidate.cpu_ms_per_second:g} CPU-ms/s",
                f"**Average CPU load delta:** {format_delta(load_delta, ' CPU-ms/s')}",
            ]
        )
    lines.extend(["", "## Changed Hot Methods"])
    if not changed_methods:
        lines.append("No comparable hot methods found.")
    else:
        for symbol in changed_methods:
            before = baseline_methods.get(symbol, 0)
            after = candidate_methods.get(symbol, 0)
            lines.append(f"- `{symbol}`: {before}ms -> {after}ms ({format_delta(after - before, 'ms')})")
    return "\n".join(lines)

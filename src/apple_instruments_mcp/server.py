from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from apple_instruments_mcp.analysis import (
    XPATH_ALLOCATIONS_STATISTICS,
    XPATH_APP_LAUNCH,
    XPATH_LEAKS_DETAILS,
    XPATH_NETWORK_CONNECTIONS,
    XPATH_TIME_PROFILE,
    RecordingTarget,
    analyze_existing,
    build_record_command,
    compare_allocation_analyses,
    compare_existing,
    compare_launch_analyses,
    compare_time_profile_analyses,
    count_xctrace_listing_items,
    format_allocations,
    format_command,
    format_launch,
    format_leaks,
    format_network,
    format_time_profiler,
    has_allocations_evidence,
    has_launch_evidence,
    has_leaks_evidence,
    has_network_evidence,
    has_time_profiler_evidence,
    list_as_json,
    parse_allocations,
    parse_app_launch,
    parse_leaks,
    parse_network,
    parse_time_profiler,
    probe_xctrace_health,
    run_analysis,
    run_command,
)
from apple_instruments_mcp.analysis import (
    list_devices as xctrace_list_devices,
)
from apple_instruments_mcp.analysis import (
    list_instruments as xctrace_list_instruments,
)
from apple_instruments_mcp.analysis import (
    list_templates as xctrace_list_templates,
)

mcp = FastMCP(
    name="apple-instruments-mcp",
    instructions=(
        "Profile Apple platform apps and processes with Instruments via xctrace: "
        "launch time, allocations, leaks, CPU, and network."
    ),
)

BundleId = Annotated[
    str | None,
    Field(description="App bundle ID for simulator/device launch, e.g. com.mycompany.myapp."),
]
DeviceId = Annotated[
    str | None,
    Field(description="Optional simulator UUID or physical device ID. Omit for host macOS profiling."),
]
LaunchPath = Annotated[
    str | None,
    Field(description="Executable or .app path to launch, useful for macOS apps and command-line tools."),
]
LaunchArgs = Annotated[
    str | None,
    Field(description="Optional shell-style arguments passed after launch_path."),
]
ProcessName = Annotated[
    str | None,
    Field(description="Attach to a running process by name."),
]
Pid = Annotated[
    int | None,
    Field(description="Attach to a running process by PID."),
]
AllProcesses = Annotated[
    bool,
    Field(description="Record all processes instead of launching or attaching to one target."),
]
DryRun = Annotated[
    bool,
    Field(description="Return the xctrace command without recording."),
]
KeepTrace = Annotated[
    bool,
    Field(description="Keep generated trace and XML artifacts and include their paths in the report."),
]
OutputDir = Annotated[
    str | None,
    Field(description="Optional directory for generated artifacts. A run-specific subdirectory is created inside it."),
]
TimeLimitSeconds = Annotated[
    int,
    Field(default=20, ge=5, le=120, description="Recording duration in seconds."),
]
TracePath = Annotated[str, Field(description="Absolute path to the .trace bundle.")]
BaselineTracePath = Annotated[str, Field(description="Absolute path to the baseline .trace bundle.")]
CandidateTracePath = Annotated[str, Field(description="Absolute path to the candidate .trace bundle.")]
ProfileType = Annotated[
    Literal["launch", "allocations", "leaks", "time_profiler", "network"],
    Field(description="Analysis type to run."),
]
LaunchGoodMs = Annotated[float, Field(ge=0, description="Launch time below this value is reported as good.")]
LaunchCriticalMs = Annotated[float, Field(ge=0, description="Launch time at or above this value is reported as critical.")]
OffenderWarningMs = Annotated[float, Field(ge=0, description="Launch offender self-time above this value is a warning.")]
OffenderCriticalMs = Annotated[float, Field(ge=0, description="Launch offender self-time above this value is critical.")]
MemoryWarningMb = Annotated[float, Field(ge=0, description="Peak memory above this value is a warning.")]
MemoryCriticalMb = Annotated[float, Field(ge=0, description="Peak memory above this value is critical.")]
MemoryCacheWarningMb = Annotated[float, Field(ge=0, description="Peak memory above this value suggests cache release recommendations.")]
LeakCriticalCount = Annotated[int, Field(ge=0, description="Leak count above this value is critical.")]
TotalCpuGoodMs = Annotated[float, Field(ge=0, description="Total profiled CPU duration below this value is good.")]
TotalCpuCriticalMs = Annotated[float, Field(ge=0, description="Total profiled CPU duration at or above this value is critical.")]
MethodWarningMs = Annotated[float, Field(ge=0, description="Hot method self-time above this value is a warning.")]
MethodCriticalMs = Annotated[float, Field(ge=0, description="Hot method self-time above this value is critical.")]
RequestWarningMs = Annotated[float, Field(ge=0, description="Request duration above this value is a warning.")]
RequestCriticalMs = Annotated[float, Field(ge=0, description="Request duration above this value is critical.")]
SlowRequestCriticalCount = Annotated[int, Field(ge=0, description="Slow request count above this value is critical.")]
TransferWarningMb = Annotated[float, Field(ge=0, description="Transferred data above this value adds a transfer-size recommendation.")]
ScopeStartMs = Annotated[
    int | None,
    Field(
        default=None,
        description=(
            "Optional inclusive lower bound (ms since trace start) for sample analysis. "
            "Use with `scope_end_ms` to zoom into a specific window (e.g. a jank around second 12)."
        ),
    ),
]
ScopeEndMs = Annotated[
    int | None,
    Field(
        default=None,
        description=(
            "Optional inclusive upper bound (ms since trace start) for sample analysis. "
            "Omit or set to 0 to extend to the end of the trace."
        ),
    ),
]
HangThresholdMs = Annotated[
    int,
    Field(
        ge=1,
        description=(
            "Main-thread inter-sample gap (ms) above which the gap is counted as a candidate stall. "
            "Default 250 mirrors typical hang-instrument settings."
        ),
    ),
]
UserBinaries = Annotated[
    str,
    Field(
        description=(
            "Comma-separated binary names that count as 'user code' for the user-methods view "
            "(e.g. `MyApp,MyAppKit`). Empty disables the user-methods section."
        ),
    ),
]


def make_target(
    *,
    bundle_id: str | None,
    device_id: str | None,
    launch_path: str | None,
    launch_args: str | None,
    process_name: str | None,
    pid: int | None,
    all_processes: bool,
) -> RecordingTarget:
    return RecordingTarget.build(
        bundle_id=bundle_id,
        device_id=device_id,
        launch_path=launch_path,
        launch_args=launch_args,
        process_name=process_name,
        pid=pid,
        all_processes=all_processes,
    )


async def run_profile(
    profile_type: str,
    target: RecordingTarget,
    time_limit_seconds: int,
    *,
    dry_run: bool,
    keep_trace: bool,
    output_dir: str | None,
) -> str:
    if profile_type == "launch":
        return await run_analysis(
            "App Launch",
            target,
            time_limit_seconds,
            lambda xml: parse_app_launch(xml, target.label),
            lambda analysis: format_launch(analysis, target.label),
            "launch",
            has_launch_evidence,
            dry_run=dry_run,
            keep_trace=keep_trace,
            output_dir=output_dir,
            xpath=XPATH_APP_LAUNCH,
        )
    if profile_type == "allocations":
        return await run_analysis(
            "Allocations",
            target,
            time_limit_seconds,
            parse_allocations,
            lambda analysis: format_allocations(analysis, target.label),
            "allocations",
            has_allocations_evidence,
            dry_run=dry_run,
            keep_trace=keep_trace,
            output_dir=output_dir,
            xpath=XPATH_ALLOCATIONS_STATISTICS,
        )
    if profile_type == "leaks":
        return await run_analysis(
            "Leaks",
            target,
            time_limit_seconds,
            parse_leaks,
            lambda analysis: format_leaks(analysis, target.label),
            "leaks",
            has_leaks_evidence,
            dry_run=dry_run,
            keep_trace=keep_trace,
            output_dir=output_dir,
            xpath=XPATH_LEAKS_DETAILS,
        )
    if profile_type == "time_profiler":
        return await run_analysis(
            "Time Profiler",
            target,
            time_limit_seconds,
            parse_time_profiler,
            lambda analysis: format_time_profiler(analysis, target.label),
            "time profiler",
            has_time_profiler_evidence,
            dry_run=dry_run,
            keep_trace=keep_trace,
            output_dir=output_dir,
            xpath=XPATH_TIME_PROFILE,
        )
    if profile_type == "network":
        return await run_analysis(
            "Network",
            target,
            time_limit_seconds,
            parse_network,
            lambda analysis: format_network(analysis, target.label),
            "network",
            has_network_evidence,
            dry_run=dry_run,
            keep_trace=keep_trace,
            output_dir=output_dir,
            xpath=XPATH_NETWORK_CONNECTIONS,
        )
    return f"Unknown profile_type: {profile_type}"


_DOCTOR_PROBE_TIMEOUT_SECONDS = 5.0


async def doctor_report() -> str:
    """Implementation of the doctor MCP tool. Kept as a plain async function
    so unit tests can call it directly without going through the FastMCP
    decorator wrapper."""
    facts: dict[str, str] = {}
    problems: list[str] = []

    try:
        path = await run_command("xcrun", "--find", "xctrace", timeout=_DOCTOR_PROBE_TIMEOUT_SECONDS)
        facts["xctrace_path"] = path.strip()
    except Exception as exc:
        problems.append(f"`xcrun --find xctrace` failed: {exc}")

    try:
        ver_output = await run_command("xcrun", "xctrace", "version", timeout=_DOCTOR_PROBE_TIMEOUT_SECONDS)
        first_line = next((line.strip() for line in ver_output.splitlines() if line.strip()), "")
        if first_line:
            facts["xctrace_version"] = first_line
    except Exception as exc:
        problems.append(f"`xctrace version` failed: {exc}")

    finding = await probe_xctrace_health()
    if finding is not None:
        marker = "blocker" if finding.severity == "blocker" else "warning"
        problems.append(f"[{marker}] {finding.message}")
        problems.extend(f"  - {hint}" for hint in finding.hints)

    if finding is None or finding.severity != "blocker":
        for label, fetch in (
            ("devices", xctrace_list_devices),
            ("templates", xctrace_list_templates),
            ("instruments", xctrace_list_instruments),
        ):
            try:
                output = await fetch()
                facts[label] = str(count_xctrace_listing_items(output))
            except Exception as exc:
                problems.append(f"`xctrace list {label}` failed: {exc}")

    ok = not problems
    header = "# xctrace doctor — " + ("✅ ok" if ok else "🔴 problems")
    lines = [header, ""]
    if facts:
        for key in ("xctrace_version", "xctrace_path", "devices", "templates", "instruments"):
            if key in facts:
                lines.append(f"- **{key}**: {facts[key]}")
    if problems:
        lines.extend(["", "## Problems"])
        lines.extend(f"- {p}" for p in problems)
    return "\n".join(lines)


@mcp.tool()
async def doctor() -> str:
    """One-shot health check: xctrace is responsive, what version, where on
    disk, and how many devices/templates/instruments it can see. Useful as the
    first call before recording so a wedged toolchain surfaces immediately
    instead of being discovered through a failed record.
    """
    return await doctor_report()


@mcp.tool()
async def list_devices() -> str:
    """List devices and runtimes visible to xctrace."""
    try:
        return await xctrace_list_devices()
    except Exception as error:
        return f"Error: {error}"


@mcp.tool()
async def list_devices_structured() -> str:
    """List devices and runtimes visible to xctrace as JSON."""
    try:
        return list_as_json(await xctrace_list_devices())
    except Exception as error:
        return f"Error: {error}"


@mcp.tool()
async def list_templates() -> str:
    """List all Instruments profiling templates installed on this Mac."""
    try:
        return await xctrace_list_templates()
    except Exception as error:
        return f"Error: {error}"


@mcp.tool()
async def list_templates_structured() -> str:
    """List Instruments profiling templates as JSON."""
    try:
        return list_as_json(await xctrace_list_templates())
    except Exception as error:
        return f"Error: {error}"


@mcp.tool()
def build_xctrace_command(
    template: Annotated[str, Field(description="Instruments template name, e.g. 'Time Profiler', 'App Launch'.")],
    bundle_id: BundleId = None,
    device_id: DeviceId = None,
    launch_path: LaunchPath = None,
    launch_args: LaunchArgs = None,
    process_name: ProcessName = None,
    pid: Pid = None,
    all_processes: AllProcesses = False,
    time_limit_seconds: TimeLimitSeconds = 20,
    output_path: Annotated[
        str | None,
        Field(description="Optional absolute path for the .trace output. Defaults to a placeholder."),
    ] = None,
) -> str:
    """Build the exact `xcrun xctrace record ...` command for the given target without executing it."""
    try:
        target = make_target(
            bundle_id=bundle_id,
            device_id=device_id,
            launch_path=launch_path,
            launch_args=launch_args,
            process_name=process_name,
            pid=pid,
            all_processes=all_processes,
        )
    except ValueError as error:
        return f"Invalid target: {error}"

    trace_path = Path(output_path) if output_path else Path("<output-path>") / "trace.trace"
    command = format_command(build_record_command(template, target, time_limit_seconds, trace_path))

    validation_errors = target.validate()
    sections = [
        "# xctrace Command",
        "",
        f"**Template:** {template}",
        f"**Target:** {target.label}",
        f"**Output:** {trace_path}",
        "",
        "```bash",
        command,
        "```",
    ]
    if validation_errors:
        sections.append("")
        sections.append("## Pre-flight warnings")
        sections.extend(f"- {warning}" for warning in validation_errors)
    return "\n".join(sections)


@mcp.tool()
async def profile_ios_app(
    bundle_id: Annotated[str, Field(description="App bundle ID, e.g. com.mycompany.myapp.")],
    device_id: Annotated[str, Field(description="Simulator UUID or physical device ID from list_devices.")],
    profile_type: ProfileType = "launch",
    time_limit_seconds: TimeLimitSeconds = 20,
    dry_run: DryRun = False,
    keep_trace: KeepTrace = False,
    output_dir: OutputDir = None,
) -> str:
    """Profile an iOS, iPadOS, tvOS, watchOS, or visionOS app by bundle ID on a simulator/device."""
    target = RecordingTarget.build(bundle_id=bundle_id, device_id=device_id)
    return await run_profile(
        profile_type,
        target,
        time_limit_seconds,
        dry_run=dry_run,
        keep_trace=keep_trace,
        output_dir=output_dir,
    )


@mcp.tool()
async def profile_mac_app(
    launch_path: Annotated[str, Field(description="macOS .app or executable path to launch.")],
    profile_type: ProfileType = "time_profiler",
    launch_args: LaunchArgs = None,
    time_limit_seconds: TimeLimitSeconds = 20,
    dry_run: DryRun = False,
    keep_trace: KeepTrace = False,
    output_dir: OutputDir = None,
) -> str:
    """Profile a macOS app or executable by launching it."""
    target = RecordingTarget.build(launch_path=launch_path, launch_args=launch_args)
    return await run_profile(
        profile_type,
        target,
        time_limit_seconds,
        dry_run=dry_run,
        keep_trace=keep_trace,
        output_dir=output_dir,
    )


@mcp.tool()
async def profile_process(
    profile_type: ProfileType = "time_profiler",
    process_name: ProcessName = None,
    pid: Pid = None,
    time_limit_seconds: TimeLimitSeconds = 20,
    dry_run: DryRun = False,
    keep_trace: KeepTrace = False,
    output_dir: OutputDir = None,
) -> str:
    """Profile a running process by process name or PID."""
    target = RecordingTarget.build(process_name=process_name, pid=pid)
    return await run_profile(
        profile_type,
        target,
        time_limit_seconds,
        dry_run=dry_run,
        keep_trace=keep_trace,
        output_dir=output_dir,
    )


@mcp.tool()
async def profile_all_processes(
    profile_type: ProfileType = "time_profiler",
    device_id: DeviceId = None,
    time_limit_seconds: TimeLimitSeconds = 20,
    dry_run: DryRun = False,
    keep_trace: KeepTrace = False,
    output_dir: OutputDir = None,
) -> str:
    """Profile all processes on the host or selected device when the template supports it."""
    target = RecordingTarget.build(device_id=device_id, all_processes=True)
    return await run_profile(
        profile_type,
        target,
        time_limit_seconds,
        dry_run=dry_run,
        keep_trace=keep_trace,
        output_dir=output_dir,
    )


@mcp.tool()
async def analyze_launch(
    bundle_id: BundleId = None,
    device_id: DeviceId = None,
    launch_path: LaunchPath = None,
    launch_args: LaunchArgs = None,
    process_name: ProcessName = None,
    pid: Pid = None,
    all_processes: AllProcesses = False,
    time_limit_seconds: TimeLimitSeconds = 20,
    dry_run: DryRun = False,
    keep_trace: KeepTrace = False,
    output_dir: OutputDir = None,
    launch_good_ms: LaunchGoodMs = 400,
    launch_critical_ms: LaunchCriticalMs = 1000,
    offender_warning_ms: OffenderWarningMs = 100,
    offender_critical_ms: OffenderCriticalMs = 300,
) -> str:
    """Record an App Launch trace and report methods that hurt startup time."""
    target = make_target(
        bundle_id=bundle_id,
        device_id=device_id,
        launch_path=launch_path,
        launch_args=launch_args,
        process_name=process_name,
        pid=pid,
        all_processes=all_processes,
    )
    return await run_analysis(
        "App Launch",
        target,
        time_limit_seconds,
        lambda xml: parse_app_launch(
            xml,
            target.label,
            launch_good_ms=launch_good_ms,
            launch_critical_ms=launch_critical_ms,
            offender_warning_ms=offender_warning_ms,
            offender_critical_ms=offender_critical_ms,
        ),
        lambda analysis: format_launch(analysis, target.label),
        "launch",
        has_launch_evidence,
        dry_run=dry_run,
        keep_trace=keep_trace,
        output_dir=output_dir,
        xpath=XPATH_APP_LAUNCH,
    )


@mcp.tool()
async def analyze_launch_trace(
    trace_path: TracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    launch_good_ms: LaunchGoodMs = 400,
    launch_critical_ms: LaunchCriticalMs = 1000,
    offender_warning_ms: OffenderWarningMs = 100,
    offender_critical_ms: OffenderCriticalMs = 300,
) -> str:
    """Analyze an existing .trace bundle recorded with the App Launch template."""
    return await analyze_existing(
        trace_path,
        lambda xml: parse_app_launch(
            xml,
            bundle_id,
            launch_good_ms=launch_good_ms,
            launch_critical_ms=launch_critical_ms,
            offender_warning_ms=offender_warning_ms,
            offender_critical_ms=offender_critical_ms,
        ),
        lambda analysis: format_launch(analysis, bundle_id),
        "launch",
        has_launch_evidence,
        xpath=XPATH_APP_LAUNCH,
    )


@mcp.tool()
async def analyze_allocations(
    bundle_id: BundleId = None,
    device_id: DeviceId = None,
    launch_path: LaunchPath = None,
    launch_args: LaunchArgs = None,
    process_name: ProcessName = None,
    pid: Pid = None,
    all_processes: AllProcesses = False,
    time_limit_seconds: TimeLimitSeconds = 20,
    dry_run: DryRun = False,
    keep_trace: KeepTrace = False,
    output_dir: OutputDir = None,
    memory_warning_mb: MemoryWarningMb = 100,
    memory_critical_mb: MemoryCriticalMb = 200,
    memory_cache_warning_mb: MemoryCacheWarningMb = 150,
) -> str:
    """Record an Allocations trace and report live memory and top allocation categories."""
    target = make_target(
        bundle_id=bundle_id,
        device_id=device_id,
        launch_path=launch_path,
        launch_args=launch_args,
        process_name=process_name,
        pid=pid,
        all_processes=all_processes,
    )
    return await run_analysis(
        "Allocations",
        target,
        time_limit_seconds,
        lambda xml: parse_allocations(
            xml,
            memory_warning_mb=memory_warning_mb,
            memory_critical_mb=memory_critical_mb,
            memory_cache_warning_mb=memory_cache_warning_mb,
        ),
        lambda analysis: format_allocations(analysis, target.label),
        "allocations",
        has_allocations_evidence,
        dry_run=dry_run,
        keep_trace=keep_trace,
        output_dir=output_dir,
        xpath=XPATH_ALLOCATIONS_STATISTICS,
    )


@mcp.tool()
async def analyze_allocations_trace(
    trace_path: TracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    memory_warning_mb: MemoryWarningMb = 100,
    memory_critical_mb: MemoryCriticalMb = 200,
    memory_cache_warning_mb: MemoryCacheWarningMb = 150,
) -> str:
    """Analyze an existing Allocations .trace bundle."""
    return await analyze_existing(
        trace_path,
        lambda xml: parse_allocations(
            xml,
            memory_warning_mb=memory_warning_mb,
            memory_critical_mb=memory_critical_mb,
            memory_cache_warning_mb=memory_cache_warning_mb,
        ),
        lambda analysis: format_allocations(analysis, bundle_id),
        "allocations",
        has_allocations_evidence,
        xpath=XPATH_ALLOCATIONS_STATISTICS,
    )


@mcp.tool()
async def analyze_leaks(
    bundle_id: BundleId = None,
    device_id: DeviceId = None,
    launch_path: LaunchPath = None,
    launch_args: LaunchArgs = None,
    process_name: ProcessName = None,
    pid: Pid = None,
    all_processes: AllProcesses = False,
    time_limit_seconds: TimeLimitSeconds = 20,
    dry_run: DryRun = False,
    keep_trace: KeepTrace = False,
    output_dir: OutputDir = None,
    leak_critical_count: LeakCriticalCount = 10,
) -> str:
    """Record a Leaks trace and report leaks with retain cycle hints when xctrace exports leak details."""
    target = make_target(
        bundle_id=bundle_id,
        device_id=device_id,
        launch_path=launch_path,
        launch_args=launch_args,
        process_name=process_name,
        pid=pid,
        all_processes=all_processes,
    )
    return await run_analysis(
        "Leaks",
        target,
        time_limit_seconds,
        lambda xml: parse_leaks(xml, leak_critical_count=leak_critical_count),
        lambda analysis: format_leaks(analysis, target.label),
        "leaks",
        has_leaks_evidence,
        dry_run=dry_run,
        keep_trace=keep_trace,
        output_dir=output_dir,
        xpath=XPATH_LEAKS_DETAILS,
    )


@mcp.tool()
async def analyze_leaks_trace(
    trace_path: TracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    leak_critical_count: LeakCriticalCount = 10,
) -> str:
    """Analyze an existing Leaks .trace bundle."""
    return await analyze_existing(
        trace_path,
        lambda xml: parse_leaks(xml, leak_critical_count=leak_critical_count),
        lambda analysis: format_leaks(analysis, bundle_id),
        "leaks",
        has_leaks_evidence,
        xpath=XPATH_LEAKS_DETAILS,
    )


def _split_user_binaries(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@mcp.tool()
async def analyze_time_profiler(
    bundle_id: BundleId = None,
    device_id: DeviceId = None,
    launch_path: LaunchPath = None,
    launch_args: LaunchArgs = None,
    process_name: ProcessName = None,
    pid: Pid = None,
    all_processes: AllProcesses = False,
    time_limit_seconds: TimeLimitSeconds = 20,
    dry_run: DryRun = False,
    keep_trace: KeepTrace = False,
    output_dir: OutputDir = None,
    total_good_ms: TotalCpuGoodMs = 16,
    total_critical_ms: TotalCpuCriticalMs = 100,
    method_warning_ms: MethodWarningMs = 50,
    method_critical_ms: MethodCriticalMs = 200,
    scope_start_ms: ScopeStartMs = None,
    scope_end_ms: ScopeEndMs = None,
    hang_threshold_ms: HangThresholdMs = 250,
    user_binaries: UserBinaries = "",
) -> str:
    """Record a Time Profiler trace and report CPU hot methods."""
    target = make_target(
        bundle_id=bundle_id,
        device_id=device_id,
        launch_path=launch_path,
        launch_args=launch_args,
        process_name=process_name,
        pid=pid,
        all_processes=all_processes,
    )
    binaries = _split_user_binaries(user_binaries)
    return await run_analysis(
        "Time Profiler",
        target,
        time_limit_seconds,
        lambda xml: parse_time_profiler(
            xml,
            total_good_ms=total_good_ms,
            total_critical_ms=total_critical_ms,
            method_warning_ms=method_warning_ms,
            method_critical_ms=method_critical_ms,
            start_ms=scope_start_ms,
            end_ms=scope_end_ms,
            hang_threshold_ms=hang_threshold_ms,
            user_binaries=binaries,
        ),
        lambda analysis: format_time_profiler(analysis, target.label),
        "time profiler",
        has_time_profiler_evidence,
        dry_run=dry_run,
        keep_trace=keep_trace,
        output_dir=output_dir,
        xpath=XPATH_TIME_PROFILE,
    )


@mcp.tool()
async def analyze_time_profiler_trace(
    trace_path: TracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    total_good_ms: TotalCpuGoodMs = 16,
    total_critical_ms: TotalCpuCriticalMs = 100,
    method_warning_ms: MethodWarningMs = 50,
    method_critical_ms: MethodCriticalMs = 200,
    scope_start_ms: ScopeStartMs = None,
    scope_end_ms: ScopeEndMs = None,
    hang_threshold_ms: HangThresholdMs = 250,
    user_binaries: UserBinaries = "",
) -> str:
    """Analyze an existing .trace bundle recorded with the Time Profiler template."""
    binaries = _split_user_binaries(user_binaries)
    return await analyze_existing(
        trace_path,
        lambda xml: parse_time_profiler(
            xml,
            total_good_ms=total_good_ms,
            total_critical_ms=total_critical_ms,
            method_warning_ms=method_warning_ms,
            method_critical_ms=method_critical_ms,
            start_ms=scope_start_ms,
            end_ms=scope_end_ms,
            hang_threshold_ms=hang_threshold_ms,
            user_binaries=binaries,
        ),
        lambda analysis: format_time_profiler(analysis, bundle_id),
        "time profiler",
        has_time_profiler_evidence,
        xpath=XPATH_TIME_PROFILE,
    )


@mcp.tool()
async def analyze_network(
    bundle_id: BundleId = None,
    device_id: DeviceId = None,
    launch_path: LaunchPath = None,
    launch_args: LaunchArgs = None,
    process_name: ProcessName = None,
    pid: Pid = None,
    all_processes: AllProcesses = False,
    time_limit_seconds: TimeLimitSeconds = 20,
    dry_run: DryRun = False,
    keep_trace: KeepTrace = False,
    output_dir: OutputDir = None,
    request_warning_ms: RequestWarningMs = 500,
    request_critical_ms: RequestCriticalMs = 2000,
    slow_request_critical_count: SlowRequestCriticalCount = 5,
    transfer_warning_mb: TransferWarningMb = 5,
) -> str:
    """Record a Network trace and report slow requests and transfer sizes."""
    target = make_target(
        bundle_id=bundle_id,
        device_id=device_id,
        launch_path=launch_path,
        launch_args=launch_args,
        process_name=process_name,
        pid=pid,
        all_processes=all_processes,
    )
    return await run_analysis(
        "Network",
        target,
        time_limit_seconds,
        lambda xml: parse_network(
            xml,
            request_warning_ms=request_warning_ms,
            request_critical_ms=request_critical_ms,
            slow_request_critical_count=slow_request_critical_count,
            transfer_warning_mb=transfer_warning_mb,
        ),
        lambda analysis: format_network(analysis, target.label),
        "network",
        has_network_evidence,
        dry_run=dry_run,
        keep_trace=keep_trace,
        output_dir=output_dir,
    )


@mcp.tool()
async def analyze_network_trace(
    trace_path: TracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    request_warning_ms: RequestWarningMs = 500,
    request_critical_ms: RequestCriticalMs = 2000,
    slow_request_critical_count: SlowRequestCriticalCount = 5,
    transfer_warning_mb: TransferWarningMb = 5,
) -> str:
    """Analyze an existing .trace bundle recorded with the Network template."""
    return await analyze_existing(
        trace_path,
        lambda xml: parse_network(
            xml,
            request_warning_ms=request_warning_ms,
            request_critical_ms=request_critical_ms,
            slow_request_critical_count=slow_request_critical_count,
            transfer_warning_mb=transfer_warning_mb,
        ),
        lambda analysis: format_network(analysis, bundle_id),
        "network",
        has_network_evidence,
        xpath=XPATH_NETWORK_CONNECTIONS,
    )


@mcp.tool()
async def compare_launch_traces(
    baseline_trace_path: BaselineTracePath,
    candidate_trace_path: CandidateTracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    launch_good_ms: LaunchGoodMs = 400,
    launch_critical_ms: LaunchCriticalMs = 1000,
    offender_warning_ms: OffenderWarningMs = 100,
    offender_critical_ms: OffenderCriticalMs = 300,
) -> str:
    """Compare two App Launch .trace bundles and report launch-time deltas."""
    return await compare_existing(
        baseline_trace_path,
        candidate_trace_path,
        lambda xml: parse_app_launch(
            xml,
            bundle_id,
            launch_good_ms=launch_good_ms,
            launch_critical_ms=launch_critical_ms,
            offender_warning_ms=offender_warning_ms,
            offender_critical_ms=offender_critical_ms,
        ),
        lambda baseline, candidate: compare_launch_analyses(baseline, candidate, bundle_id),
        "launch",
        has_launch_evidence,
        xpath=XPATH_APP_LAUNCH,
    )


@mcp.tool()
async def compare_memory_traces(
    baseline_trace_path: BaselineTracePath,
    candidate_trace_path: CandidateTracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    memory_warning_mb: MemoryWarningMb = 100,
    memory_critical_mb: MemoryCriticalMb = 200,
    memory_cache_warning_mb: MemoryCacheWarningMb = 150,
) -> str:
    """Compare two Allocations .trace bundles and report memory deltas."""
    return await compare_existing(
        baseline_trace_path,
        candidate_trace_path,
        lambda xml: parse_allocations(
            xml,
            memory_warning_mb=memory_warning_mb,
            memory_critical_mb=memory_critical_mb,
            memory_cache_warning_mb=memory_cache_warning_mb,
        ),
        lambda baseline, candidate: compare_allocation_analyses(baseline, candidate, bundle_id),
        "allocations",
        has_allocations_evidence,
        xpath=XPATH_ALLOCATIONS_STATISTICS,
    )


@mcp.tool()
async def compare_cpu_traces(
    baseline_trace_path: BaselineTracePath,
    candidate_trace_path: CandidateTracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    total_good_ms: TotalCpuGoodMs = 16,
    total_critical_ms: TotalCpuCriticalMs = 100,
    method_warning_ms: MethodWarningMs = 50,
    method_critical_ms: MethodCriticalMs = 200,
) -> str:
    """Compare two Time Profiler .trace bundles and report CPU hot-method deltas."""
    return await compare_existing(
        baseline_trace_path,
        candidate_trace_path,
        lambda xml: parse_time_profiler(
            xml,
            total_good_ms=total_good_ms,
            total_critical_ms=total_critical_ms,
            method_warning_ms=method_warning_ms,
            method_critical_ms=method_critical_ms,
        ),
        lambda baseline, candidate: compare_time_profile_analyses(baseline, candidate, bundle_id),
        "time profiler",
        has_time_profiler_evidence,
        xpath=XPATH_TIME_PROFILE,
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()

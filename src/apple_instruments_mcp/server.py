from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from apple_instruments_mcp.analysis import (
    RecordingTarget,
    analyze_existing,
    build_record_command,
    compare_allocation_analyses,
    compare_existing,
    compare_launch_analyses,
    compare_time_profile_analyses,
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
    run_analysis,
)
from apple_instruments_mcp.analysis import (
    list_devices as xctrace_list_devices,
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
TracePath = Annotated[str, Field(description="Absolute path to the .xctrace file.")]
BaselineTracePath = Annotated[str, Field(description="Absolute path to the baseline .xctrace file.")]
CandidateTracePath = Annotated[str, Field(description="Absolute path to the candidate .xctrace file.")]
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
        )
    return f"Unknown profile_type: {profile_type}"


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
        Field(description="Optional absolute path for the .xctrace output. Defaults to a placeholder."),
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

    trace_path = Path(output_path) if output_path else Path("<output-path>") / "trace.xctrace"
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
    """Analyze an existing .xctrace file recorded with the App Launch template."""
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
    """Record an Allocations trace and report peak memory and top allocation types."""
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
    )


@mcp.tool()
async def analyze_allocations_trace(
    trace_path: TracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    memory_warning_mb: MemoryWarningMb = 100,
    memory_critical_mb: MemoryCriticalMb = 200,
    memory_cache_warning_mb: MemoryCacheWarningMb = 150,
) -> str:
    """Analyze an existing .xctrace file recorded with the Allocations template."""
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
    """Record a Leaks trace and report leaks with retain cycle hints."""
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
    )


@mcp.tool()
async def analyze_leaks_trace(
    trace_path: TracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    leak_critical_count: LeakCriticalCount = 10,
) -> str:
    """Analyze an existing .xctrace file recorded with the Leaks template."""
    return await analyze_existing(
        trace_path,
        lambda xml: parse_leaks(xml, leak_critical_count=leak_critical_count),
        lambda analysis: format_leaks(analysis, bundle_id),
        "leaks",
        has_leaks_evidence,
    )


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
        ),
        lambda analysis: format_time_profiler(analysis, target.label),
        "time profiler",
        has_time_profiler_evidence,
        dry_run=dry_run,
        keep_trace=keep_trace,
        output_dir=output_dir,
    )


@mcp.tool()
async def analyze_time_profiler_trace(
    trace_path: TracePath,
    bundle_id: Annotated[str, Field(description="Target name used in the report.")] = "unknown target",
    total_good_ms: TotalCpuGoodMs = 16,
    total_critical_ms: TotalCpuCriticalMs = 100,
    method_warning_ms: MethodWarningMs = 50,
    method_critical_ms: MethodCriticalMs = 200,
) -> str:
    """Analyze an existing .xctrace file recorded with the Time Profiler template."""
    return await analyze_existing(
        trace_path,
        lambda xml: parse_time_profiler(
            xml,
            total_good_ms=total_good_ms,
            total_critical_ms=total_critical_ms,
            method_warning_ms=method_warning_ms,
            method_critical_ms=method_critical_ms,
        ),
        lambda analysis: format_time_profiler(analysis, bundle_id),
        "time profiler",
        has_time_profiler_evidence,
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
    """Analyze an existing .xctrace file recorded with the Network template."""
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
    """Compare two App Launch .xctrace files and report launch-time deltas."""
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
    """Compare two Allocations .xctrace files and report memory deltas."""
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
    """Compare two Time Profiler .xctrace files and report CPU hot-method deltas."""
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
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()

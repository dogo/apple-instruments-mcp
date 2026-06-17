"""Public API for the analysis package.

The implementation is split by context (one module per analyzer plus shared infra:
models, targets, severity, xctrace, xml_helpers, quality, orchestrator). This
package's __init__ re-exports the stable surface so external callers can keep
importing from `apple_instruments_mcp.analysis` directly.
"""

from __future__ import annotations

from apple_instruments_mcp.analysis.allocations import (
    XPATH_ALLOCATIONS_STATISTICS,
    compare_allocation_analyses,
    format_allocations,
    has_allocations_evidence,
    parse_allocations,
)
from apple_instruments_mcp.analysis.launch import (
    XPATH_APP_LAUNCH,
    compare_launch_analyses,
    format_launch,
    has_launch_evidence,
    parse_app_launch,
)
from apple_instruments_mcp.analysis.leaks import (
    XPATH_LEAKS_DETAILS,
    format_leaks,
    has_leaks_evidence,
    parse_leaks,
)
from apple_instruments_mcp.analysis.models import (
    AllocationAnalysis,
    AllocationCategory,
    AnalysisQuality,
    CallTreeFrame,
    HotMethod,
    LaunchAnalysis,
    LaunchOffender,
    LaunchPhase,
    LaunchPhaseName,
    LeakEntry,
    LeaksAnalysis,
    NetworkAnalysis,
    NetworkRequest,
    Severity,
    Status,
    TimeProfileAnalysis,
)
from apple_instruments_mcp.analysis.network import (
    XPATH_NETWORK_CONNECTIONS,
    format_network,
    has_network_evidence,
    parse_network,
)
from apple_instruments_mcp.analysis.orchestrator import (
    analyze_existing,
    compare_existing,
    run_analysis,
    run_preset_analysis,
    unsupported_template_report,
)
from apple_instruments_mcp.analysis.presets import (
    PRESETS,
    preset_families,
    preset_instruments,
    preset_names,
)
from apple_instruments_mcp.analysis.quality import assess_xml_quality, format_quality
from apple_instruments_mcp.analysis.severity import (
    format_delta,
    get_allocation_suggestion,
    get_hot_method_suggestion,
    get_launch_suggestion,
    get_leak_suggestion,
    get_memory_severity,
    get_severity,
    get_status,
)
from apple_instruments_mcp.analysis.targets import RecordingTarget, format_target_error
from apple_instruments_mcp.analysis.time_profile import (
    XPATH_TIME_PROFILE,
    compare_time_profile_analyses,
    format_time_profiler,
    has_time_profiler_evidence,
    parse_time_profiler,
)
from apple_instruments_mcp.analysis.xctrace import (
    build_record_command,
    count_xctrace_listing_items,
    export_xml,
    format_command,
    list_as_json,
    list_devices,
    list_instruments,
    list_templates,
    parse_xctrace_listing,
    probe_xctrace_health,
    record_trace,
    run_command,
)
from apple_instruments_mcp.analysis.xml_helpers import parse_time_profile_xml

__all__ = [
    "XPATH_APP_LAUNCH",
    "XPATH_ALLOCATIONS_STATISTICS",
    "XPATH_LEAKS_DETAILS",
    "XPATH_NETWORK_CONNECTIONS",
    "XPATH_TIME_PROFILE",
    "AllocationAnalysis",
    "AllocationCategory",
    "AnalysisQuality",
    "CallTreeFrame",
    "HotMethod",
    "LaunchAnalysis",
    "LaunchOffender",
    "LaunchPhase",
    "LaunchPhaseName",
    "LeakEntry",
    "LeaksAnalysis",
    "NetworkAnalysis",
    "NetworkRequest",
    "RecordingTarget",
    "Severity",
    "Status",
    "TimeProfileAnalysis",
    "analyze_existing",
    "assess_xml_quality",
    "build_record_command",
    "compare_allocation_analyses",
    "compare_existing",
    "compare_launch_analyses",
    "compare_time_profile_analyses",
    "count_xctrace_listing_items",
    "export_xml",
    "format_allocations",
    "format_command",
    "format_delta",
    "format_launch",
    "format_leaks",
    "format_network",
    "format_quality",
    "format_target_error",
    "format_time_profiler",
    "get_allocation_suggestion",
    "get_hot_method_suggestion",
    "get_launch_suggestion",
    "get_leak_suggestion",
    "get_memory_severity",
    "get_severity",
    "get_status",
    "has_allocations_evidence",
    "has_launch_evidence",
    "has_leaks_evidence",
    "has_network_evidence",
    "has_time_profiler_evidence",
    "list_as_json",
    "list_devices",
    "list_instruments",
    "list_templates",
    "parse_allocations",
    "parse_app_launch",
    "parse_leaks",
    "parse_network",
    "parse_time_profile_xml",
    "parse_time_profiler",
    "parse_xctrace_listing",
    "probe_xctrace_health",
    "record_trace",
    "PRESETS",
    "preset_families",
    "preset_instruments",
    "preset_names",
    "run_analysis",
    "run_preset_analysis",
    "run_command",
    "unsupported_template_report",
]

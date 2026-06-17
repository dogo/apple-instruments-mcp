from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["critical", "warning", "ok"]
Status = Literal["good", "warning", "critical"]
LaunchPhaseName = Literal["pre-main", "post-main", "unknown"]


@dataclass(frozen=True)
class CallTreeFrame:
    symbol: str
    self_ms: float
    total_ms: float
    binary: str = ""


@dataclass(frozen=True)
class SampleFrame:
    """One frame inside a Time Profiler sample.

    `addr`, `binary_uuid`, `binary_load_addr`, `arch` are populated when the
    xctrace export carried them and are used by `symbolicate` to attempt
    name resolution against a dSYM. Empty strings mean "not available" and
    cause the symbolicator to leave the frame as-is.
    """

    symbol: str
    binary: str = ""
    addr: str = ""
    binary_uuid: str = ""
    binary_load_addr: str = ""
    arch: str = ""


@dataclass(frozen=True)
class TimeProfileSample:
    """A single Time Profiler row, leaf-first frames. `time_ns` is the offset
    from the start of the run; 0 when xctrace's export didn't carry start-time
    (older fixtures, some templates)."""

    weight_ns: int
    frames: tuple[SampleFrame, ...]
    time_ns: int = 0
    thread_name: str = ""
    is_main_thread: bool = False


@dataclass(frozen=True)
class LaunchOffender:
    symbol: str
    self_time_ms: int
    total_time_ms: int
    percent: int
    phase: LaunchPhaseName
    severity: Severity
    suggestion: str | None = None


@dataclass(frozen=True)
class LaunchPhase:
    name: str
    duration_ms: int
    percent: int


@dataclass(frozen=True)
class LaunchAnalysis:
    total_launch_ms: int
    status: Status
    phases: list[LaunchPhase]
    offenders: list[LaunchOffender]
    summary: str
    recommendations: list[str]


@dataclass(frozen=True)
class AllocationCategory:
    type: str
    live_bytes: int
    live_count: int
    total_bytes: int
    total_count: int
    severity: Severity
    suggestion: str | None = None


@dataclass(frozen=True)
class AllocationAnalysis:
    peak_memory_mb: float
    live_memory_mb: float
    status: Status
    top_allocations: list[AllocationCategory]
    summary: str
    recommendations: list[str]


@dataclass(frozen=True)
class LeakEntry:
    type: str
    count: int
    total_bytes: int
    root_cycle: bool
    suggestion: str | None = None


@dataclass(frozen=True)
class LeaksAnalysis:
    total_leaks: int
    total_leaked_bytes: int
    status: Status
    leaks: list[LeakEntry]
    summary: str
    recommendations: list[str]


@dataclass(frozen=True)
class HotMethod:
    symbol: str
    self_time_ms: int
    total_time_ms: int
    percent: int
    severity: Severity
    suggestion: str | None = None
    binary: str = ""
    is_user: bool = False


@dataclass(frozen=True)
class MainThreadStats:
    """Approximate stall signal derived from Time Profiler samples. The
    profiler only samples *running* threads, so a long gap between consecutive
    main-thread samples is a candidate stall, not a confirmed hang."""

    samples: int
    weight_ms: int
    weight_pct: float
    max_gap_ms: int
    gap_threshold_ms: int
    candidate_stalls: int


@dataclass(frozen=True)
class ScopeInfo:
    """Window applied via --start-ms / --end-ms when the LLM zooms into one
    moment of the trace instead of analyzing the whole recording."""

    start_ms: int
    end_ms: int
    samples_in_scope: int


@dataclass(frozen=True)
class TimeProfileAnalysis:
    total_duration_ms: int
    status: Status
    hot_methods: list[HotMethod]
    summary: str
    recommendations: list[str]
    user_methods: list[HotMethod] = field(default_factory=list)
    main_thread: MainThreadStats | None = None
    scope: ScopeInfo | None = None


@dataclass(frozen=True)
class NetworkRequest:
    url: str
    method: str
    duration_ms: int
    bytes: int
    status_code: int
    severity: Severity


@dataclass(frozen=True)
class NetworkAnalysis:
    total_requests: int
    total_transferred_mb: float
    status: Status
    slow_requests: list[NetworkRequest]
    summary: str
    recommendations: list[str]


@dataclass(frozen=True)
class AnalysisQuality:
    confidence: Literal["high", "low"]
    warnings: list[str]

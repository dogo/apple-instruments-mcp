from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["critical", "warning", "ok"]
Status = Literal["good", "warning", "critical"]
LaunchPhaseName = Literal["pre-main", "post-main", "unknown"]


@dataclass(frozen=True)
class CallTreeFrame:
    symbol: str
    self_ms: float
    total_ms: float


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


@dataclass(frozen=True)
class TimeProfileAnalysis:
    total_duration_ms: int
    status: Status
    hot_methods: list[HotMethod]
    summary: str
    recommendations: list[str]


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

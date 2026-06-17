"""Recording presets that map to one or more xctrace instruments.

A preset is a name (e.g. `cpu`, `memory`, `full`) that the LLM can pick when it
wants one recording to cover multiple analysis families. The recording uses
`xctrace record --instrument <name>` repeated per family, and the orchestrator
then exports each family's XPath and runs its parser/formatter.

Naming follows xcprof's verified-on-Xcode-26 instrument list, except we use
`Time Profiler` (matching our existing `time-profile` parser) instead of xcprof's
`CPU Profiler` — confirmed empirically that the simulator-wedge case isn't
instrument-specific, so the parser-reuse wins.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from apple_instruments_mcp.analysis.allocations import (
    XPATH_ALLOCATIONS_STATISTICS,
    format_allocations,
    has_allocations_evidence,
    parse_allocations,
)
from apple_instruments_mcp.analysis.leaks import (
    XPATH_LEAKS_DETAILS,
    format_leaks,
    has_leaks_evidence,
    parse_leaks,
)
from apple_instruments_mcp.analysis.network import (
    XPATH_NETWORK_CONNECTIONS,
    format_network,
    has_network_evidence,
    parse_network,
)
from apple_instruments_mcp.analysis.time_profile import (
    XPATH_TIME_PROFILE,
    format_time_profiler,
    has_time_profiler_evidence,
    parse_time_profiler,
)


@dataclass(frozen=True)
class Family:
    """One analysis family within a preset.

    `instrument_name` is what we pass to `xctrace --instrument`. `xpath` /
    `evidence_checker` / `parser` / `formatter` mirror the per-template
    `run_analysis` chain — the multi-family orchestrator runs each family the
    same way the single-template tools do today.
    """

    key: str
    instrument_name: str
    parser_name: str
    xpath: str
    evidence_checker: Callable[[str], bool]
    parser: Callable[[str], object]
    formatter: Callable[[object, str], str]
    section_title: str


FAMILY_CPU = Family(
    key="cpu",
    instrument_name="Time Profiler",
    parser_name="time profiler",
    xpath=XPATH_TIME_PROFILE,
    evidence_checker=has_time_profiler_evidence,
    parser=lambda xml: parse_time_profiler(xml),
    formatter=lambda analysis, label: format_time_profiler(analysis, label),  # type: ignore[arg-type]
    section_title="CPU (Time Profiler)",
)

FAMILY_ALLOCATIONS = Family(
    key="allocations",
    instrument_name="Allocations",
    parser_name="allocations",
    xpath=XPATH_ALLOCATIONS_STATISTICS,
    evidence_checker=has_allocations_evidence,
    parser=lambda xml: parse_allocations(xml),
    formatter=lambda analysis, label: format_allocations(analysis, label),  # type: ignore[arg-type]
    section_title="Allocations",
)

FAMILY_LEAKS = Family(
    key="leaks",
    instrument_name="Leaks",
    parser_name="leaks",
    xpath=XPATH_LEAKS_DETAILS,
    evidence_checker=has_leaks_evidence,
    parser=lambda xml: parse_leaks(xml),
    formatter=lambda analysis, label: format_leaks(analysis, label),  # type: ignore[arg-type]
    section_title="Leaks",
)

FAMILY_NETWORK = Family(
    key="network",
    instrument_name="Network Connections",
    parser_name="network",
    xpath=XPATH_NETWORK_CONNECTIONS,
    evidence_checker=has_network_evidence,
    parser=lambda xml: parse_network(xml),
    formatter=lambda analysis, label: format_network(analysis, label),  # type: ignore[arg-type]
    section_title="Network",
)

_FAMILIES_BY_KEY: dict[str, Family] = {
    f.key: f
    for f in (FAMILY_CPU, FAMILY_ALLOCATIONS, FAMILY_LEAKS, FAMILY_NETWORK)
}

# Preset name → ordered list of family keys it captures. Order is the order
# the sections appear in the multi-family report.
PRESETS: dict[str, tuple[str, ...]] = {
    "cpu": ("cpu",),
    "memory": ("allocations", "leaks"),
    "network": ("network",),
    "full": ("cpu", "allocations", "leaks", "network"),
}


def preset_families(preset: str) -> list[Family]:
    """Return the family records belonging to a preset, in display order.

    Raises ValueError when the preset name isn't registered.
    """
    try:
        keys = PRESETS[preset]
    except KeyError:
        valid = ", ".join(sorted(PRESETS))
        raise ValueError(f"unknown preset '{preset}' (valid: {valid})") from None
    return [_FAMILIES_BY_KEY[k] for k in keys]


def preset_instruments(preset: str) -> list[str]:
    """Return the `--instrument` names needed to record this preset.

    De-duplicates while preserving first-seen order so two families sharing
    an instrument don't repeat it on the xctrace command line.
    """
    seen: set[str] = set()
    instruments: list[str] = []
    for family in preset_families(preset):
        if family.instrument_name in seen:
            continue
        seen.add(family.instrument_name)
        instruments.append(family.instrument_name)
    return instruments


def preset_names() -> list[str]:
    """Stable display order of the registered presets."""
    return ["cpu", "memory", "network", "full"]

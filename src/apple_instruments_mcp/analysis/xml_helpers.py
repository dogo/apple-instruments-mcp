from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict

from apple_instruments_mcp.analysis.models import CallTreeFrame

_NS_PER_MS = 1_000_000

# Leaf symbols where the thread is parked in a kernel wait. Instruments hides these
# in the Time Profiler view by default ("Hide System Libraries"). Counting them as
# CPU work would massively inflate totals on traces that keep recording after the
# app is idle (workers parked in mach_msg2_trap / semaphore_wait dominate the sample
# stream). When a row's leaf is one of these, we drop the whole sample.
_IDLE_LEAF_SYMBOLS = frozenset(
    {
        "mach_msg2_trap",
        "mach_msg_trap",
        "mach_msg_overwrite_trap",
        "start_wqthread",
        "_pthread_wqthread",
        "semaphore_wait_trap",
        "semaphore_timedwait_trap",
        "__ulock_wait",
        "__psynch_cvwait",
        "__psynch_mutexwait",
        "kevent",
        "kevent_id",
        "kevent_qos",
        "__select",
        "__pselect",
        "poll",
        "ppoll",
        "_pthread_cond_wait",
    }
)


def _build_id_map(root: ET.Element) -> dict[str, ET.Element]:
    return {elem.get("id"): elem for elem in root.iter() if elem.get("id")}  # type: ignore[misc]


def _resolve(elem: ET.Element, id_map: dict[str, ET.Element]) -> ET.Element:
    ref = elem.get("ref")
    if ref is not None:
        return id_map.get(ref, elem)
    return elem


def parse_time_profile_xml(xml_content: str) -> tuple[list[CallTreeFrame], float]:
    """Parse xctrace --xpath '...time-profile' output into call-tree frames.

    Each &lt;row&gt; is a sample with a &lt;weight&gt; (nanoseconds) and a &lt;tagged-backtrace&gt;.
    The first &lt;frame&gt; in each backtrace is the leaf (innermost call), which receives
    the self-time; every distinct frame in the sample receives the same weight as
    total-time. Elements use id/ref deduplication so we resolve refs against an id map
    built from the whole document.
    """
    if not xml_content.strip():
        return [], 0.0
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return [], 0.0

    id_map = _build_id_map(root)

    self_ns: dict[str, int] = defaultdict(int)
    total_ns: dict[str, int] = defaultdict(int)
    total_duration_ns = 0

    for row in root.iter("row"):
        weight_elem = row.find("weight")
        backtrace_elem = row.find("tagged-backtrace")
        if weight_elem is None or backtrace_elem is None:
            continue

        # Only count samples where the thread was actually running on a CPU. Instruments
        # records Blocked and Runnable samples too, but those represent wait/idle time
        # and would heavily inflate totals on traces that include worker threads parked
        # in mach_msg2_trap or semaphore_wait.
        state_elem = row.find("thread-state")
        if state_elem is not None:
            state_resolved = _resolve(state_elem, id_map)
            state_text = (state_resolved.text or "").strip()
            if state_text and state_text != "Running":
                continue

        weight_resolved = _resolve(weight_elem, id_map)
        try:
            weight = int((weight_resolved.text or "0").strip())
        except (AttributeError, ValueError):
            continue
        if weight <= 0:
            continue

        tagged_resolved = _resolve(backtrace_elem, id_map)
        backtrace_inner = tagged_resolved.find("backtrace")
        if backtrace_inner is None:
            continue
        backtrace_inner = _resolve(backtrace_inner, id_map)

        sample_frames: list[str] = []
        for frame_elem in backtrace_inner.findall("frame"):
            frame_resolved = _resolve(frame_elem, id_map)
            name = frame_resolved.get("name")
            if not name or name == "<deduplicated_symbol>":
                continue
            sample_frames.append(name)

        if not sample_frames:
            continue

        if sample_frames[0] in _IDLE_LEAF_SYMBOLS:
            continue

        total_duration_ns += weight
        self_ns[sample_frames[0]] += weight

        seen: set[str] = set()
        for name in sample_frames:
            if name in seen:
                continue
            seen.add(name)
            total_ns[name] += weight

    symbols = set(total_ns) | set(self_ns)
    frames = [
        CallTreeFrame(
            symbol=symbol,
            self_ms=self_ns.get(symbol, 0) / _NS_PER_MS,
            total_ms=total_ns.get(symbol, 0) / _NS_PER_MS,
        )
        for symbol in symbols
    ]
    return frames, total_duration_ns / _NS_PER_MS

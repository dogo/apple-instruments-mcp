from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from apple_instruments_mcp.analysis.models import (
    AllocationAnalysis,
    AllocationCategory,
    Status,
)
from apple_instruments_mcp.analysis.severity import (
    format_delta,
    get_allocation_suggestion,
    get_memory_severity,
)


XPATH_ALLOCATIONS_STATISTICS = (
    '/trace-toc/run[@number="1"]/tracks/track[@name="Allocations"]/details/detail[@name="Statistics"]'
)


def has_allocations_evidence(xml_content: str) -> bool:
    return bool(
        re.search(r"<(live-bytes|total-bytes|peak[^>]*)", xml_content, re.IGNORECASE)
        or re.search(r'<row[^>]+(?:persistent-bytes|total-bytes|category)=', xml_content)
    )


def parse_allocations(
    xml_content: str,
    *,
    memory_warning_mb: float = 100,
    memory_critical_mb: float = 200,
    memory_cache_warning_mb: float = 150,
) -> AllocationAnalysis:
    categories: list[AllocationCategory] = []
    peak_mb = 0.0
    live_mb = 0.0

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        root = None

    if root is not None:
        total_categories = {
            "All Heap & Anonymous VM",
            "All Heap Allocations",
            "All Anonymous VM",
            "All VM Regions",
            "destroyed event",
        }
        heap_total: int | None = None
        heap_and_vm_total: int | None = None
        vm_total: int | None = None
        for row in root.iter("row"):
            type_name = row.attrib.get("category")
            if not type_name:
                continue
            live_bytes = int(row.attrib.get("persistent-bytes", "0") or 0)
            live_count = int(row.attrib.get("count-persistent", "0") or 0)
            total_bytes = int(row.attrib.get("total-bytes", "0") or 0)
            total_count = int(row.attrib.get("count-total", "0") or 0)

            if type_name == "All Heap Allocations":
                heap_total = live_bytes
            elif type_name == "All Heap & Anonymous VM":
                heap_and_vm_total = live_bytes
            elif type_name == "All VM Regions":
                vm_total = live_bytes

            if type_name in total_categories or total_bytes < 1024:
                continue
            categories.append(
                AllocationCategory(
                    type=type_name,
                    live_bytes=live_bytes,
                    live_count=live_count,
                    total_bytes=total_bytes,
                    total_count=total_count,
                    severity=get_memory_severity(live_bytes / 1_048_576, memory_warning_mb, memory_critical_mb),
                    suggestion=get_allocation_suggestion(type_name),
                )
            )

        if heap_total is not None:
            live_mb = heap_total / 1_048_576
        elif heap_and_vm_total is not None:
            live_mb = heap_and_vm_total / 1_048_576
        else:
            live_mb = sum(category.live_bytes for category in categories) / 1_048_576

        peak_source = (
            vm_total
            if vm_total is not None
            else heap_and_vm_total
            if heap_and_vm_total is not None
            else heap_total
        )
        if peak_source is not None:
            peak_mb = peak_source / 1_048_576

    for match in re.finditer(r"<row>([\s\S]*?)</row>", xml_content):
        row = match.group(1)
        type_match = re.search(r"<type[^>]*>([^<]+)</type>", row)
        type_name = type_match.group(1).strip() if type_match else "Unknown"
        live_bytes = int((re.search(r"<live-bytes[^>]*>(\d+)</live-bytes>", row) or ["", "0"])[1])
        live_count = int((re.search(r"<live-count[^>]*>(\d+)</live-count>", row) or ["", "0"])[1])
        total_bytes = int((re.search(r"<total-bytes[^>]*>(\d+)</total-bytes>", row) or ["", "0"])[1])
        total_count = int((re.search(r"<total-count[^>]*>(\d+)</total-count>", row) or ["", "0"])[1])

        if total_bytes < 1024:
            continue
        live_mb += live_bytes / 1_048_576
        categories.append(
            AllocationCategory(
                type=type_name,
                live_bytes=live_bytes,
                live_count=live_count,
                total_bytes=total_bytes,
                total_count=total_count,
                severity=get_memory_severity(live_bytes / 1_048_576, memory_warning_mb, memory_critical_mb),
                suggestion=get_allocation_suggestion(type_name),
            )
        )

    peak_match = re.search(r"peak[^>]*memory[^>]*>([0-9.]+)\s*(mb|kb)?", xml_content, re.IGNORECASE)
    if peak_match and peak_mb == 0:
        peak_mb = float(peak_match.group(1))
        if peak_match.group(2) and peak_match.group(2).lower() == "kb":
            peak_mb /= 1024
    elif peak_mb == 0:
        peak_mb = live_mb * 1.3

    categories.sort(key=lambda category: category.live_bytes, reverse=True)
    status: Status = (
        "critical" if peak_mb > memory_critical_mb else "warning" if peak_mb > memory_warning_mb else "good"
    )

    if status == "good":
        summary = f"✅ Peak memory {peak_mb:.1f}MB - healthy."
    elif status == "warning":
        summary = f"⚠️ Peak memory {peak_mb:.1f}MB - monitor on older devices."
    else:
        summary = f"🔴 Peak memory {peak_mb:.1f}MB - high risk of jetsam kill on iPhone with 3GB RAM."

    recommendations: list[str] = []
    if any("uiimage" in category.type.lower() for category in categories):
        recommendations.append("Downscale images before storing in memory. Use ImageIO for thumbnail generation.")
    if any("imageio" in category.type.lower() or "cg image" in category.type.lower() for category in categories):
        recommendations.append(
            "Audit image decoding and caching; ImageIO/CG image VM can grow quickly during gallery flows."
        )
    if any(category.type.startswith("VM: ") for category in categories[:10]):
        recommendations.append(
            "Inspect VM categories separately from heap objects; large VM regions often point to image, layer, "
            "or mapped-file pressure."
        )
    if peak_mb > memory_cache_warning_mb:
        recommendations.append("Subscribe to UIApplicationDidReceiveMemoryWarningNotification and release caches.")
    recommendations.append("Use Xcode Memory Gauge during testing. Target < 50MB for typical use, < 120MB peak.")

    return AllocationAnalysis(
        peak_memory_mb=round(peak_mb, 1),
        live_memory_mb=round(live_mb, 1),
        status=status,
        top_allocations=categories[:15],
        summary=summary,
        recommendations=recommendations,
    )


def format_allocations(analysis: AllocationAnalysis, bundle_id: str) -> str:
    lines = [
        f"# Memory Allocations - {bundle_id}",
        f"\n{analysis.summary}",
        f"\n**Peak:** {analysis.peak_memory_mb}MB | **Live:** {analysis.live_memory_mb}MB",
        "\n## Top Allocations by Type",
    ]
    if not analysis.top_allocations:
        lines.append("No allocation data found.")
    else:
        for category in analysis.top_allocations:
            icon = "🔴" if category.severity == "critical" else "🟡" if category.severity == "warning" else "🟢"
            live_mb = category.live_bytes / 1_048_576
            total_mb = category.total_bytes / 1_048_576
            lines.append(f"\n{icon} `{category.type}`")
            lines.append(
                f"   Live: **{live_mb:.2f}MB** ({category.live_count} objects) | "
                f"Total: {total_mb:.2f}MB ({category.total_count} allocs)"
            )
            if category.suggestion:
                lines.append(f"   💡 {category.suggestion}")

    lines.append("\n## Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in analysis.recommendations)
    return "\n".join(lines)


def compare_allocation_analyses(baseline: AllocationAnalysis, candidate: AllocationAnalysis, target_name: str) -> str:
    peak_delta = candidate.peak_memory_mb - baseline.peak_memory_mb
    live_delta = candidate.live_memory_mb - baseline.live_memory_mb
    baseline_types = {category.type: category.live_bytes for category in baseline.top_allocations}
    candidate_types = {category.type: category.live_bytes for category in candidate.top_allocations}
    changed_types = sorted(
        set(baseline_types) | set(candidate_types),
        key=lambda type_name: abs(candidate_types.get(type_name, 0) - baseline_types.get(type_name, 0)),
        reverse=True,
    )[:10]

    lines = [
        f"# Memory Trace Comparison - {target_name}",
        "",
        f"**Baseline peak:** {baseline.peak_memory_mb}MB",
        f"**Candidate peak:** {candidate.peak_memory_mb}MB",
        f"**Peak delta:** {format_delta(round(peak_delta, 2), 'MB')}",
        f"**Live delta:** {format_delta(round(live_delta, 2), 'MB')}",
        "",
        "## Changed Allocation Types",
    ]
    if not changed_types:
        lines.append("No comparable allocation types found.")
    else:
        for type_name in changed_types:
            before_mb = baseline_types.get(type_name, 0) / 1_048_576
            after_mb = candidate_types.get(type_name, 0) / 1_048_576
            delta = format_delta(round(after_mb - before_mb, 2), "MB")
            lines.append(
                f"- `{type_name}`: {before_mb:.2f}MB -> {after_mb:.2f}MB ({delta})"
            )
    return "\n".join(lines)

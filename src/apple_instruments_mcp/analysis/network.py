from __future__ import annotations

import re

from apple_instruments_mcp.analysis.models import (
    NetworkAnalysis,
    NetworkRequest,
    Status,
)
from apple_instruments_mcp.analysis.severity import get_severity


def has_network_evidence(xml_content: str) -> bool:
    return "<request" in xml_content or bool(re.search(r"<(url|duration|bytes|status)[^>]*>", xml_content))


def parse_network(
    xml_content: str,
    *,
    request_warning_ms: float = 500,
    request_critical_ms: float = 2000,
    slow_request_critical_count: int = 5,
    transfer_warning_mb: float = 5,
) -> NetworkAnalysis:
    # TODO: Not yet validated against a real Network .trace export. The regex below
    # matches a fabricated <request url=... method=...> shape; xctrace's Network
    # template emits nsurlsession-task-info / connection-event rows. xctrace also
    # supports `--har` for HTTP Archive export which may be a better source. Rewrite
    # once a real Network trace is available.
    requests: list[NetworkRequest] = []
    req_pattern = re.compile(
        r'<request[^>]*url="([^"]+)"[^>]*method="([^"]+)"[^>]*duration="([0-9.]+)"[^>]*bytes="(\d+)"[^>]*status="(\d+)"'
    )

    for match in req_pattern.finditer(xml_content):
        duration_ms = float(match.group(3)) * 1000
        requests.append(
            NetworkRequest(
                url=match.group(1),
                method=match.group(2),
                duration_ms=round(duration_ms),
                bytes=int(match.group(4)),
                status_code=int(match.group(5)),
                severity=get_severity(duration_ms, request_critical_ms, request_warning_ms),
            )
        )

    if not requests:
        for match in re.finditer(r"<row>([\s\S]*?)</row>", xml_content):
            row = match.group(1)
            url_match = re.search(r"<url[^>]*>([^<]+)</url>", row)
            url = url_match.group(1).strip() if url_match else ""
            duration = float((re.search(r"<duration[^>]*>([0-9.]+)", row) or ["", "0"])[1])
            bytes_count = int((re.search(r"<bytes[^>]*>(\d+)", row) or ["", "0"])[1])
            status_code = int((re.search(r"<status[^>]*>(\d+)", row) or ["", "200"])[1])
            if not url:
                continue
            duration_ms = duration * 1000
            requests.append(
                NetworkRequest(
                    url=url,
                    method="GET",
                    duration_ms=round(duration_ms),
                    bytes=bytes_count,
                    status_code=status_code,
                    severity=get_severity(duration_ms, request_critical_ms, request_warning_ms),
                )
            )

    requests.sort(key=lambda request: request.duration_ms, reverse=True)
    total_transferred = sum(request.bytes for request in requests) / 1_048_576
    slow_count = sum(1 for request in requests if request.severity != "ok")
    status: Status = "good" if slow_count == 0 else "critical" if slow_count > slow_request_critical_count else "warning"

    if status == "good":
        summary = f"✅ {len(requests)} requests - all within acceptable latency."
    elif status == "warning":
        summary = f"⚠️ {slow_count} slow request(s) found out of {len(requests)} total."
    else:
        summary = f"🔴 {slow_count} slow request(s) - network is a bottleneck."

    recommendations: list[str] = []
    if any(request.status_code >= 400 for request in requests):
        recommendations.append("Fix failing requests (4xx/5xx) - these cause silent UX degradation.")
    if total_transferred > transfer_warning_mb:
        recommendations.append(
            f"Total transfer > {transfer_warning_mb:g}MB. Use pagination, compression (gzip/brotli), and caching."
        )
    recommendations.append("Use URLCache for GET requests. Consider background URLSession for large transfers.")

    return NetworkAnalysis(
        total_requests=len(requests),
        total_transferred_mb=round(total_transferred, 2),
        status=status,
        slow_requests=requests[:15],
        summary=summary,
        recommendations=recommendations,
    )


def format_network(analysis: NetworkAnalysis, bundle_id: str) -> str:
    lines = [
        f"# Network Activity - {bundle_id}",
        f"\n{analysis.summary}",
        f"\n**Requests:** {analysis.total_requests} | **Transferred:** {analysis.total_transferred_mb}MB",
        "\n## Slow Requests",
    ]
    if not analysis.slow_requests:
        lines.append("No slow requests found.")
    else:
        for request in analysis.slow_requests:
            icon = "🔴" if request.severity == "critical" else "🟡" if request.severity == "warning" else "🟢"
            lines.append(f"\n{icon} `{request.method} {request.url}`")
            lines.append(
                f"   Duration: **{request.duration_ms}ms** | Size: {request.bytes / 1024:.1f}KB | Status: {request.status_code}"
            )

    lines.append("\n## Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in analysis.recommendations)
    return "\n".join(lines)

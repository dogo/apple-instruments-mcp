from __future__ import annotations

from apple_instruments_mcp.analysis.models import Severity, Status


def get_severity(
    ms: float, threshold_critical: float = 300, threshold_warning: float = 100
) -> Severity:
    if ms > threshold_critical:
        return "critical"
    if ms > threshold_warning:
        return "warning"
    return "ok"


def get_memory_severity(mb: float, warning_mb: float = 100, critical_mb: float = 200) -> Severity:
    if mb > critical_mb:
        return "critical"
    if mb > warning_mb:
        return "warning"
    return "ok"


def get_status(ms: float, good_threshold: float, critical_threshold: float) -> Status:
    if ms < good_threshold:
        return "good"
    if ms < critical_threshold:
        return "warning"
    return "critical"


def get_launch_suggestion(symbol: str, phase: str) -> str | None:
    s = symbol.lower()
    if "database" in s or "sqlite" in s or "coredata" in s:
        return "Move database initialization to a background queue or use lazy loading."
    if "analytics" in s or "firebase" in s or "segment" in s:
        return "Defer analytics SDK initialization after first frame is rendered."
    if "network" in s or "urlsession" in s or "alamofire" in s:
        return "Avoid synchronous network calls on launch. Use async/await or callbacks."
    if "image" in s or "uiimage" in s or "sdwebimage" in s:
        return "Defer image loading/caching setup to after first frame."
    if phase == "pre-main" and "+initialize" in s:
        return "Avoid heavy work in +initialize or static initializers - they run before main()."
    if "json" in s or "decoder" in s or "codable" in s:
        return "Defer JSON parsing to a background thread. Consider caching decoded models."
    return None


def get_allocation_suggestion(type_name: str) -> str | None:
    t = type_name.lower()
    if "uiimage" in t or "cgimage" in t:
        return "Use downsampled images. Load at display size, not original resolution."
    if "string" in t or "nsstring" in t:
        return "Consider using StaticString or interning repeated strings."
    if "data" in t or "nsdata" in t:
        return "Stream large Data objects instead of loading fully into memory."
    if "array" in t or "nsarray" in t:
        return "Use lazy collections or pagination for large arrays."
    if "viewcontroller" in t or "uiview" in t:
        return "Check for retained view controllers outside the view hierarchy."
    return None


def get_leak_suggestion(type_name: str) -> str | None:
    t = type_name.lower()
    if "closure" in t or "block" in t:
        return "Capture lists ([weak self]) in closures referencing self."
    if "delegate" in t:
        return "Delegate properties should be weak. Check protocol declaration."
    if "timer" in t or "nstimer" in t:
        return "Invalidate timers in deinit or viewDidDisappear."
    if "notificationcenter" in t:
        return "Remove observers in deinit: NotificationCenter.default.removeObserver(self)."
    return None


def get_hot_method_suggestion(symbol: str) -> str | None:
    s = symbol.lower()
    if "layout" in s or "autolayout" in s:
        return "Profile Auto Layout constraints - reduce constraint count or use manual layout for hot paths."
    if "draw" in s or "render" in s or "metal" in s:
        return "Move rendering work to background threads or use Metal for GPU offloading."
    if "json" in s or "decoder" in s:
        return "Parse JSON on a background queue. Cache decoded results."
    if "sort" in s or "filter" in s or "map" in s:
        return "Use lazy sequences or move collection operations off the main thread."
    if "fetch" in s or "coredata" in s:
        return "Add fetch limit and use async fetch requests (NSAsynchronousFetchRequest)."
    return None


def format_delta(value: float, unit: str, lower_is_better: bool = True) -> str:
    direction = "regression" if (value > 0 and lower_is_better) or (value < 0 and not lower_is_better) else "improvement"
    sign = "+" if value > 0 else ""
    return f"{sign}{value:g}{unit} ({direction})"

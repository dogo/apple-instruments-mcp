# Changelog

## 1.0.2 - 2026-06-15

- Restored analysis against real `xctrace` XML exports after validating physical-device traces.
- Added validated Allocations and Leaks parsers for the exported Instruments detail rows.
- Added Network trace analysis for `network-connection-detected` socket-level rows when HTTP/HAR task details are absent.
- Updated parser status documentation and regression coverage for the validated trace shapes.

## 1.0.1 - 2026-06-15

- Fixed generated `xcrun xctrace record --output` paths to use `.trace`, which current Xcode versions require for recording.
- Updated MCP tool descriptions, examples, and README guidance from `.xctrace` to `.trace` for recorded trace bundles.
- Added regression coverage for generated record commands and dry-run output.

## 1.0.0 - 2026-06-15

- Initial Python release of `apple-instruments-mcp`.
- Added profiling tools for Apple platform apps, host processes, and all-processes recordings through `xcrun xctrace`.
- Added analysis and comparison tools for launch, allocations, leaks, CPU, and network traces.

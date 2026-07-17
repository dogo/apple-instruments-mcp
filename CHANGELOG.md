# Changelog

## 1.2.1 - 2026-07-17

- Mark analyses and comparisons as inconclusive when `xctrace export` fails instead of parsing missing or partial XML and potentially reporting false zero activity.
- Include subprocess exit status or terminating signals such as `SIGSEGV` in `xctrace` command failures.
- Diagnose physical-device readiness wedges before recording: devices visible to CoreDevice/`devicectl` but listed under `Devices Offline` by `xctrace` now fail fast with Xcode-specific preparation guidance instead of stalling until the watchdog fires.
- Extended `doctor` with online/offline device counts, CoreSimulator readiness, and sandbox-access diagnostics, so a sandboxed MCP process losing write access to InstrumentsCLI/CoreSimulator state no longer masquerades as a tracing wedge.
- Fail faster on known Instruments tap disconnections and reduced the recording teardown grace from 60 to 15 seconds.

## 1.2.0 - 2026-07-16

- Fixed `analyze_network` to export the Network Connections XPath instead of the trace table of contents.
- Stopped force-killing every `xctrace` process on the Mac before recordings. The watchdog now owns and terminates only the child process created for the current request.
- Normalized Time Profiler CPU-active time by the observed wall-clock sample span before assigning overall status. The parser now recognizes xctrace's real `sample-time` and formatted thread fields, reports distinguish cumulative CPU-active time from average CPU load, and no longer claim the main thread is blocked without main-thread evidence.
- Fixed healthy Time Profiler methods with `ok` severity being incorrectly promoted to an overall warning.
- Clean up empty temporary run directories, zero-byte `.trace` bundles, and `RunIssues.storedata`-only bundles after failed recordings while continuing to preserve partial traces containing real payloads.
- Honor `keep_trace=True` on recording failures by preserving the run directory and reporting trace/XML artifact paths even when an artifact was not created.
- Added a macOS CI smoke test that executes the installed `xcrun xctrace` through the project subprocess wrapper.

## 1.1.0 - 2026-06-17

- Added two new MCP tools: `doctor` (one-shot xctrace health check with xctrace version/path and device/template/instrument counts) and `profile_preset` (`cpu`/`memory`/`network`/`full` bundles that record multiple instruments in a single trace and report each family that produced data).
- Added dSYM symbolication to the time-profile tools. Pass `dsym_path` on `analyze_time_profiler` / `analyze_time_profiler_trace` to resolve raw-address frames from release builds; UUID is verified via `dwarfdump` before `atos` runs and atos line-count mismatches drop the batch entirely, so symbol names are never invented.
- Added scope/hang/user-method views to time profiler analysis. `scope_start_ms` and `scope_end_ms` clip samples to a window; `hang_threshold_ms` (default 250) surfaces main-thread inter-sample gaps as candidate stalls in a new "Main Thread" section; `user_binaries` filters a "Top User Methods" view so system frames don't crowd out app code.
- Replaced the `--time-limit + 30s` wrapper timeout on xctrace record with a streaming watchdog: 15s startup deadline + 60s teardown grace, with distinct diagnostics per phase and the last xctrace stdout line preserved so post-launch tap wedges (DTServiceHub/dtsecurity stalling after the simulator accepts the launch) are diagnosable from the response alone.
- Trust the saved `.trace` bundle as ground truth when xctrace exits non-zero with a finalized bundle (e.g. a `--launch` target killed by `--time-limit` returning its own exit status). A bundle is considered finalized when `Trace*.run/` holds anything beyond the boilerplate `RunIssues.storedata`.
- Pass `--no-prompt` on every record so xctrace doesn't hang on privacy prompts in non-interactive use; surface per-probe iOS preflight wall-clock timings in the failure diagnostic so it's obvious which probes passed before a post-launch wedge.

## 1.0.4 - 2026-06-15

- Replaced the blunt `time_limit + 30s` wall timeout on `xctrace record` with a streaming watchdog that bails out within `time_limit + 15s` grace when xctrace announces `Starting recording` but never finishes — the post-launch runtime wedge case where the 1.0.3 pre-flight already passed.
- Added a separate 15s startup timeout for the case where xctrace itself never reaches `Starting recording`, with a distinct diagnosis that suggests `pkill -9 xctrace`.
- Pre-flight now records per-probe wall-clock durations and surfaces them in the failure diagnostic so it's obvious which probes passed before the record-time wedge.
- Preserved the last line of xctrace's stdout in the error message so DTServiceHub-style runtime wedges are diagnosable from the response alone.

## 1.0.3 - 2026-06-15

- Fixed `profile_ios_app` and other iOS tools hanging ~40s with a generic `Command timed out` when CoreSimulator is wedged. Added a fast pre-flight (`simctl list devices` + `simctl get_app_container`, 5s each) that short-circuits with a specific diagnosis for wedged CoreSimulator, non-booted simulator, or missing app — including the exact recovery commands.
- Improved the timeout branch in `format_target_error` so xctrace timeouts against an iOS simulator now name CoreSimulator as the likely cause and suggest `simctl shutdown && boot` / `killall com.apple.CoreSimulator.CoreSimulatorService`.
- Preserved the partial `.trace` bundle when recording fails so it can be inspected in Instruments.app instead of being cleaned up.

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

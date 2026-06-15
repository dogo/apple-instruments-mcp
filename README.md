# apple-instruments-mcp

`apple-instruments-mcp` is a Python MCP server for profiling Apple platform apps and processes with Instruments through `xcrun xctrace`. It lets MCP clients such as Claude Desktop record traces, inspect existing `.trace` bundles, and return concise performance reports with actionable recommendations.

The server can target iOS, iPadOS, macOS, tvOS, watchOS, visionOS, simulators, physical devices, and host processes when those targets are visible to the installed Xcode/Instruments toolchain. Actual template and device support is determined by `xcrun xctrace list devices` and `xcrun xctrace list templates` on your Mac.

## Features

- Record new traces with `xctrace` from an MCP client.
- Analyze existing `.trace` bundles without recording again.
- Report launch time, memory allocations, leaks, CPU hot spots, and network activity.
- Launch apps by bundle ID or executable path.
- Attach to running processes by process name or PID.
- Record all processes when an Instruments template supports it.
- List available devices, simulators, runtimes, and Instruments templates.
- Return raw or JSON-structured device/template listings.
- Preview the generated `xctrace` command with `dry_run`.
- Keep `.trace` and XML artifacts for later inspection.
- Return human-readable summaries with top offenders and suggested fixes.
- Runs as a standard stdio MCP server.

## Requirements

- macOS
- Xcode with Instruments installed
- Xcode Command Line Tools: `xcode-select --install`
- Python 3.11 or newer
- A supported target visible to `xctrace`: booted simulator, connected device, local macOS app, running process, or all-processes recording.

Physical devices may require enabling UI automation in `Settings > Developer`.

## Installation

The package is published on PyPI. The recommended way is to run it through [`uvx`](https://github.com/astral-sh/uv), which downloads and caches the server on demand without polluting your environment:

```bash
uvx apple-instruments-mcp
```

Alternatively, install it globally with `pipx` or `pip`:

```bash
pipx install apple-instruments-mcp
# or
python -m pip install apple-instruments-mcp
```

Either path provides the `apple-instruments-mcp` executable.

## MCP Client Configuration

`apple-instruments-mcp` is a standard stdio MCP server, so any MCP-compatible client works — Claude Desktop, Claude Code, Codex CLI, Kiro, Cursor, Cline, Continue, Windsurf, Zed, or anything else that speaks MCP.

The simplest config uses `uvx`, so the client launches the server on demand with no separate install step. Example for Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "apple-instruments": {
      "command": "uvx",
      "args": ["apple-instruments-mcp"]
    }
  }
}
```

To pin a specific version, replace the arg with `apple-instruments-mcp@1.0.1`.

For Claude Code:

```bash
claude mcp add apple-instruments -- uvx apple-instruments-mcp
```

If you prefer a global install (`pipx` or `pip`), point the client at the resulting binary instead:

```json
{
  "mcpServers": {
    "apple-instruments": {
      "command": "apple-instruments-mcp"
    }
  }
}
```

Other clients (Codex CLI, Kiro, Cursor, Cline, Continue, Windsurf, Zed) accept the same `command` / `args` shape under their own MCP server config — check the client's docs for the exact file path. Restart the client after saving.

## Example Prompts

```text
List the devices and Instruments templates available on this Mac.
Record an App Launch trace for com.example.app on this iPhone simulator and show the startup offenders.
Launch /Applications/MyMacApp.app with Time Profiler and show CPU hot methods.
Attach Allocations to the running process named MyMacApp for 30 seconds.
Attach Time Profiler to PID 1234.
Record all processes with Time Profiler for 10 seconds.
Analyze network activity for com.example.app and flag slow requests.
Analyze the existing trace at ~/Desktop/launch.trace.
Compare ~/Desktop/baseline.trace and ~/Desktop/candidate.trace for launch regressions.
```

## Tools

| Tool | Instruments template | Description |
| --- | --- | --- |
| `list_devices` | - | Lists devices, simulators, runtimes, and host targets visible to `xctrace`. |
| `list_devices_structured` | - | Returns the device/runtime listing as JSON. |
| `list_templates` | - | Lists Instruments templates installed on this Mac. |
| `list_templates_structured` | - | Returns the template listing as JSON. |
| `profile_ios_app` | Selected by `profile_type` | Profiles an iOS, iPadOS, tvOS, watchOS, or visionOS app by bundle ID on a simulator/device. |
| `profile_mac_app` | Selected by `profile_type` | Profiles a macOS `.app` or executable by launch path. |
| `profile_process` | Selected by `profile_type` | Profiles a running process by process name or PID. |
| `profile_all_processes` | Selected by `profile_type` | Profiles all processes on the host or selected device. |
| `analyze_launch` | App Launch | Records and analyzes app startup time. |
| `analyze_launch_trace` | App Launch | Analyzes an existing App Launch `.trace`. |
| `analyze_allocations` | Allocations | ❌ Not supported by `xctrace export` — returns an explanatory error. Use Instruments.app. |
| `analyze_allocations_trace` | Allocations | ❌ Not supported by `xctrace export` — returns an explanatory error. Use Instruments.app. |
| `analyze_leaks` | Leaks | ❌ Not supported by `xctrace export` — returns an explanatory error. Use Instruments.app. |
| `analyze_leaks_trace` | Leaks | ❌ Not supported by `xctrace export` — returns an explanatory error. Use Instruments.app. |
| `analyze_time_profiler` | Time Profiler | Records CPU samples and reports hot methods. |
| `analyze_time_profiler_trace` | Time Profiler | Analyzes an existing Time Profiler `.trace`. |
| `analyze_network` | Network | Records network requests, latency, transfer sizes, and status codes. |
| `analyze_network_trace` | Network | Analyzes an existing Network `.trace`. |
| `compare_launch_traces` | App Launch | Compares two App Launch traces and reports startup deltas. |
| `compare_memory_traces` | Allocations | ❌ Not supported by `xctrace export` — returns an explanatory error. Use Instruments.app. |
| `compare_cpu_traces` | Time Profiler | Compares two Time Profiler traces and reports CPU deltas. |
| `build_xctrace_command` | Any | Returns the exact `xcrun xctrace record` command for a target without executing it. |

## Recording Targets

Recording tools accept exactly one target mode:

- `bundle_id`: app bundle identifier, for example `com.example.app`. Use with `device_id` for iOS, iPadOS, tvOS, watchOS, and visionOS simulator/device launches.
- `launch_path`: executable path or `.app` path. Use this for macOS apps and command-line tools.
- `process_name`: attach to a running process by name.
- `pid`: attach to a running process by process ID.
- `all_processes`: record all processes when the selected template supports it.

Additional recording arguments:

- `device_id`: optional simulator UUID or physical device identifier from `list_devices`. Omit it for host macOS profiling.
- `launch_args`: optional shell-style arguments passed after `launch_path`.
- `time_limit_seconds`: recording duration, from 5 to 120 seconds. Defaults to 20.
- `dry_run`: return the generated `xctrace` command without recording.
- `keep_trace`: keep generated `.trace` and XML artifacts, and include their paths in the report.
- `output_dir`: optional parent directory for generated artifacts. Each run creates a dedicated subdirectory inside it.

Examples:

```json
{ "bundle_id": "com.example.app", "device_id": "SIMULATOR-UUID" }
{ "launch_path": "/Applications/MyMacApp.app" }
{ "launch_path": "/usr/bin/python3", "launch_args": "--version" }
{ "process_name": "MyMacApp" }
{ "pid": 1234 }
{ "all_processes": true }
{ "launch_path": "/Applications/MyMacApp.app", "dry_run": true }
{ "bundle_id": "com.example.app", "device_id": "SIMULATOR-UUID", "keep_trace": true, "output_dir": "~/Desktop/traces" }
```

The `profile_*` tools are higher-level wrappers around the generic `analyze_*` tools. Prefer them when you know the target shape:

```json
{ "profile_type": "launch", "bundle_id": "com.example.app", "device_id": "SIMULATOR-UUID" }
{ "profile_type": "time_profiler", "launch_path": "/Applications/MyMacApp.app" }
{ "profile_type": "allocations", "process_name": "MyMacApp" }
{ "profile_type": "time_profiler", "pid": 1234 }
{ "profile_type": "time_profiler" }
```

Supported `profile_type` values are `launch`, `allocations`, `leaks`, `time_profiler`, and `network`.

## Custom Thresholds

The generic `analyze_*` and `analyze_*_trace` tools expose parser-specific thresholds. Use these when the defaults are too strict or too loose for a device class, platform, workload, or CI budget.

Launch:

- `launch_good_ms`
- `launch_critical_ms`
- `offender_warning_ms`
- `offender_critical_ms`

Allocations:

- `memory_warning_mb`
- `memory_critical_mb`
- `memory_cache_warning_mb`

Leaks:

- `leak_critical_count`

Time Profiler:

- `total_good_ms`
- `total_critical_ms`
- `method_warning_ms`
- `method_critical_ms`

Network:

- `request_warning_ms`
- `request_critical_ms`
- `slow_request_critical_count`
- `transfer_warning_mb`

Example:

```json
{
  "bundle_id": "com.example.app",
  "device_id": "SIMULATOR-UUID",
  "launch_good_ms": 700,
  "launch_critical_ms": 1500,
  "offender_warning_ms": 150,
  "offender_critical_ms": 500
}
```

## Trace Analysis Arguments

Trace analysis tools accept:

- `trace_path`: absolute path to an existing `.trace` bundle.
- `bundle_id`: optional target name used in the generated report.

Trace comparison tools accept:

- `baseline_trace_path`: absolute path to the baseline `.trace` bundle.
- `candidate_trace_path`: absolute path to the candidate `.trace` bundle.
- `bundle_id`: optional target name used in the generated report.

Example:

```json
{
  "baseline_trace_path": "~/Desktop/baseline.trace",
  "candidate_trace_path": "~/Desktop/candidate.trace",
  "bundle_id": "com.example.app"
}
```

## Example Report

```markdown
# App Launch Analysis - com.example.app

Warning: Launch time 1240ms - above 400ms. Users may notice the delay.

**Total:** 1240ms

## Phases
- **pre-main (dyld + static init):** 434ms (35%)
- **post-main (AppDelegate + UI):** 806ms (65%)

## Top Offenders

Critical: `-[DatabaseManager setup]` [post-main]
   Self: **540ms** | Total: 540ms | 43%
   Suggestion: Move database initialization to a background queue or use lazy loading.

Warning: `+[AnalyticsSDK configure:]` [post-main]
   Self: **210ms** | Total: 210ms | 17%
   Suggestion: Defer analytics SDK initialization after first frame is rendered.

## Recommendations
- Fix 1 critical offender(s) - each adds 300ms+ to launch.
- Target: total launch under 400ms.
```

## Notes

- Temporary `.trace` bundles created by recording tools are cleaned up after each run.
- All analysis is based on the XML exported by `xcrun xctrace export`.
- Reports include an `Analysis Quality` section when the exported XML is empty or no recognizable data was found for the selected parser. Export failures (for example, an unsupported xpath) are reported under `Export Warning`.
- If you already have a trace, prefer the `_trace` tools to avoid recording again.
- Current Xcode versions expect `xcrun xctrace record --output` paths to use the `.trace` extension; `.xctrace` may be rejected before recording starts.

## Parser Status

Each parser is wired to a specific `xctrace export --xpath` schema. The tooling has been validated end-to-end against real `.trace` bundles for the ✅ rows. The Allocations and Leaks tools intentionally short-circuit with an explanatory error message because Apple's `xctrace export` does not expose either of those data sets via xpath.

| Template | xpath / schema | Status |
| --- | --- | --- |
| Time Profiler | `time-profile` | ✅ validated against real traces |
| App Launch | `time-profile` (CPU samples, idle leaves filtered) | ✅ validated against real traces |
| Allocations | n/a | ❌ not exposed by `xctrace export` — tool returns a clear "use Instruments.app" message |
| Leaks | n/a | ❌ not exposed by `xctrace export` — tool returns a clear "use Instruments.app" message |
| Network | (legacy regex) | ⚠️ not validated — pending a Network trace from a physical device (`xctrace export --har` is also worth considering) |

### App Launch caveats

The App Launch parser uses the same `time-profile` schema as Time Profiler and classifies frames into pre-main (dyld / static init / Swift runtime) vs post-main (AppDelegate / UIApplication / Cocoa methods) by symbol heuristic. Two things to keep in mind:

- `total_launch_ms` is **CPU-active** launch time, not wall-clock. xctrace does not expose a clean "app became active" marker we can read.
- Samples whose leaf frame is a known kernel wait (`mach_msg2_trap`, `start_wqthread`, `semaphore_wait_trap`, etc.) are dropped, matching Instruments' default "Hide System Libraries" behaviour. Without this, a long recording that idles after launch would dominate the totals with worker threads parked in wait.

## Troubleshooting

Recording tools run a few pre-flight checks before invoking `xctrace`. A target is rejected up front when `launch_path` does not exist on this Mac, `pid` is not a positive integer or no longer running, or `bundle_id` contains characters Instruments does not accept. When `xctrace` itself fails, the error message is classified per target (bundle not installed, dead process, unresolved device, invalid `launch_path`, missing Xcode tools) and the report includes a fix hint scoped to that target instead of a generic checklist.

If recording fails, check these first:

- The target app is installed on the selected simulator or device, or the local launch path exists.
- The simulator/device is booted and visible in `xcrun xctrace list devices`.
- The process exists when using `process_name` or `pid`.
- Xcode and command line tools are selected correctly: `xcode-select -p`.
- The Instruments template exists on your machine: use `list_templates`.
- Physical devices are trusted, unlocked, connected, and allowed to run UI automation.

Use `build_xctrace_command` to inspect the exact command that would run, without recording. The returned command also surfaces any pre-flight warnings detected against the chosen target.

You can also verify `xctrace` directly:

```bash
xcrun xctrace list devices
xcrun xctrace list templates
```

## Development

Clone the repository and install the editable build with the `dev` extra:

```bash
git clone git@github.com:dogo/apple-instruments-mcp.git
cd apple-instruments-mcp
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

Run linters, type check, and the test suite:

```bash
ruff check src tests
pyright
PYTHONPATH=src python -m unittest discover -s tests -v
```

The package ships a `py.typed` marker so downstream consumers can type-check against its public API. A `uv.lock` is committed for reproducible dependency installs with [uv](https://github.com/astral-sh/uv); CI runs the same checks across Python 3.11–3.13 via `.github/workflows/ci.yml`.

Run the MCP server locally:

```bash
python -m apple_instruments_mcp
```

### Releasing

Releases are published to PyPI through GitHub Actions trusted publishing — no API tokens stored in the repo. Steps:

1. Bump `version` in `pyproject.toml`, commit, and push to `main`.
2. Tag the commit with `X.Y.Z` (no `v` prefix) matching that version and push the tag.
3. The `Release` workflow builds `sdist` + `wheel`, verifies the tag matches `pyproject.toml`, and uploads to PyPI via OIDC.

One-time PyPI setup: on https://pypi.org, register the project name and add a Trusted Publisher pointing at this repository, the `release.yml` workflow, and the `pypi` environment.

## License

MIT

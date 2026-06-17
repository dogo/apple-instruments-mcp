"""Resolve raw-address frames in a Time Profiler trace against an explicit
dSYM bundle (or plain Mach-O).

The flow mirrors xcprof's `symbolicate.go`:

1. Group unsymbolicated frames by (UUID, load-addr, arch). Each group needs
   one `atos` invocation.
2. For each unique UUID, find the DWARF Mach-O inside the dSYM bundle. We
   verify the candidate carries the requested UUID via `xcrun dwarfdump
   --uuid`, so a bundle with multiple architectures or a wrong path can't
   silently misattribute names.
3. Batch every address of an image into one `atos` call, parse one symbol
   per input line, and rebuild the affected `TimeProfileSample`s with the
   resolved names.

Honest-fallback contract: when *anything* fails — dSYM missing, UUID
mismatch, atos crash, line-count mismatch — the affected frames are left as
raw addresses. We never invent a name.

Auto-discovery (Spotlight `mdfind` against `com_apple_xcode_dsym_uuids`) is
deliberately out of scope here; only an explicit `dsym_path` is accepted.
The auto-discovery path is a future addition and lives next to the same
`resolve_one_image` plumbing when it lands.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, replace
from pathlib import Path

from apple_instruments_mcp.analysis.models import SampleFrame, TimeProfileSample

DWARFDUMP_TIMEOUT_SECONDS = 10.0
ATOS_TIMEOUT_SECONDS = 10.0

_HEX_ADDR_RE = re.compile(r"^0x[0-9a-f]+$", re.IGNORECASE)


@dataclass(frozen=True)
class SymbolicationSummary:
    attempted: bool
    resolved: int
    unresolved: int
    images_with_dsym: int
    images_without_dsym: int
    note: str = ""


def is_unsymbolicated(symbol: str) -> bool:
    """A frame is unsymbolicated when its `symbol` is just a hex address.

    xctrace exports `0x10001a2b4` as the frame `name` when it has no symbol
    for the address; a real symbol like `MyApp.run()` never matches.
    """
    return bool(symbol) and bool(_HEX_ADDR_RE.match(symbol.strip()))


def _resolvable(frame: SampleFrame) -> bool:
    return bool(frame.binary_uuid) and bool(frame.addr) and is_unsymbolicated(frame.symbol)


def _dwarf_candidates(dsym_path: Path) -> list[Path]:
    """A `.dSYM` bundle has `<bundle>/Contents/Resources/DWARF/<binary>`; for a
    plain Mach-O path we just return that path."""
    inner = dsym_path / "Contents" / "Resources" / "DWARF"
    if inner.is_dir():
        return sorted(p for p in inner.iterdir() if p.is_file())
    if dsym_path.is_file():
        return [dsym_path]
    return []


async def _run_capturing(*args: str, timeout: float) -> tuple[int, str]:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        return -1, ""
    rc = process.returncode if process.returncode is not None else 0
    return rc, stdout.decode("utf-8", errors="replace")


async def dsym_has_uuid(binary: Path, uuid: str) -> bool:
    """Confirm a candidate Mach-O carries the requested UUID — guards against a
    wrong/mismatched bundle when an explicit `--dsym` is supplied."""
    rc, out = await _run_capturing(
        "xcrun", "dwarfdump", "--uuid", str(binary), timeout=DWARFDUMP_TIMEOUT_SECONDS
    )
    if rc != 0:
        return False
    return uuid.upper() in out.upper()


async def find_dwarf_binary(dsym_path: Path, uuid: str) -> Path | None:
    """Pick the inner Mach-O of a `.dSYM` whose DWARF carries `uuid` — by UUID,
    not blindly the first entry. `None` when no candidate matches."""
    for candidate in _dwarf_candidates(dsym_path):
        if await dsym_has_uuid(candidate, uuid):
            return candidate
    return None


def _parse_atos_line(line: str) -> str:
    """Strip the ` (in <image>) (file:line)` suffix atos appends.

    Unresolved entries come back as the raw `0x…` — we leave those untouched
    and the caller treats them as a miss.
    """
    line = line.strip()
    idx = line.find(" (in ")
    if idx >= 0:
        return line[:idx].strip()
    return line


def _build_atos_argv(
    binary: Path, arch: str, load_addr: str, addrs: list[str]
) -> list[str]:
    args = ["atos", "-o", str(binary)]
    if arch:
        args.extend(["-arch", arch])
    if load_addr:
        args.extend(["-l", load_addr])
    args.extend(addrs)
    return args


async def atos_resolve(
    binary: Path, arch: str, load_addr: str, addrs: list[str]
) -> dict[str, str]:
    """Run one batched `atos` call and pair each input address with its output
    line. Returns `{}` when:

    - `atos` exited non-zero
    - the number of output lines doesn't match the number of input addresses
      (mis-aligned output would cause silent mis-attribution, which is worse
      than leaving frames raw)
    """
    if not addrs:
        return {}
    rc, out = await _run_capturing(
        *_build_atos_argv(binary, arch, load_addr, addrs),
        timeout=ATOS_TIMEOUT_SECONDS,
    )
    if rc != 0:
        return {}
    lines = [line for line in out.strip("\n").split("\n") if line.strip()]
    if len(lines) != len(addrs):
        return {}
    return {addr: _parse_atos_line(lines[i]) for i, addr in enumerate(addrs)}


def _group_addresses(
    samples: list[TimeProfileSample],
) -> dict[tuple[str, str, str], set[str]]:
    """Bucket resolvable frames by (UUID, load_addr, arch)."""
    groups: dict[tuple[str, str, str], set[str]] = {}
    for sample in samples:
        for frame in sample.frames:
            if not _resolvable(frame):
                continue
            key = (frame.binary_uuid, frame.binary_load_addr, frame.arch)
            groups.setdefault(key, set()).add(frame.addr)
    return groups


def _rebuild_samples(
    samples: list[TimeProfileSample],
    resolved: dict[tuple[str, str, str], dict[str, str]],
) -> tuple[list[TimeProfileSample], int, int]:
    """Return new samples with resolved symbols substituted in. Counts how
    many addresses were named vs. left raw."""
    new_samples: list[TimeProfileSample] = []
    resolved_count = 0
    unresolved_count = 0
    for sample in samples:
        new_frames: list[SampleFrame] = []
        changed = False
        for frame in sample.frames:
            if not _resolvable(frame):
                new_frames.append(frame)
                continue
            key = (frame.binary_uuid, frame.binary_load_addr, frame.arch)
            name = resolved.get(key, {}).get(frame.addr, "")
            if name and not is_unsymbolicated(name):
                new_frames.append(replace(frame, symbol=name))
                resolved_count += 1
                changed = True
            else:
                new_frames.append(frame)
                unresolved_count += 1
        if changed:
            new_samples.append(replace(sample, frames=tuple(new_frames)))
        else:
            new_samples.append(sample)
    return new_samples, resolved_count, unresolved_count


async def symbolize_samples(
    samples: list[TimeProfileSample], dsym_path: str | Path
) -> tuple[list[TimeProfileSample], SymbolicationSummary]:
    """Resolve raw-address frames against the dSYM at `dsym_path`.

    Returns the rebuilt sample list (frozen dataclasses replaced where a name
    was found) and a summary the caller can render alongside the report.
    """
    dsym = Path(dsym_path).expanduser()
    if not dsym.exists():
        return samples, SymbolicationSummary(
            attempted=True,
            resolved=0,
            unresolved=0,
            images_with_dsym=0,
            images_without_dsym=0,
            note=f"dsym_path does not exist: {dsym}",
        )

    groups = _group_addresses(samples)
    if not groups:
        return samples, SymbolicationSummary(
            attempted=True,
            resolved=0,
            unresolved=0,
            images_with_dsym=0,
            images_without_dsym=0,
            note="no raw-address frames in this trace — nothing to symbolicate",
        )

    dwarf_for_uuid: dict[str, Path | None] = {}
    resolved_by_key: dict[tuple[str, str, str], dict[str, str]] = {}
    images_with_dsym = 0
    images_without_dsym = 0

    for key, addrs in groups.items():
        uuid, load_addr, arch = key
        if uuid not in dwarf_for_uuid:
            dwarf_for_uuid[uuid] = await find_dwarf_binary(dsym, uuid)
        dwarf = dwarf_for_uuid[uuid]
        if dwarf is None:
            images_without_dsym += 1
            continue
        images_with_dsym += 1
        names = await atos_resolve(dwarf, arch, load_addr, sorted(addrs))
        if names:
            resolved_by_key[key] = names

    new_samples, resolved, unresolved = _rebuild_samples(samples, resolved_by_key)
    return new_samples, SymbolicationSummary(
        attempted=True,
        resolved=resolved,
        unresolved=unresolved,
        images_with_dsym=images_with_dsym,
        images_without_dsym=images_without_dsym,
    )


def format_symbolication_summary(summary: SymbolicationSummary | None) -> str:
    """Render a one-paragraph status block. Returns an empty string when
    symbolication wasn't attempted (the report stays clean in that case)."""
    if summary is None or not summary.attempted:
        return ""
    lines = [
        "## Symbolication",
        f"- Resolved frames: **{summary.resolved}**",
        f"- Unresolved frames: **{summary.unresolved}**",
        f"- Images matched in dSYM: {summary.images_with_dsym}",
    ]
    if summary.images_without_dsym:
        lines.append(
            f"- Images without a matching dSYM: {summary.images_without_dsym} "
            "(frames left as raw addresses — honest fallback)"
        )
    if summary.note:
        lines.append(f"- Note: {summary.note}")
    return "\n".join(lines)

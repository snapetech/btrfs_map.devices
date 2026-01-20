#!/usr/bin/env python3
import argparse
import os
import random
import re
import struct
import subprocess
import sys
from bisect import bisect_left
from dataclasses import dataclass
from typing import List, Optional, Tuple

# -----------------------------
# helpers: run command
# -----------------------------
def run_cmd(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError("Command failed: " + " ".join(cmd) + "\nstdout:\n" + proc.stdout + "\nstderr:\n" + proc.stderr)
    return proc

# -----------------------------
# parse sizes like 1.00MiB 30.18TiB etc to bytes
# -----------------------------
_SIZE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]iB|B)\s*$")

_UNIT = {
    "B": 1,
    "KiB": 1024,
    "MiB": 1024**2,
    "GiB": 1024**3,
    "TiB": 1024**4,
    "PiB": 1024**5,
}

def parse_size_to_bytes(s: str) -> int:
    m = _SIZE_RE.match(s)
    if not m:
        raise ValueError(f"Unrecognized size token: {s!r}")
    val = float(m.group(1))
    unit = m.group(2)
    return int(val * _UNIT[unit])

# -----------------------------
# FIEMAP ioctl
# -----------------------------
# Linux fiemap structures:
# struct fiemap { __u64 fm_start; __u64 fm_length; __u32 fm_flags; __u32 fm_mapped_extents;
#                 __u32 fm_extent_count; __u32 fm_reserved; struct fiemap_extent fm_extents[...]; };
# struct fiemap_extent { __u64 fe_logical; __u64 fe_physical; __u64 fe_length; __u64 fe_reserved64[2];
#                        __u32 fe_flags; __u32 fe_reserved[3]; };

try:
    import fcntl  # type: ignore
except Exception:
    fcntl = None

# _IOWR('f', 11, struct fiemap)
# ioctl number varies by arch; easiest is hardcode Linux generic:
FIEMAP_IOCTL = 0xC020660B  # commonly correct on x86_64
FIEMAP_FLAG_SYNC = 0x00000001

FIEMAP_EXTENT_LAST = 0x00000001

@dataclass
class Extent:
    logical: int
    physical: int
    length: int
    flags: int

def fiemap_extents(path: str, max_extents: int = 512) -> List[Extent]:
    if fcntl is None:
        raise RuntimeError("fcntl not available; cannot use FIEMAP")

    # allocate buffer for fiemap + extents
    fiemap_header_fmt = "<QQIIII"  # start, length, flags, mapped, count, reserved
    fiemap_header_size = struct.calcsize(fiemap_header_fmt)

    fiemap_extent_fmt = "<QQQQQIIII"  # logical, physical, length, reserved64[0], reserved64[1], flags, reserved[0..2]
    fiemap_extent_size = struct.calcsize(fiemap_extent_fmt)

    buf = bytearray(fiemap_header_size + (max_extents * fiemap_extent_size))

    # start=0, length=all (~0), flags=SYNC, mapped=0, count=max_extents, reserved=0
    struct.pack_into(fiemap_header_fmt, buf, 0, 0, 0xFFFFFFFFFFFFFFFF, FIEMAP_FLAG_SYNC, 0, max_extents, 0)

    with open(path, "rb", buffering=0) as fd:
        fcntl.ioctl(fd.fileno(), FIEMAP_IOCTL, buf, True)

    start, length, flags, mapped, count, reserved = struct.unpack_from(fiemap_header_fmt, buf, 0)
    extents: List[Extent] = []
    for i in range(mapped):
        off = fiemap_header_size + (i * fiemap_extent_size)
        (fe_logical, fe_physical, fe_length, _r0, _r1, fe_flags, _r2, _r3, _r4) = struct.unpack_from(fiemap_extent_fmt, buf, off)
        extents.append(Extent(logical=fe_logical, physical=fe_physical, length=fe_length, flags=fe_flags))
        if fe_flags & FIEMAP_EXTENT_LAST:
            break
    return extents

# -----------------------------
# chunk layout parsing
# -----------------------------
@dataclass(frozen=True)
class Range:
    start: int
    end: int  # exclusive

def parse_list_chunks(mount_point: str, target_devids: List[int]) -> List[Range]:
    out = run_cmd(["btrfs", "inspect-internal", "list-chunks", mount_point]).stdout.splitlines()
    ranges: List[Range] = []

    # data lines start with spaces + digits
    for line in out:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if line.startswith("Devid"):
            continue
        if not re.match(r"^\s*\d+\s+\d+\s+", line):
            continue

        parts = line.split()
        # Expected columns:
        # Devid PNumber Type/profile PStart Length PEnd LNumber LStart Usage%
        # Example:
        # 4 1 Data/single 1.00MiB 1.00GiB 1.00GiB 1 30.18TiB 99.54
        try:
            devid = int(parts[0])
            if devid not in target_devids:
                continue
            lstart = parse_size_to_bytes(parts[7])
            length = parse_size_to_bytes(parts[4])
            ranges.append(Range(start=lstart, end=lstart + length))
        except Exception:
            # If format differs, ignore line rather than blow up; user can paste a sample for tweaks.
            continue

    if not ranges:
        raise RuntimeError("Parsed 0 target chunk ranges from list-chunks output (format mismatch or wrong devids).")

    # merge overlapping/adjacent ranges
    ranges.sort(key=lambda r: r.start)
    merged: List[Range] = []
    cur = ranges[0]
    for r in ranges[1:]:
        if r.start <= cur.end:
            cur = Range(cur.start, max(cur.end, r.end))
        else:
            merged.append(cur)
            cur = r
    merged.append(cur)
    return merged

def range_contains(ranges: List[Range], x: int) -> bool:
    # binary search on start
    starts = [r.start for r in ranges]
    i = bisect_left(starts, x)
    # candidate is i-1 (range start <= x)
    for j in (i, i - 1):
        if 0 <= j < len(ranges):
            r = ranges[j]
            if r.start <= x < r.end:
                return True
    return False

# -----------------------------
# main scanning
# -----------------------------
def iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            yield p

def logical_resolve_sample(mount_point: str, logical: int) -> Tuple[bool, str]:
    proc = subprocess.run(
        ["btrfs", "inspect-internal", "logical-resolve", str(logical), mount_point],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    ok = proc.returncode == 0 and proc.stdout.strip() != ""
    return ok, (proc.stdout.strip() if ok else proc.stderr.strip())

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mount", required=True, help="Mounted btrfs filesystem root, e.g. /mnt/datapool_btrfs")
    ap.add_argument("--start-dir", default=None, help="Optional subdir to start scanning under mount")
    ap.add_argument("--target-device", action="append", default=[], help="Block device path(s), e.g. /dev/sdi (optional)")
    ap.add_argument("--target-devid", action="append", type=int, default=[], help="Btrfs devid(s), e.g. 4 (optional)")
    ap.add_argument("--output", required=True, help="Output file list (paths) that touch target devids")
    ap.add_argument("--errors", required=True, help="Output error log file")
    ap.add_argument("--validate-every", type=int, default=50000, help="Every N files, validate 3 random samples via logical-resolve")
    args = ap.parse_args()

    mount_point = os.path.abspath(args.mount)
    scan_root = os.path.abspath(args.start_dir) if args.start_dir else mount_point

    if not os.path.isdir(mount_point):
        raise RuntimeError(f"--mount is not a directory: {mount_point}")

    # Determine target devids
    target_devids: List[int] = []
    if args.target_devid:
        target_devids = list(dict.fromkeys(args.target_devid))
    else:
        if not args.target_device:
            raise RuntimeError("Provide either --target-devid or --target-device (one or more).")

        # map /dev/XXX -> devid using `btrfs filesystem show`
        show = run_cmd(["btrfs", "filesystem", "show", mount_point]).stdout.splitlines()
        dev_to_devid = {}
        # Lines look like: "devid    4 size ... used ... path /dev/sdi"
        for line in show:
            m = re.search(r"devid\s+(\d+)\s+.*\s+path\s+(\S+)\s*$", line)
            if m:
                devid = int(m.group(1))
                dev = m.group(2)
                dev_to_devid[os.path.realpath(dev)] = devid

        for dev in args.target_device:
            rp = os.path.realpath(dev)
            if rp not in dev_to_devid:
                raise RuntimeError(f"Could not map target device to devid via `btrfs filesystem show`: {dev} (realpath {rp})")
            target_devids.append(dev_to_devid[rp])

        target_devids = list(dict.fromkeys(target_devids))

    print(f"Target devids: {target_devids}", file=sys.stderr)
    print("Parsing chunk layout (list-chunks)...", file=sys.stderr)
    target_ranges = parse_list_chunks(mount_point, target_devids)
    print(f"Target chunk ranges: {len(target_ranges)} merged ranges", file=sys.stderr)

    total = 0
    hits = 0
    inline_or_unmappable = 0
    hard_errors = 0
    samples_with_extents: List[Tuple[str, int]] = []

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.errors)), exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as outf, open(args.errors, "w", encoding="utf-8") as errf:
        for path in iter_files(scan_root):
            total += 1
            try:
                st = os.lstat(path)
                if not os.path.isfile(path) or os.path.islink(path):
                    continue

                exts = fiemap_extents(path, max_extents=512)
                if not exts:
                    # likely inline extent or special case; cannot attribute to a single data device
                    inline_or_unmappable += 1
                else:
                    # On btrfs, fiemap "physical" is effectively the filesystem logical bytenr for logical-resolve/chunk mapping.
                    # We test "physical" against list-chunks LStart ranges.
                    hit = False
                    for e in exts:
                        if range_contains(target_ranges, e.physical):
                            hit = True
                            break
                    if hit:
                        hits += 1
                        outf.write(path + "\n")

                    # keep sample candidates for validation
                    if len(samples_with_extents) < 1000:
                        samples_with_extents.append((path, exts[0].physical))
                    else:
                        # reservoir-ish
                        if random.random() < 0.0005:
                            samples_with_extents[random.randrange(len(samples_with_extents))] = (path, exts[0].physical)

            except Exception as e:
                hard_errors += 1
                errf.write(f"{path}\t{repr(e)}\n")

            if total % 10000 == 0:
                rate_note = f"Checked {total} files, hits {hits}, inline/unmappable {inline_or_unmappable}, errors {hard_errors}"
                print(rate_note, file=sys.stderr)

            if args.validate_every > 0 and total % args.validate_every == 0:
                print(f"Validation checkpoint at {total} files (sampling 3)", file=sys.stderr)
                # choose 3 samples that actually had extents
                candidates = [s for s in samples_with_extents if s[1] > 0]
                for _ in range(3):
                    if not candidates:
                        print("  no extent samples available yet", file=sys.stderr)
                        break
                    p, logical = random.choice(candidates)
                    ok, msg = logical_resolve_sample(mount_point, logical)
                    if ok:
                        print(f"  sample OK: {p} -> logical {logical} resolves to {msg.splitlines()[0]}", file=sys.stderr)
                    else:
                        # This can legitimately fail sometimes (RO/degraded + missing device), but we want to see it.
                        print(f"  sample FAIL: {p} -> logical {logical} logical-resolve failed: {msg[:200]}", file=sys.stderr)

    print(f"Done. Checked {total} files; hits {hits}; inline/unmappable {inline_or_unmappable}; errors {hard_errors}.", file=sys.stderr)
    print(f"Results written to {args.output}", file=sys.stderr)
    print(f"Errors written to {args.errors}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

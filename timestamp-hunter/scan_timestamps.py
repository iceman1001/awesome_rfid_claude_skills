#!/usr/bin/env python3
"""
scan_timestamps.py — scan a byte array for embedded date/time values.

Tries many common timestamp encodings (binary integer/float and textual)
and reports offsets where plausible dates are found. Handles both
endiannesses. Uses a plausibility year range to suppress random-noise
matches, and warns when hit density still suggests false positives.

Input: a file path, a --hex string, a --base64 string, or stdin (-).
Output: human-readable text (default) or --json.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import re
import struct
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

# ---- Epoch anchors (all UTC) ------------------------------------------------

EPOCH_UNIX     = datetime(1970,  1,  1, tzinfo=timezone.utc)
EPOCH_FILETIME = datetime(1601,  1,  1, tzinfo=timezone.utc)
EPOCH_HFS      = datetime(1904,  1,  1, tzinfo=timezone.utc)
EPOCH_NSDATE   = datetime(2001,  1,  1, tzinfo=timezone.utc)
EPOCH_OLE      = datetime(1899, 12, 30, tzinfo=timezone.utc)
EPOCH_GPS      = datetime(1980,  1,  6, tzinfo=timezone.utc)


@dataclass
class Finding:
    offset: int
    length: int
    format: str
    datetime: str        # ISO 8601 rendering of the decoded value
    raw: str             # repr of the raw value (int, hex, or text)
    approximate: bool = False  # True for text matches in non-ASCII encodings

    def line(self) -> str:
        approx = " ~" if self.approximate else "  "
        return f"0x{self.offset:08x} ({self.offset:>10}) +{self.length}{approx} {self.format:<22} {self.datetime}   [{self.raw}]"


# ---- Helpers ----------------------------------------------------------------

def _safe_epoch_add(epoch: datetime, seconds: float) -> datetime | None:
    """Add `seconds` to `epoch`, returning None on overflow / bad values."""
    if not math.isfinite(seconds):
        return None
    # datetime tops out near year 9999; reject extreme values before arithmetic
    if abs(seconds) > 1e11:
        return None
    try:
        return epoch + timedelta(seconds=seconds)
    except (OverflowError, OSError, ValueError):
        return None


def _in_window(dt: datetime, min_year: int, max_year: int) -> bool:
    return min_year <= dt.year <= max_year


# ---- Binary scanners --------------------------------------------------------
# Each scanner yields Finding objects. `aligned=True` restricts offsets to
# multiples of the field size, which massively reduces noise when scanning
# structured binaries (PE/ELF/MachO/filesystem images/etc).

def scan_unix32(data: bytes, min_year: int, max_year: int, aligned: bool) -> Iterable[Finding]:
    step = 4 if aligned else 1
    end = len(data) - 3
    for off in range(0, end, step):
        chunk = data[off:off + 4]
        for endian, fmt in (("LE", "<I"), ("BE", ">I")):
            (val,) = struct.unpack(fmt, chunk)
            if val == 0:
                continue
            dt = _safe_epoch_add(EPOCH_UNIX, val)
            if dt and _in_window(dt, min_year, max_year):
                yield Finding(off, 4, f"unix32-{endian}", dt.isoformat(), str(val))


def scan_unix64(data: bytes, min_year: int, max_year: int, aligned: bool) -> Iterable[Finding]:
    step = 8 if aligned else 1
    end = len(data) - 7
    for off in range(0, end, step):
        chunk = data[off:off + 8]
        for endian, fmt in (("LE", "<Q"), ("BE", ">Q")):
            (val,) = struct.unpack(fmt, chunk)
            if val == 0:
                continue
            # Seconds since epoch
            dt = _safe_epoch_add(EPOCH_UNIX, val)
            if dt and _in_window(dt, min_year, max_year):
                yield Finding(off, 8, f"unix64-s-{endian}", dt.isoformat(), str(val))
            # Milliseconds since epoch (common in Java / JS)
            dt = _safe_epoch_add(EPOCH_UNIX, val / 1000.0)
            if dt and _in_window(dt, min_year, max_year):
                yield Finding(off, 8, f"unix64-ms-{endian}", dt.isoformat(), str(val))


def scan_filetime(data: bytes, min_year: int, max_year: int, aligned: bool) -> Iterable[Finding]:
    """Windows FILETIME: 100-ns intervals since 1601-01-01 UTC."""
    step = 8 if aligned else 1
    end = len(data) - 7
    for off in range(0, end, step):
        chunk = data[off:off + 8]
        for endian, fmt in (("LE", "<Q"), ("BE", ">Q")):
            (val,) = struct.unpack(fmt, chunk)
            if val == 0:
                continue
            dt = _safe_epoch_add(EPOCH_FILETIME, val / 10_000_000)
            if dt and _in_window(dt, min_year, max_year):
                yield Finding(off, 8, f"filetime-{endian}", dt.isoformat(), f"0x{val:016x}")


def scan_nsdate(data: bytes, min_year: int, max_year: int, aligned: bool) -> Iterable[Finding]:
    """Apple NSDate / CFAbsoluteTime: IEEE 754 double, seconds since 2001-01-01."""
    step = 8 if aligned else 1
    end = len(data) - 7
    # Plausible values: seconds since 2001, roughly [-1e9, 2e9].
    # Reject tiny values (denormals, small ints that look like zero) so we
    # don't report thousands of "2001-01-01T00:00:00" from near-zero floats.
    MIN_MAG = 60.0          # at least a minute from epoch
    MAX_MAG = 2.0e9         # ~63 years either side
    for off in range(0, end, step):
        chunk = data[off:off + 8]
        for endian, fmt in (("LE", "<d"), ("BE", ">d")):
            try:
                (val,) = struct.unpack(fmt, chunk)
            except struct.error:
                continue
            if not math.isfinite(val):
                continue
            absv = abs(val)
            if absv < MIN_MAG or absv > MAX_MAG:
                continue
            dt = _safe_epoch_add(EPOCH_NSDATE, val)
            if dt and _in_window(dt, min_year, max_year):
                yield Finding(off, 8, f"nsdate-{endian}", dt.isoformat(), f"{val!r}")


def scan_ole_date(data: bytes, min_year: int, max_year: int, aligned: bool) -> Iterable[Finding]:
    """OLE Automation date: IEEE 754 double, days since 1899-12-30."""
    step = 8 if aligned else 1
    end = len(data) - 7
    # Plausible days-since-1899: ~0 to ~50000. Tight float bounds kill noise.
    MIN_MAG = 1.0
    MAX_MAG = 1.0e5
    for off in range(0, end, step):
        chunk = data[off:off + 8]
        for endian, fmt in (("LE", "<d"), ("BE", ">d")):
            try:
                (val,) = struct.unpack(fmt, chunk)
            except struct.error:
                continue
            if not math.isfinite(val):
                continue
            absv = abs(val)
            if absv < MIN_MAG or absv > MAX_MAG:
                continue
            dt = _safe_epoch_add(EPOCH_OLE, val * 86400)
            if dt and _in_window(dt, min_year, max_year):
                yield Finding(off, 8, f"ole-date-{endian}", dt.isoformat(), f"{val!r}")


def scan_hfs(data: bytes, min_year: int, max_year: int, aligned: bool) -> Iterable[Finding]:
    """HFS / HFS+ / classic Mac: 32-bit seconds since 1904-01-01."""
    step = 4 if aligned else 1
    end = len(data) - 3
    for off in range(0, end, step):
        chunk = data[off:off + 4]
        for endian, fmt in (("LE", "<I"), ("BE", ">I")):
            (val,) = struct.unpack(fmt, chunk)
            if val == 0:
                continue
            dt = _safe_epoch_add(EPOCH_HFS, val)
            if dt and _in_window(dt, min_year, max_year):
                yield Finding(off, 4, f"hfs-{endian}", dt.isoformat(), str(val))


def scan_dos(data: bytes, min_year: int, max_year: int, aligned: bool) -> Iterable[Finding]:
    """DOS date+time (MS-DOS / ZIP / FAT).

    Two 16-bit words. DATE = YYYYYYYMMMMDDDDD (year = 1980 + Y, 7 bits),
    TIME = HHHHHMMMMMMSSSSS (seconds stored as /2). Word order varies, so
    we try both (time,date) and (date,time) layouts.
    """
    step = 4 if aligned else 1
    end = len(data) - 3
    for off in range(0, end, step):
        for endian, fmt in (("LE", "<HH"), ("BE", ">HH")):
            w1, w2 = struct.unpack(fmt, data[off:off + 4])
            for (date_raw, time_raw, order) in ((w2, w1, "td"), (w1, w2, "dt")):
                year   = ((date_raw >> 9) & 0x7F) + 1980
                month  = (date_raw >> 5) & 0x0F
                day    = date_raw & 0x1F
                hour   = (time_raw >> 11) & 0x1F
                minute = (time_raw >> 5)  & 0x3F
                second = (time_raw & 0x1F) * 2
                if not (1 <= month <= 12 and 1 <= day <= 31
                        and 0 <= hour < 24 and 0 <= minute < 60 and 0 <= second < 60):
                    continue
                if not (min_year <= year <= max_year):
                    continue
                try:
                    dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
                except ValueError:
                    continue  # e.g. Feb 30
                yield Finding(
                    off, 4, f"dos-{endian}-{order}", dt.isoformat(),
                    f"date=0x{date_raw:04x} time=0x{time_raw:04x}",
                )


def scan_gps(data: bytes, min_year: int, max_year: int, aligned: bool) -> Iterable[Finding]:
    """GPS time: 32-bit seconds since 1980-01-06 (ignoring leap seconds)."""
    step = 4 if aligned else 1
    end = len(data) - 3
    for off in range(0, end, step):
        chunk = data[off:off + 4]
        for endian, fmt in (("LE", "<I"), ("BE", ">I")):
            (val,) = struct.unpack(fmt, chunk)
            if val == 0:
                continue
            dt = _safe_epoch_add(EPOCH_GPS, val)
            if dt and _in_window(dt, min_year, max_year):
                yield Finding(off, 4, f"gps-{endian}", dt.isoformat(), str(val))


# ---- Text scanners ----------------------------------------------------------

_TEXT_PATTERNS: list[tuple[re.Pattern[bytes], str]] = [
    (re.compile(
        rb"\b(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
        rb"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
    ), "ISO-8601"),
    (re.compile(
        rb"\b(\d{4})-(\d{2})-(\d{2})\b"
    ), "ISO-date"),
    (re.compile(
        rb"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{1,2} "
        rb"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
        rb"\d{4} \d{2}:\d{2}:\d{2}(?:\s+(?:GMT|UTC|[+-]\d{4}))?"
    ), "RFC2822"),
    (re.compile(
        rb"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
        rb"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} "
        rb"\d{2}:\d{2}:\d{2} \d{4}"
    ), "unix-date"),
]


def _extract_year(s: str) -> int | None:
    m = re.search(r"\d{4}", s)
    return int(m.group()) if m else None


def scan_text_ascii(data: bytes, min_year: int, max_year: int) -> Iterable[Finding]:
    for pattern, name in _TEXT_PATTERNS:
        for m in pattern.finditer(data):
            text = m.group(0).decode("ascii", errors="replace")
            y = _extract_year(text)
            if y is not None and not (min_year <= y <= max_year):
                continue
            yield Finding(m.start(), m.end() - m.start(),
                          f"text-{name}-ascii", text, text)


def scan_text_utf16(data: bytes, min_year: int, max_year: int) -> Iterable[Finding]:
    """Look for the same patterns in UTF-16 LE/BE.

    Implementation trick: decode the whole buffer, run the ASCII regex on
    the decoded text's utf-8 form, then approximate the byte offset as
    char_index * 2. Accurate enough to locate the match for the user.
    """
    for encoding, tag in (("utf-16-le", "utf16le"), ("utf-16-be", "utf16be")):
        try:
            decoded = data.decode(encoding, errors="replace")
        except Exception:
            continue
        decoded_bytes = decoded.encode("utf-8", errors="replace")
        for pattern, name in _TEXT_PATTERNS:
            for m in pattern.finditer(decoded_bytes):
                text = m.group(0).decode("utf-8", errors="replace")
                y = _extract_year(text)
                if y is not None and not (min_year <= y <= max_year):
                    continue
                # Map utf-8 byte offset → char index → utf-16 byte offset
                char_start = len(decoded_bytes[:m.start()].decode("utf-8", errors="replace"))
                byte_offset = char_start * 2
                byte_len = (m.end() - m.start()) * 2  # rough for ASCII-in-UTF16
                yield Finding(byte_offset, byte_len,
                              f"text-{name}-{tag}", text, text, approximate=True)


# ---- Driver -----------------------------------------------------------------

ALL_BINARY_SCANNERS = [
    scan_unix32, scan_unix64, scan_filetime,
    scan_nsdate, scan_ole_date, scan_hfs, scan_dos, scan_gps,
]


def scan_all(data: bytes, min_year: int, max_year: int, aligned: bool,
             skip_formats: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for fn in ALL_BINARY_SCANNERS:
        name = fn.__name__.replace("scan_", "")
        if name in skip_formats:
            continue
        findings.extend(fn(data, min_year, max_year, aligned))
    if "text" not in skip_formats:
        findings.extend(scan_text_ascii(data, min_year, max_year))
        findings.extend(scan_text_utf16(data, min_year, max_year))
    findings.sort(key=lambda f: (f.offset, f.format))
    return findings


def load_input(args: argparse.Namespace) -> bytes:
    if args.hex is not None:
        clean = re.sub(r"\s+", "", args.hex)
        if clean.startswith(("0x", "0X")):
            clean = clean[2:]
        return bytes.fromhex(clean)
    if args.base64 is not None:
        return base64.b64decode(args.base64, validate=False)
    if args.input == "-" or args.input is None and not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    if args.input is None:
        sys.exit("error: no input provided. Give a file path, --hex, --base64, or pipe to stdin.")
    path = Path(args.input)
    if not path.exists():
        sys.exit(f"error: file not found: {path}")
    return path.read_bytes()


def print_text_report(data: bytes, findings: list[Finding], args: argparse.Namespace) -> None:
    by_format: dict[str, int] = {}
    for f in findings:
        by_format[f.format] = by_format.get(f.format, 0) + 1

    print(f"Scanned {len(data):,} bytes. Found {len(findings)} candidate timestamp(s).")
    print(f"Plausibility window: {args.min_year}–{args.max_year}. Aligned mode: {args.aligned}.")
    print()

    # Noise warnings: flag formats whose hit count looks like random-data density.
    # For unix32 on any buffer, unaligned, the expected random rate is
    # roughly (year_window_seconds / 2^32) per byte * 2 endians.
    if not args.aligned and len(data) >= 64:
        window_seconds = (args.max_year - args.min_year) * 365.25 * 86400
        expected_rate = (window_seconds / 2**32) * 2  # two endianness attempts
        expected_unix32 = expected_rate * max(0, len(data) - 3)
        actual = by_format.get("unix32-LE", 0) + by_format.get("unix32-BE", 0)
        if expected_unix32 >= 1 and actual >= max(10, 0.5 * expected_unix32):
            print(f"! Warning: {actual} unix32 hits at this density looks like "
                  f"random-data noise (expected ~{expected_unix32:.0f} from random "
                  f"bytes in {len(data)} bytes). Re-run with --aligned or a "
                  f"narrower --min-year/--max-year window for cleaner results.")
            print()

    if by_format:
        print("By format:")
        for fmt, n in sorted(by_format.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {fmt:<26} {n}")
        print()

    if findings:
        print("Findings (offset_hex (offset_dec) +len  format  datetime  [raw]):")
        limit = args.limit
        for f in findings[:limit]:
            print(f.line())
        if len(findings) > limit:
            print(f"... and {len(findings) - limit} more (raise --limit or use --json).")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", nargs="?", help="path to binary file, or '-' for stdin")
    parser.add_argument("--hex", help="input as hex string (whitespace ignored)")
    parser.add_argument("--base64", help="input as base64 string")
    parser.add_argument("--min-year", type=int, default=2000,
                        help="earliest plausible year (default: 2000). Lower this if analyzing "
                             "old artifacts; raise it to reduce noise.")
    parser.add_argument("--max-year", type=int, default=2035,
                        help="latest plausible year (default: 2035)")
    parser.add_argument("--aligned", action="store_true",
                        help="only check offsets aligned to the field size. "
                             "Massively reduces false positives in structured binaries.")
    parser.add_argument("--skip", action="append", default=[],
                        help="skip a scanner (e.g. --skip unix32 --skip dos). "
                             "Options: unix32 unix64 filetime nsdate ole_date hfs dos gps text")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--limit", type=int, default=200,
                        help="max findings to print in text mode (default: 200)")
    args = parser.parse_args()

    data = load_input(args)
    findings = scan_all(data, args.min_year, args.max_year, args.aligned, set(args.skip))

    if args.json:
        out = {
            "bytes_scanned": len(data),
            "min_year": args.min_year,
            "max_year": args.max_year,
            "aligned": args.aligned,
            "skipped": args.skip,
            "findings": [asdict(f) for f in findings],
        }
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print_text_report(data, findings, args)


if __name__ == "__main__":
    main()

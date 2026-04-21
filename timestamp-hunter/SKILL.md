---
name: timestamp-hunter
description: Scan a byte array, binary file, hex string, or base64 blob for embedded date/time values across many encodings (unix32/64, unix-ms, Windows FILETIME, Apple NSDate, OLE date, HFS, DOS date-time, GPS time, and textual ISO-8601/RFC-2822) in both endiannesses. Use any time the user gives Claude raw bytes, a binary file, hex dump, memory dump, packet capture, firmware, or unknown binary blob and wants to know when it was created, what dates are in it, or whether it has timestamps. Trigger on phrases like "find dates in this", "are there timestamps", "when was this made", "what's in this binary", "decode these bytes", "reverse engineer this file", "what are these 8 bytes" — even if the user does not say "timestamp". Also trigger for forensics, malware analysis, and firmware reversing tasks. Do NOT trigger for text-only inputs where dates are already visible.
---

# timestamp-hunter

Scans a byte array for embedded dates and times across many common encodings. Because there are a dozen-plus ways to store a timestamp in binary, and each has two endiannesses, this is the kind of task where a deterministic scanner is far more reliable than eyeballing hex.

## When to use this skill

Any task where the user has binary data (file, hex, base64, packet capture, memory dump, firmware image, unknown blob) and any of these would be useful:

- Finding when the data was created, modified, or built
- Identifying embedded log timestamps or event records
- Recognizing a file format by its timestamp fields
- Forensic or malware analysis (compile times, certificate dates, etc.)
- Reverse-engineering a binary protocol
- Just "what's in this?" investigation

If the user pastes hex or base64 inline rather than uploading a file, still run the scanner — pass the input via `--hex` or `--base64`.

If the input is a plain text file where dates would be visible as readable strings, don't bother with this skill — just grep.

## What the scanner covers

Binary integer / float formats (both endiannesses):

| Format | Size | Epoch | Notes |
|---|---|---|---|
| `unix32` | 4B | 1970-01-01 | Classic Unix `time_t`. Highest false-positive rate of any format (see noise warnings). |
| `unix64-s` | 8B | 1970-01-01 | 64-bit Unix seconds. |
| `unix64-ms` | 8B | 1970-01-01 | Milliseconds — common in Java, JS, MongoDB. |
| `filetime` | 8B | 1601-01-01 | Windows `FILETIME`, 100-ns ticks. Low false positives. |
| `nsdate` | 8B | 2001-01-01 | Apple `NSDate` / `CFAbsoluteTime`, IEEE 754 double, seconds. |
| `ole-date` | 8B | 1899-12-30 | Microsoft OLE Automation date, IEEE 754 double, days. |
| `hfs` | 4B | 1904-01-01 | HFS / HFS+ / classic Mac. |
| `dos` | 4B | 1980-01-01 | MS-DOS / FAT / ZIP bit-packed date-time. |
| `gps` | 4B | 1980-01-06 | GPS time (leap seconds ignored). |

Text formats (ASCII and UTF-16 LE/BE):

- ISO 8601 (`2024-06-15T10:30:45Z`, with or without fractional seconds and timezone)
- ISO date only (`2024-06-15`)
- RFC 2822 / HTTP date (`Wed, 15 Jun 2024 10:30:45 GMT`)
- Unix `date` output (`Wed Jun 15 10:30:45 2024`)

## How to invoke

The scanner lives at `scripts/scan_timestamps.py` (stdlib Python, no dependencies).

**Scan a file:**

```bash
python3 scripts/scan_timestamps.py path/to/file.bin
```

**Scan a hex string** (whitespace and `0x` prefix are ignored):

```bash
python3 scripts/scan_timestamps.py --hex "80f87c140fbfda01 01000000"
```

**Scan a base64 blob:**

```bash
python3 scripts/scan_timestamps.py --base64 "gPh8FA+/2gE="
```

**Pipe bytes in on stdin:**

```bash
cat file.bin | python3 scripts/scan_timestamps.py -
```

## Recommended workflow

Start with default settings to get a lay of the land, then tighten based on what you see:

```bash
python3 scripts/scan_timestamps.py file.bin
```

If the output warns about random-data noise, or you see thousands of `unix32` hits that span every offset, try one or more of these:

1. **`--aligned`** — only checks offsets divisible by the field size (e.g., unix32 at offsets 0, 4, 8, …). This is correct for structured binaries: file headers, network packets, databases, protocol buffers, serialized structs. It cuts noise by ~4×.
2. **`--min-year` / `--max-year`** — narrow the plausibility window. Defaults are `2000–2035`. If the artifact is from a known era (e.g., "this firmware is from 2018"), use `--min-year 2017 --max-year 2019`. This is the single most effective knob for killing false positives.
3. **`--skip unix32 --skip hfs --skip gps --skip dos`** — drop the noisy 32-bit formats. Use this to see only the structurally-distinctive 8-byte formats (FILETIME, NSDate, OLE date, unix64) plus text. These have dramatically lower false-positive rates.

Available `--skip` values: `unix32`, `unix64`, `filetime`, `nsdate`, `ole_date`, `hfs`, `dos`, `gps`, `text`.

**`--json`** emits structured output for further processing. Prefer this when the caller is going to consume the findings programmatically.

**`--limit N`** raises the cap on how many findings are shown in text mode (default 200). Use `--json` if you need all of them.

## Interpreting results

Each finding line looks like:

```
0x00000400 (      1024) +8   filetime-LE            2024-06-15T10:30:45+00:00   [0x01dabf0f147cf880]
```

Columns: hex offset, decimal offset, field length, format tag, decoded UTC datetime, raw value.

The `~` marker after the length indicates a text match found via UTF-16 decoding, where the byte offset is approximate (accurate to within a few bytes, not exact).

**Expect overlapping interpretations.** An 8-byte FILETIME value will also decode its first 4 bytes as a (wrong) unix32 and its last 4 bytes as another (wrong) unix32. Don't try to suppress these — the alternate readings are useful context. When the user asks "what is this timestamp at offset X", show them all the interpretations and let the surrounding context decide. For example: a timestamp inside a PE file header at a 4-byte-aligned offset is much more likely to be `unix32` than `hfs-BE` of the same bytes.

**Cross-check implausible-looking results.** If a scan turns up a single clean FILETIME at a file-header-ish offset (e.g., 0x80, 0x3C) and nothing else, that's usually a real timestamp. If a scan turns up 50 unix32 hits spread evenly across the file, that's noise.

## What to tell the user

Start with a one-sentence summary of the most likely real timestamps, then offer the fuller scan if relevant. For example:

> "Three plausible embedded timestamps: a Windows FILETIME at offset 0x80 reading 2024-06-15 10:30 UTC (likely compile time), and two ASCII ISO-8601 strings at 0x3F0 and 0x410 reading 2024-06-14 and 2024-06-16 (likely embedded log entries). There are also ~180 other candidate unix32 matches, but the density suggests they're incidental matches against random bytes rather than real timestamps."

If the scan is inconclusive (many hits, no clear winners), say so and suggest narrowing flags rather than guessing.

## Limitations to be honest about

- **False positives are unavoidable for 32-bit formats.** A plausible-looking unix32 in an isolated 4-byte window is usually noise. Prefer the 8-byte formats (FILETIME, NSDate, OLE date, unix64-ms) as high-confidence signal.
- **Timezone information is lost.** All decoded datetimes are shown in UTC. If the source stored a local time without TZ info (common in filesystems like FAT), the real wall-clock time may be off by a few hours.
- **Leap seconds are ignored** for GPS time — the reported value can be off by ~18 seconds as of 2024.
- **The UTF-16 text scanner uses approximate offsets.** They're good enough to locate the match by eye, not for byte-exact work.
- **Custom / proprietary formats aren't covered.** e.g., IBM System z timestamps, Cisco NetFlow times, Chrome/WebKit times (microseconds since 1601). Ask the user what they suspect if the scanner comes up empty.

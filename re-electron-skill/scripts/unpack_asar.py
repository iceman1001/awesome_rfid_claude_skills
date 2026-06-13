#!/usr/bin/env python3
"""Extract Electron ASAR archives without npx dependency.

ASAR format: Electron Archive — a tar-like format with JSON header.
This is a minimal extractor; for full ASAR support use @electron/asar.
"""

import json
import os
import struct
import sys
from pathlib import Path


def read_int(f, size=4):
    return struct.unpack("<I", f.read(size))[0]


def extract_asar(asar_path: str, output_dir: str) -> int:
    """Extract an ASAR archive to output_dir. Returns number of files extracted."""
    asar_path = Path(asar_path)
    output_dir = Path(output_dir)

    if not asar_path.exists():
        print(f"[!] ASAR file not found: {asar_path}")
        return 0

    with open(asar_path, "rb") as f:
        # Read header
        header_size_raw = f.read(4)
        if len(header_size_raw) < 4:
            # Try offset 4 (some ASARs have a 4-byte padding)
            f.seek(0)
            header = f.read(8)
            if header[:4] == b"\x04\x00\x00\x00":
                header_size_raw = header[4:8]
            else:
                print("[!] Invalid ASAR: too small")
                return 0

        header_size = struct.unpack("<I", header_size_raw)[0]
        header_padding = 4 + 4  # size field + reserved field

        # Read header JSON
        header_bytes = f.read(header_size - header_padding)
        header_str = header_bytes.decode("utf-8", errors="replace")
        header_json_start = header_str.index("{")
        header_str = header_str[header_json_start:]

        try:
            header = json.loads(header_str)
        except json.JSONDecodeError:
            print("[!] Failed to parse ASAR header JSON")
            print(f"    Header prefix: {header_str[:200]}")
            return 0

        base_offset = f.tell()

        count = 0

        def extract_files(node: dict, current_base: int):
            nonlocal count
            files = node.get("files", {})
            for name, info in files.items():
                file_path = output_dir / name
                if "files" in info:
                    # Directory
                    file_path.mkdir(parents=True, exist_ok=True)
                    extract_files(info, current_base)
                elif "offset" in info:
                    # File
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    offset = current_base + int(info["offset"])
                    size = int(info["size"])
                    f.seek(offset)
                    data = f.read(size)
                    file_path.write_bytes(data)
                    count += 1
                # Skip "unpacked" files — they're stored externally

        extract_files(header, base_offset)

    print(f"[+] Extracted {count} files to {output_dir}")
    return count


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: unpack_asar.py <app.asar> <output_dir>")
        sys.exit(1)

    extract_asar(sys.argv[1], sys.argv[2])

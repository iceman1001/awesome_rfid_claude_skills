#!/usr/bin/env python3
"""
rigol_screenshot.py -- grab a Rigol scope display hardcopy over LXI and save a real
PNG, in ONE flow.

The Rigol hardcopy (`lxi screenshot`) is a BMP regardless of the file extension you
give it, so every caller otherwise has to notice "this .png is actually a BMP" and
convert it by hand. This grabs the BMP and converts it to a true PNG in one call.

Output goes to a per-label folder (default ./rigol/). A bare filename lands in that
folder; use --dir to pick another label ("runA" -> ./runA/) or an explicit path;
or pass a path that already contains a directory and it is used as-is.

Examples:
  ./rigol_screenshot.py                         # -> ./rigol/rigol_screenshot.png
  ./rigol_screenshot.py boot.png                # -> ./rigol/boot.png
  ./rigol_screenshot.py boot.png --dir runA     # -> ./runA/boot.png
  ./rigol_screenshot.py shots/run.png           # explicit path -> used as-is
  ./rigol_screenshot.py --scope-ip 10.0.0.10 --timeout 20

Importable (used by rigol.py / rigol_scope_live.py):
  from rigol_screenshot import grab_png
  grab_png("10.0.0.10", "/path/capture.png")    # writes a true PNG, returns the path
"""
import argparse
import os
import subprocess
import sys
import tempfile

from rigol_colors import ColorHelpFormatter
from rigol_pathhelper import resolve_outdir   # shared per-label output-folder helper

SCOPE_IP_DEFAULT = "10.0.0.10"


def grab_png(scope_ip, out_path, timeout=15):
    """Capture the Rigol display and write a TRUE PNG to out_path (extension forced to
    .png; parent dir created if needed). Grabs a temp .bmp via `lxi screenshot`, then
    converts with Pillow. Returns the final path; raises RuntimeError on capture
    failure."""
    out_path = os.path.splitext(out_path)[0] + ".png"
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd, bmp = tempfile.mkstemp(suffix=".bmp")
    os.close(fd)
    try:
        r = subprocess.run(["lxi", "screenshot", "-a", scope_ip, "-t", str(timeout), bmp],
                           capture_output=True, text=True)
        if r.returncode != 0 or not os.path.getsize(bmp):
            raise RuntimeError(f"lxi screenshot failed: {r.stderr.strip() or 'empty file'}")
        from PIL import Image
        with Image.open(bmp) as img:
            img.load()
            img.save(out_path, "PNG")
    finally:
        try:
            os.remove(bmp)
        except OSError:
            pass
    return out_path


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=ColorHelpFormatter)
    ap.add_argument("out", nargs="?", default="rigol_screenshot.png", help="output filename or path (ext forced to .png; default: rigol_screenshot.png)")
    ap.add_argument("--dir", default=None, help="destination folder for a bare filename: a label (./<name>/) or a path (default: ./rigol/)")
    ap.add_argument("--scope-ip", default=SCOPE_IP_DEFAULT, help=f"Rigol scope IP (lxi, default {SCOPE_IP_DEFAULT})")
    ap.add_argument("--timeout", type=int, default=15, help="lxi capture timeout, s (default 15)")
    a = ap.parse_args()

    out = a.out
    if not os.path.dirname(out):                       # bare filename -> destination folder
        out = os.path.join(resolve_outdir(a.dir), out)
    try:
        print(f"saved {grab_png(a.scope_ip, out, a.timeout)}")
    except Exception as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()

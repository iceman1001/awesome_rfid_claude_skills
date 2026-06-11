#!/usr/bin/env python3
"""Shared output-folder helper for the rigol-scope scripts.

Captures, CSV dumps and screenshots are written into a per-label folder next to
these scripts (default ./rigol/), so the skill directory stays clean and each
run/session can have its own folder.
"""
import os


def project_dir(name="rigol"):
    """Return (creating on demand) the output folder `<script_dir>/<name>/`."""
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    os.makedirs(d, exist_ok=True)
    return d

def resolve_outdir(dest=None):
    """Resolve a destination folder (created on demand):
      None / ""        -> the default output folder (./rigol/),
      a bare name      -> ./<name>/  (e.g. "runA"),
      a path           -> that path (relative to cwd, or absolute)."""
    if not dest:
        return project_dir()
    if os.path.isabs(dest) or os.sep in dest or (os.altsep and os.altsep in dest):
        os.makedirs(dest, exist_ok=True)
        return dest
    return project_dir(dest)

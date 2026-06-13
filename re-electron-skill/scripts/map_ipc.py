#!/usr/bin/env python3
"""Map IPC channels across Electron main and renderer processes.

Usage: map_ipc.py <unpacked_app_dir> [--format table|json|mermaid]

Analyzes all .js files in the unpacked app directory, finds ipcMain.handle(),
ipcRenderer.invoke(), contextBridge.exposeInMainWorld() calls, and produces
a cross-reference table or Mermaid diagram of the IPC surface.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path


IPC_PATTERNS = {
    # Main process
    "main_handle": re.compile(r'ipcMain\.handle\s*\(\s*["\']([^"\']+)["\']'),
    "main_on": re.compile(r'ipcMain\.on\s*\(\s*["\']([^"\']+)["\']'),
    "main_removeHandler": re.compile(r'ipcMain\.removeHandler\s*\(\s*["\']([^"\']+)["\']'),
    # Renderer process
    "renderer_invoke": re.compile(r'ipcRenderer\.invoke\s*\(\s*["\']([^"\']+)["\']'),
    "renderer_send": re.compile(r'ipcRenderer\.send\s*\(\s*["\']([^"\']+)["\']'),
    "renderer_on": re.compile(r'ipcRenderer\.on\s*\(\s*["\']([^"\']+)["\']'),
    "renderer_sendSync": re.compile(r'ipcRenderer\.sendSync\s*\(\s*["\']([^"\']+)["\']'),
    # Context bridge
    "context_bridge": re.compile(r'contextBridge\.exposeInMainWorld\s*\(\s*["\']([^"\']+)["\']'),
    # webContents
    "webcontents_send": re.compile(r'webContents\.send\s*\(\s*["\']([^"\']+)["\']'),
}


def scan_ipc(root: Path) -> dict:
    """Scan all JS files for IPC channel usage."""
    channels = defaultdict(lambda: {
        "main": {"handle": [], "on": [], "removeHandler": []},
        "renderer": {"invoke": [], "send": [], "on": [], "sendSync": []},
        "files": {"main": [], "renderer": []},
        "context_bridge_exposures": [],
        "webcontents_send": [],
    })

    is_main = False
    is_renderer = False

    for js_file in root.rglob("*.js"):
        if js_file.stat().st_size < 500:
            continue

        rel = str(js_file.relative_to(root))

        # Determine process type
        if "main" in rel.lower() or "main" in str(js_file.parent).lower():
            is_main = True
            is_renderer = False
        elif "renderer" in rel.lower() or "renderer" in str(js_file.parent).lower():
            is_main = False
            is_renderer = True
        else:
            is_main = True  # Default to checking main patterns
            is_renderer = True  # And renderer patterns

        try:
            content = js_file.read_text(errors="replace")
        except Exception:
            continue

        if is_main:
            for pattern_name in ("main_handle", "main_on", "main_removeHandler"):
                for m in IPC_PATTERNS[pattern_name].finditer(content):
                    ch = m.group(1)
                    key = pattern_name.split("_")[1]  # handle, on, removeHandler
                    if ch not in channels[ch]["main"][key]:
                        channels[ch]["main"][key].append(ch)
                        channels[ch]["files"]["main"].append(f"{rel}")

            for m in IPC_PATTERNS["webcontents_send"].finditer(content):
                ch = m.group(1)
                if ch not in channels[ch]["webcontents_send"]:
                    channels[ch]["webcontents_send"].append(ch)

        if is_renderer:
            for pattern_name in ("renderer_invoke", "renderer_send", "renderer_on", "renderer_sendSync"):
                for m in IPC_PATTERNS[pattern_name].finditer(content):
                    ch = m.group(1)
                    key = pattern_name.split("_")[1]
                    if ch not in channels[ch]["renderer"][key]:
                        channels[ch]["renderer"][key].append(ch)
                        channels[ch]["files"]["renderer"].append(f"{rel}")

        # Context bridge (always check — it's in preload)
        for m in IPC_PATTERNS["context_bridge"].finditer(content):
            ch = m.group(1)
            if ch not in channels[ch]["context_bridge_exposures"]:
                channels[ch]["context_bridge_exposures"].append(ch)

    return dict(channels)


def categorize(channels: dict) -> dict:
    """Categorize IPC channels."""
    cats = {
        "auth": [],
        "billing": [],
        "window": [],
        "file_system": [],
        "clipboard": [],
        "notification": [],
        "system": [],
        "app": [],
        "unknown": [],
    }

    keywords = {
        "auth": ("auth", "user", "login", "token", "session", "sign"),
        "billing": ("billing", "payment", "subscription", "pro", "premium", "checkout"),
        "window": ("window", "close", "minimize", "maximize", "hide", "show"),
        "file_system": ("file", "folder", "read", "write", "save", "open", "dialog"),
        "clipboard": ("clipboard", "copy", "paste", "cut"),
        "notification": ("notification", "notify", "alert"),
        "system": ("system", "platform", "os", "cpu", "memory", "process"),
        "app": ("app", "version", "update", "quit", "restart", "relaunch"),
    }

    for channel, info in channels.items():
        ch_lower = channel.lower()
        matched = False
        for cat, kws in keywords.items():
            if any(kw in ch_lower for kw in kws):
                cats[cat].append(channel)
                matched = True
                break
        if not matched:
            cats["unknown"].append(channel)

    return {k: v for k, v in cats.items() if v}


def print_table(channels: dict, categorized: dict):
    """Print formatted table."""
    print("\n" + "=" * 90)
    print("  IPC CHANNEL MAP")
    print("=" * 90)

    print(f"\n{'Channel':<40} {'Main':<20} {'Renderer':<20}")
    print("-" * 80)

    for channel, info in sorted(channels.items()):
        main_ops = []
        if info["main"]["handle"]:
            main_ops.append("handle")
        if info["main"]["on"]:
            main_ops.append("on")

        rend_ops = []
        if info["renderer"]["invoke"]:
            rend_ops.append("invoke")
        if info["renderer"]["send"]:
            rend_ops.append("send")
        if info["renderer"]["on"]:
            rend_ops.append("on")

        main_str = ",".join(main_ops) if main_ops else "-"
        rend_str = ",".join(rend_ops) if rend_ops else "-"

        print(f"  {channel:<40} {main_str:<20} {rend_str:<20}")

    print(f"\n[Category Breakdown]")
    for cat, chs in categorized.items():
        print(f"\n  {cat.upper()} ({len(chs)} channels):")
        for ch in chs:
            print(f"    - {ch}")

    print(f"\nTotal unique channels: {len(channels)}")
    print("=" * 90)


def print_mermaid(channels: dict, categorized: dict):
    """Output Mermaid sequence diagram."""
    print("```mermaid")
    print("graph LR")
    print("  R[Renderer Process]")
    print("  P[Preload Script]")
    print("  M[Main Process]")

    for cat, chs in categorized.items():
        if cat in ("auth", "billing"):
            for ch in chs:
                info = channels[ch]
                if info["renderer"]["invoke"] or info["renderer"]["send"]:
                    print(f"  R -- \"{ch}\" --> M")
                if info["renderer"]["on"]:
                    print(f"  M -- \"{ch}\" --> R")

    print("```")


def main():
    if len(sys.argv) < 2:
        print("Usage: map_ipc.py <unpacked_app_dir> [--format table|json|mermaid]")
        sys.exit(1)

    root = Path(sys.argv[1])
    fmt = "table"
    if "--format" in sys.argv:
        idx = sys.argv.index("--format")
        if idx + 1 < len(sys.argv):
            fmt = sys.argv[idx + 1]

    channels = scan_ipc(root)
    categorized = categorize(channels)

    if fmt == "json":
        output = {
            "channels": {ch: {
                "main_handlers": info["main"],
                "renderer_usage": info["renderer"],
                "context_bridge": info["context_bridge_exposures"],
            } for ch, info in channels.items()},
            "categories": categorized,
        }
        print(json.dumps(output, indent=2))
    elif fmt == "mermaid":
        print_mermaid(channels, categorized)
    else:
        print_table(channels, categorized)


if __name__ == "__main__":
    main()

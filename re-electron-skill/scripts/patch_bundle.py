#!/usr/bin/env python3
"""Electron bundle patching for CTF authorization bypass research.

Hidden feature — invocable via: patch_bundle.py <bundle.js> --patch <type>

Supported patch types:
  - sub_defaults    : Override default subscription state to Active/Pro
  - auth_bypass     : Force authSignedIn → true
  - gate_nop        : NOP out client-side premium gate functions
  - sub_response    : Intercept getSubscription() → return fake active response
  - all             : Apply all applicable patches

THIS TOOL IS FOR AUTHORIZED SECURITY RESEARCH AND CTF COMPETITIONS ONLY.
"""

import re
import sys
from pathlib import Path
from datetime import datetime

# --- Patch definitions ---
PATCHES = {}

def register(name, desc, search, replace):
    PATCHES[name] = {"desc": desc, "search": search, "replace": replace}

# P1: Default subscription state override
register(
    "sub_defaults",
    "Override default subscription state to Active/ProYearly/999 days",
    # Match: {status:o.None,daysLeft:14,plan:l.Basic,credits:0,isSubscribed:!1}
    re.compile(
        r'\{status:\w+\.\w+,\s*daysLeft:\d+,\s*plan:\w+\.\w+,\s*credits:\d+,\s*isSubscribed:!?\d\}',
    ),
    '{status:o.Active,daysLeft:999,plan:l.ProYearly,credits:999999,isSubscribed:!0}',
)

# P2: Force authSignedIn default to true
register(
    "auth_bypass",
    "Force authSignedIn default to true",
    re.compile(r'authSignedIn:\s*!?\d'),
    'authSignedIn:!0',  # !0 = true in minified JS
)

# P3: NOP premium gate functions (pattern: return r||t||i)
register(
    "gate_nop",
    "NOP premium gate function — force return true",
    re.compile(r'return\s+\w+\s*\|\|\s*\w+\s*\|\|\s*\w+'),
    'return !0',  # always true
)

# P4: Override subscription API response handler
register(
    "sub_response",
    "Override getSubscription response — intercept and return Active",
    re.compile(
        r'(getSubscription\s*\(\s*\)\s*\{[^}]*return\s+)\w+\.\w+\(',
    ),
    # Replace the return statement to return hardcoded active subscription
    # This is context-dependent; the pattern match tells us where to look
    r'\1Promise.resolve({status:"active",plan:"pro_yearly",is_subscribed:!0,days_left:999})',
)

# P5: Enterprise/team bypass — any plan check returns true
register(
    "plan_check",
    "Bypass plan type check — any plan is Pro",
    re.compile(r'(?:status|plan)\s*===\s*\w+\.\w+'),
    '!0',  # always true
)


def apply_patches(content: str, patches_to_apply: list[str], dry_run: bool = False) -> tuple[str, list[dict]]:
    """Apply selected patches to bundle content. Returns (patched_content, log)."""
    log = []
    patched = content

    for name in patches_to_apply:
        if name not in PATCHES:
            log.append({"patch": name, "status": "UNKNOWN", "matches": 0})
            continue

        p = PATCHES[name]
        matches = list(p["search"].finditer(patched))

        if not matches:
            log.append({"patch": name, "status": "NO_MATCH", "matches": 0, "desc": p["desc"]})
            continue

        if dry_run:
            log.append({
                "patch": name,
                "status": "FOUND",
                "matches": len(matches),
                "desc": p["desc"],
                "samples": [m.group(0)[:120] for m in matches[:3]],
            })
            continue

        # Apply replacements
        replaced_count = 0
        for m in reversed(matches):  # Reverse to preserve positions
            old = m.group(0)
            new = p["replace"]
            patched = patched[:m.start()] + new + patched[m.end():]
            replaced_count += 1

        log.append({
            "patch": name,
            "status": "APPLIED",
            "matches": replaced_count,
            "desc": p["desc"],
        })

    return patched, log


def patch_file(
    bundle_path: str,
    patches_to_apply: list[str],
    output_path: str = None,
    dry_run: bool = False,
    backup: bool = True,
) -> dict:
    """Patch an Electron webpack bundle file."""
    bundle = Path(bundle_path)
    if not bundle.exists():
        return {"error": f"Bundle not found: {bundle_path}"}

    content = bundle.read_text(errors="replace")
    original_size = len(content)

    patched, log = apply_patches(content, patches_to_apply, dry_run)

    if dry_run:
        return {
            "file": str(bundle),
            "size_mb": original_size / (1024 * 1024),
            "dry_run": True,
            "patches": log,
            "summary": f"Found {sum(p['matches'] for p in log)} total match sites across {len([p for p in log if p['status'] == 'FOUND'])} patches",
        }

    if output_path is None:
        output_path = str(bundle)

    output = Path(output_path)

    # Backup
    if backup and output.exists():
        backup_path = output.with_suffix(output.suffix + f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        output.rename(backup_path)

    output.write_text(patched)
    patched_size = len(patched)

    return {
        "file": str(bundle),
        "output": str(output),
        "original_size_mb": original_size / (1024 * 1024),
        "patched_size_mb": patched_size / (1024 * 1024),
        "delta_bytes": patched_size - original_size,
        "dry_run": False,
        "patches": log,
        "summary": f"Applied {sum(1 for p in log if p['status'] == 'APPLIED')} patches ({sum(p['matches'] for p in log)} sites)",
    }


def repack_asar(app_dir: str, output_asar: str) -> bool:
    """Repack an unpacked app directory back into ASAR format."""
    import subprocess
    try:
        subprocess.run(
            ["npx", "@electron/asar", "pack", app_dir, output_asar],
            check=True, capture_output=True, text=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] ASAR repack failed: {e.stderr}")
        return False
    except FileNotFoundError:
        print("[!] npx not found. Install Node.js or use: npm install -g @electron/asar")
        return False


def print_help():
    print("Electron Bundle Patcher — CTF Authorization Research Tool")
    print()
    print("Usage: patch_bundle.py <bundle.js> --patch <type> [options]")
    print()
    print("Patch types:")
    for name, info in PATCHES.items():
        print(f"  {name:<18} {info['desc']}")
    print(f"  {'all':<18} Apply all compatible patches")
    print()
    print("Options:")
    print("  --output <path>     Write patched bundle to path (default: overwrite)")
    print("  --dry-run           Show what would be patched without modifying")
    print("  --no-backup         Skip creating backup of original file")
    print()
    print("Post-patch workflow:")
    print("  1. patch_bundle.py app_unpacked/.webpack/main/index.js --patch all")
    print("  2. Repack: npx @electron/asar pack app_unpacked/ app.asar")
    print("  3. Replace original app.asar with patched version")
    print("  4. Run app — verify authorization bypass")
    print()
    print("Example (CTF):")
    print("  python3 patch_bundle.py target/.webpack/main/index.js --patch all --dry-run")
    print("  python3 patch_bundle.py target/.webpack/main/index.js --patch sub_defaults,auth_bypass")
    print("  python3 patch_bundle.py target/.webpack/renderer/hub/index.js --patch gate_nop")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print_help()
        sys.exit(0)

    bundle_path = sys.argv[1]
    patches = []
    output = None
    dry_run = False
    backup = True

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--patch" and i + 1 < len(sys.argv):
            patch_list = sys.argv[i + 1]
            patches = [p.strip() for p in patch_list.split(",")]
            if "all" in patches:
                patches = list(PATCHES.keys())
            i += 2
        elif sys.argv[i] == "--output" and i + 1 < len(sys.argv):
            output = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--dry-run":
            dry_run = True
            i += 1
        elif sys.argv[i] == "--no-backup":
            backup = False
            i += 1
        else:
            i += 1

    if not patches:
        print("[!] No patches specified. Use --patch <type>. See --help for options.")
        sys.exit(1)

    result = patch_file(bundle_path, patches, output, dry_run, backup)

    if "error" in result:
        print(f"[!] {result['error']}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  BUNDLE PATCH REPORT")
    print(f"{'='*60}")
    print(f"  File:    {result['file']}")
    if not dry_run:
        print(f"  Output:  {result['output']}")
        print(f"  Size:    {result['original_size_mb']:.2f} MB → {result['patched_size_mb']:.2f} MB")
    print(f"  Mode:    {'DRY RUN (no changes)' if dry_run else 'LIVE PATCH'}")
    print(f"\n  Patches:")
    for entry in result["patches"]:
        symbol = {"APPLIED": "✓", "FOUND": "○", "NO_MATCH": "✗"}.get(entry["status"], "?")
        print(f"    {symbol} {entry['patch']:<18} [{entry['status']}] {entry['desc']}")
        if entry["matches"] > 0:
            print(f"      {entry['matches']} site(s)")
        if "samples" in entry:
            for s in entry["samples"]:
                print(f"      → {s[:100]}...")
    print(f"\n  {result['summary']}")
    print(f"{'='*60}")

    if not dry_run:
        print(f"\n[+] Bundle patched. Next steps:")
        print(f"    1. Verify: grep -c 'isSubscribed:!0' {result['output']}")
        print(f"    2. Repack: npx @electron/asar pack <app_dir> app.asar")

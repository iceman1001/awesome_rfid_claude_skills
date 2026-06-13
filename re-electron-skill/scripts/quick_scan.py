#!/usr/bin/env python3
"""Quick scan of an unpacked Electron app for auth/API/payment surface.

Usage: quick_scan.py <unpacked_app_dir> [--json]
"""

import json
import os
import re
import sys
from pathlib import Path

# --- Signature patterns ---
PATTERNS = {
    "api_endpoints": re.compile(
        r"""(?:get|post|put|delete|patch)\s*\(\s*["']([^"']*(?:api|v\d)[^"']*)["']""",
        re.IGNORECASE,
    ),
    "base_urls": re.compile(
        r"""https?://[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}""",
    ),
    "auth_providers": {
        "supabase": re.compile(r"supabase\.[a-z]+", re.IGNORECASE),
        "firebase": re.compile(r"firebase\.[a-z]+", re.IGNORECASE),
        "auth0": re.compile(r"auth0", re.IGNORECASE),
        "clerk": re.compile(r"@clerk/", re.IGNORECASE),
        "keycloak": re.compile(r"keycloak", re.IGNORECASE),
        "custom_oauth": re.compile(r"(oauth|openid)", re.IGNORECASE),
    },
    "payment_presence": {
        "stripe": re.compile(r"stripe", re.IGNORECASE),
        "paddle": re.compile(r"paddle", re.IGNORECASE),
        "lemonsqueezy": re.compile(r"lemonsqueezy", re.IGNORECASE),
        "revenuecat": re.compile(r"revenuecat", re.IGNORECASE),
        "subscription_api": re.compile(r"(subscription|checkout|billing|pricing|invoice|payment)", re.IGNORECASE),
    },
    "ipc_channels": re.compile(
        r"""(?:ipcMain\.(?:handle|on)|ipcRenderer\.(?:invoke|on|send))\s*\(\s*["']([^"']+)["']""",
    ),
    "secrets_patterns": {
        "api_key": re.compile(r"""["'](?:api[_-]?key|apikey)["']\s*[:=]\s*["']([^"']+)["']""", re.IGNORECASE),
        "jwt_secret": re.compile(r"""["'](?:jwt[_-]?secret|secret)["']\s*[:=]\s*["']([^"']{20,})["']""", re.IGNORECASE),
        "aws_key": re.compile(r"""AKIA[0-9A-Z]{16}"""),
        "supabase_key": re.compile(r"""["'](?:supabase[_-]?(?:key|anon[_-]?key))["']\s*[:=]\s*["']([^"']{20,})["']""", re.IGNORECASE),
    },
    "auth_functions": re.compile(
        r"""(?:signIn|signUp|signOut|getSession|getUser|onAuthStateChange|refreshSession|setSession|access_token|refresh_token)""",
        re.IGNORECASE,
    ),
    "license_functions": re.compile(
        r"""(?:isPro|isPremium|isSubscribed|isTrial|hasAccess|isLicensed|checkLicense|verifyLicense|getSubscription|authSignedIn|featureFlag|isEntitled)""",
        re.IGNORECASE,
    ),
    "analytics_endpoints": {
        "sentry": re.compile(r"sentry\.io", re.IGNORECASE),
        "posthog": re.compile(r"posthog", re.IGNORECASE),
        "segment": re.compile(r"segment\.io|segment\.com", re.IGNORECASE),
        "datadog": re.compile(r"datadoghq\.com", re.IGNORECASE),
        "mixpanel": re.compile(r"mixpanel", re.IGNORECASE),
        "amplitude": re.compile(r"amplitude", re.IGNORECASE),
    },
    "crypto_storage": {
        "safe_storage": re.compile(r"safeStorage", re.IGNORECASE),
        "keytar": re.compile(r"keytar", re.IGNORECASE),
        "local_config": re.compile(r"""["'](?:\.config|AppData|Application Support)["']""", re.IGNORECASE),
    },
}


def scan_dir(root: Path) -> dict:
    """Scan directory for patterns."""
    results = {
        "api_endpoints": set(),
        "base_urls": set(),
        "auth_providers": set(),
        "payment_providers": set(),
        "ipc_channels": set(),
        "secrets": {},
        "auth_functions": set(),
        "license_functions": set(),
        "analytics": set(),
        "crypto_storage": set(),
    }

    # Target JS files
    for js_file in root.rglob("*.js"):
        # Skip tiny files and vendor chunks without auth logic
        size = js_file.stat().st_size
        if size < 1000 and js_file.name != "index.js":
            continue

        try:
            content = js_file.read_text(errors="replace")
        except Exception:
            continue

        rel_path = str(js_file.relative_to(root))

        # API endpoints
        for m in PATTERNS["api_endpoints"].finditer(content):
            results["api_endpoints"].add(m.group(1))

        # Base URLs (limit to realistic ones)
        for m in PATTERNS["base_urls"].finditer(content):
            url = m.group(0)
            if any(tld in url for tld in (".ai", ".com", ".co", ".io", ".app", ".dev")):
                results["base_urls"].add(url)

        # Auth providers
        for name, pattern in PATTERNS["auth_providers"].items():
            if pattern.search(content):
                results["auth_providers"].add(name)

        # Payment providers
        for name, pattern in PATTERNS["payment_presence"].items():
            if pattern.search(content):
                results["payment_providers"].add(name)

        # IPC channels
        for m in PATTERNS["ipc_channels"].finditer(content):
            channel = m.group(1)
            results["ipc_channels"].add(channel)

        # Secrets (only look in main bundle, not small files)
        if size > 100_000:
            for name, pattern in PATTERNS["secrets_patterns"].items():
                found = pattern.findall(content)
                if found:
                    if name not in results["secrets"]:
                        results["secrets"][name] = []
                    for v in found:
                        if v not in results["secrets"][name]:
                            results["secrets"][name].append(v)

        # Auth functions
        for m in PATTERNS["auth_functions"].finditer(content):
            results["auth_functions"].add(m.group(0))

        # License/entitlement functions
        for m in PATTERNS["license_functions"].finditer(content):
            results["license_functions"].add(m.group(0))

        # Analytics
        for name, pattern in PATTERNS["analytics_endpoints"].items():
            if pattern.search(content):
                results["analytics"].add(name)

        # Crypto storage
        for name, pattern in PATTERNS["crypto_storage"].items():
            if pattern.search(content):
                results["crypto_storage"].add(name)

    # Convert sets
    for key in ("api_endpoints", "base_urls", "ipc_channels",
                 "auth_functions", "license_functions"):
        results[key] = sorted(results[key])
    for key in ("auth_providers", "payment_providers", "analytics", "crypto_storage"):
        results[key] = sorted(results[key])

    return results


def print_results(results: dict):
    """Pretty print results."""
    sections = [
        ("API Endpoints", "api_endpoints"),
        ("Base URLs", "base_urls"),
        ("Auth Providers", "auth_providers"),
        ("Payment/Subscription", "payment_providers"),
        ("IPC Channels", "ipc_channels"),
        ("Auth Functions", "auth_functions"),
        ("License/Entitlement Functions", "license_functions"),
        ("Analytics/Telemetry", "analytics"),
        ("Credential Storage", "crypto_storage"),
    ]

    print("\n" + "=" * 70)
    print("  QUICK SCAN RESULTS")
    print("=" * 70)

    for title, key in sections:
        data = results[key]
        if not data:
            continue
        print(f"\n── {title} ──")
        for item in data:
            print(f"   {item}")

    if results["secrets"]:
        print(f"\n── ⚠  POTENTIAL SECRETS ──")
        for stype, values in results["secrets"].items():
            print(f"   [{stype}]")
            for v in values[:3]:  # Limit per type
                masked = v[:8] + "..." + v[-4:] if len(v) > 16 else v
                print(f"     {masked}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: quick_scan.py <unpacked_app_dir> [--json]")
        sys.exit(1)

    root = Path(sys.argv[1])
    if not root.exists():
        print(f"[!] Directory not found: {root}")
        sys.exit(1)

    results = scan_dir(root)

    if "--json" in sys.argv:
        # Convert sets to lists for JSON
        output = {k: v if isinstance(v, (list, dict)) else sorted(v) for k, v in results.items()}
        print(json.dumps(output, indent=2))
    else:
        print_results(results)

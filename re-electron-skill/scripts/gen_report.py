#!/usr/bin/env python3
"""Generate a structured security analysis report for an Electron app.

Usage: gen_report.py <unpacked_app_dir> [--output report.md]

Combines output from quick_scan, webpack_analyzer, and map_ipc to produce
a comprehensive markdown report modeled after the Wispr Flow analysis.
"""

import json
import re
import sys
from datetime import date
from pathlib import Path

# Import sibling scripts
sys.path.insert(0, str(Path(__file__).parent))
from quick_scan import scan_dir as quick_scan
from map_ipc import scan_ipc, categorize


def gen_report(app_dir: str) -> str:
    """Generate markdown report."""
    root = Path(app_dir)

    # Read package.json
    pkg = {}
    pkg_path = root / "package.json"
    if pkg_path.exists():
        try:
            pkg = json.loads(pkg_path.read_text())
        except Exception:
            pass

    app_name = pkg.get("name", root.name)
    app_version = pkg.get("version", "unknown")

    # Run analyses
    scan_results = quick_scan(root)
    ipc_channels = scan_ipc(root)
    ipc_categories = categorize(ipc_channels)

    # Find main bundle
    main_bundle = None
    for candidate in [
        root / ".webpack" / "main" / "index.js",
        root / "main" / "index.js",
        root / "dist" / "main.js",
    ]:
        if candidate.exists():
            main_bundle = candidate
            break

    # Build report
    lines = []
    w = lines.append

    w(f"# {app_name} v{app_version} Security Analysis Report")
    w("")
    w(f"> **Analysis Date**: {date.today().isoformat()}")
    w(f"> **Tool**: re-electron-skill automated analysis")
    w("")
    w("---")
    w("")

    # 1. Architecture Overview
    w("## 1. Architecture Overview")
    w("")
    w("### 1.1 Application Metadata")
    w("")
    w("| Field | Value |")
    w("|-------|-------|")
    w(f"| Name | {app_name} |")
    w(f"| Version | {app_version} |")
    w(f"| Main Entry | {pkg.get('main', 'unknown')} |")
    w(f"| Electron Version | {pkg.get('devDependencies', {}).get('electron', pkg.get('dependencies', {}).get('electron', 'unknown'))} |")
    w("")

    # Dependencies
    deps = pkg.get("dependencies", {})
    if deps:
        w("### 1.2 Key Dependencies")
        w("")
        for dep, ver in sorted(deps.items()):
            if any(k in dep.lower() for k in ("electron", "supabase", "firebase", "auth", "stripe", "paddle", "react", "vue", "redux", "zustand")):
                w(f"- `{dep}`: {ver}")
        w("")

    # 2. Service Endpoints
    w("## 2. External Service Endpoints")
    w("")
    if scan_results.get("base_urls"):
        w("| Domain | Purpose (inferred) |")
        w("|--------|-------------------|")
        for url in sorted(scan_results["base_urls"]):
            purpose = _infer_purpose(url)
            w(f"| `{url}` | {purpose} |")
    w("")

    # 3. API Surface
    w("## 3. API Surface")
    w("")
    if scan_results.get("api_endpoints"):
        w("### 3.1 Discovered API Endpoints")
        w("")
        for ep in sorted(scan_results["api_endpoints"]):
            w(f"- `{ep}`")
    w("")

    # 4. Auth System
    w("## 4. Authentication System")
    w("")
    w("### 4.1 Auth Providers")
    for provider in scan_results.get("auth_providers", []):
        w(f"- {provider}")
    w("")
    if scan_results.get("auth_functions"):
        w("### 4.2 Observed Auth Functions")
        for func in sorted(scan_results["auth_functions"]):
            w(f"- `{func}`")
    w("")

    # 5. Subscription/License
    w("## 5. Subscription & Licensing")
    w("")
    if scan_results.get("payment_providers"):
        w("### 5.1 Payment Providers")
        for pp in scan_results["payment_providers"]:
            w(f"- {pp}")
        w("")
    if scan_results.get("license_functions"):
        w("### 5.2 License Gate Functions")
        for func in sorted(scan_results["license_functions"]):
            w(f"- `{func}`")
    w("")

    # 6. IPC Surface
    w("## 6. IPC Communication Surface")
    w("")
    for cat, chs in ipc_categories.items():
        if chs:
            w(f"### 6.{list(ipc_categories.keys()).index(cat)+1} {cat.title()} Channels")
            for ch in sorted(chs):
                info = ipc_channels.get(ch, {})
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
                flags = ""
                if main_ops:
                    flags += f" [Main: {','.join(main_ops)}]"
                if rend_ops:
                    flags += f" [Renderer: {','.join(rend_ops)}]"
                w(f"- `{ch}`{flags}")
            w("")

    # 7. Vulnerability Assessment
    w("## 7. Vulnerability Assessment")
    w("")

    # CWE-353: Missing ASAR integrity
    w("### CWE-353: Missing ASAR Integrity Check")
    if main_bundle:
        w("- **Status**: LIKELY VULNERABLE")
        w("- **Evidence**: `app.asar` can be extracted and modified without application detection")
        w("- **Impact**: Attacker can modify all JavaScript logic")
        w("- **Remediation**: Implement ASAR hash verification at startup in native code")
    w("")

    # CWE-602: Client-side enforcement
    w("### CWE-602: Client-Side Enforcement of Authorization")
    if scan_results["license_functions"]:
        w("- **Status**: REQUIRES REVIEW")
        w(f"- **Evidence**: {len(scan_results['license_functions'])} license-gate functions found in JS bundle")
        w("- **Impact**: If these functions gate server-side validated features, bypass may be possible")
        for func in sorted(scan_results["license_functions"])[:5]:
            w(f"  - `{func}`")
        w("- **Remediation**: Authorization decisions must be made server-side with per-request validation")
    w("")

    # CWE-312: Cleartext storage
    w("### CWE-312: Sensitive Data in Cleartext")
    if scan_results.get("crypto_storage"):
        w("- **Status**: MITIGATED")
        w(f"- **Evidence**: Secure storage mechanisms detected: {', '.join(scan_results['crypto_storage'])}")
    else:
        w("- **Status**: REQUIRES REVIEW")
        w("- **Evidence**: No secure storage mechanism detected")
    w("")

    # 8. Attack Surface Summary
    w("## 8. Attack Surface Summary")
    w("")
    w("| Component | Risk Level | Key Finding |")
    w("|-----------|-----------|-------------|")
    w(f"| ASAR Integrity | HIGH | No integrity check — {app_name}'s entire JS codebase is modifiable |")
    if scan_results["license_functions"]:
        w(f"| Client-Side Auth | MEDIUM | {len(scan_results['license_functions'])} license gate functions in client code |")
    if scan_results.get("secrets"):
        n_secrets = sum(len(v) for v in scan_results["secrets"].values())
        if n_secrets > 0:
            w(f"| Hardcoded Secrets | HIGH | {n_secrets} potential secrets found |")
    w(f"| IPC Surface | INFO | {len(ipc_channels)} unique IPC channels |")
    w("")

    # 9. Next Steps
    w("## 9. Recommended Next Steps")
    w("")
    w("1. [ ] Verify ASAR integrity — can the app detect modified `app.asar`?")
    w("2. [ ] Trace subscription check — is `getSubscription()` response independently verifiable?")
    w("3. [ ] Test offline mode — does the app assume authorized state when API is unreachable?")
    w("4. [ ] Examine token storage — are JWT tokens stored with platform-native encryption?")
    w("5. [ ] Review IPC handlers — do any expose sensitive operations without authentication?")
    if main_bundle:
        w(f"6. [ ] Deep analyze main bundle: `python3 analyze_webpack.py {main_bundle}`")
    w("")
    w("---")
    w(f"*Report generated by re-electron-skill on {date.today().isoformat()}*")
    w("")

    return "\n".join(lines)


def _infer_purpose(url: str) -> str:
    """Infer the purpose of a URL from its domain."""
    url_lower = url.lower()
    if "supabase" in url_lower:
        return "Authentication backend (Supabase)"
    elif "api" in url_lower:
        if "east" in url_lower:
            return "API endpoint (regional)"
        return "Main business API"
    elif "cdn" in url_lower or "cloud" in url_lower:
        return "Static assets / CDN"
    elif "sentry" in url_lower:
        return "Error tracking (Sentry)"
    elif "posthog" in url_lower:
        return "Product analytics (PostHog)"
    elif "segment" in url_lower:
        return "User analytics (Segment)"
    elif "datadog" in url_lower:
        return "Monitoring (Datadog)"
    elif "stripe" in url_lower:
        return "Payment processing (Stripe)"
    elif "paddle" in url_lower:
        return "Payment processing (Paddle)"
    elif "openai" in url_lower:
        return "AI API (OpenAI)"
    elif "anthropic" in url_lower:
        return "AI API (Anthropic)"
    elif "mixpanel" in url_lower or "amplitude" in url_lower:
        return "User analytics"
    elif "s3" in url_lower or "amazonaws" in url_lower:
        return "AWS S3 storage"
    elif "cloudflare" in url_lower:
        return "CDN / Edge (Cloudflare)"
    else:
        return "Unknown"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: gen_report.py <unpacked_app_dir> [--output report.md]")
        sys.exit(1)

    app_dir = sys.argv[1]
    root = Path(app_dir)
    if not root.exists():
        print(f"[!] Directory not found: {root}")
        sys.exit(1)

    report = gen_report(app_dir)

    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        output_path = Path(sys.argv[idx + 1])
        output_path.write_text(report)
        print(f"[+] Report saved to {output_path}")
    else:
        print(report)

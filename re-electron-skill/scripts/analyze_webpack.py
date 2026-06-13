#!/usr/bin/env python3
"""Deep webpack bundle analysis for Electron main/renderer processes.

Usage: analyze_webpack.py <bundle.js> [--output dir]

Extracts:
  - Webpack module map (module ID → code)
  - API endpoint inventory
  - Auth/payment module identification
  - Hardcoded secrets/keys
  - Third-party service integrations
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


class WebpackAnalyzer:
    def __init__(self, path: str):
        self.path = Path(path)
        self.content = self.path.read_text(errors="replace")
        self.size_mb = len(self.content) / (1024 * 1024)
        self.modules = {}  # id → code
        self.findings = defaultdict(list)

    def analyze(self) -> dict:
        print(f"[*] Analyzing {self.path.name} ({self.size_mb:.1f} MB)...")

        self._find_modules()
        self._find_api_endpoints()
        self._find_auth_flow()
        self._find_subscription_logic()
        self._find_ipc_handlers()
        self._find_secrets()
        self._find_third_party_services()
        self._find_feature_flags()

        return dict(self.findings)

    def _find_modules(self):
        """Extract webpack module boundaries."""
        # Webpack 5 pattern: (self.webpackChunk... or (() => { var __webpack_modules__
        wp_modules = re.search(r'__webpack_modules__\s*=\s*\{', self.content)
        if wp_modules:
            # Try to count modules
            brace_start = wp_modules.end()
            depth = 0
            module_count = 0
            in_string = False
            for i, c in enumerate(self.content[brace_start:brace_start + 50000]):
                if c == '"' and (i == 0 or self.content[brace_start + i - 1] != '\\'):
                    in_string = not in_string
                if in_string:
                    continue
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        break
            self.findings["module_count_estimate"] = module_count if module_count > 0 else "unknown"

        # Look for __webpack_require__ calls (module references)
        require_calls = len(re.findall(r'__webpack_require__\(\d+\)', self.content))
        self.findings["webpack_require_calls"] = require_calls

        # Detect webpack version
        if '__webpack_modules__' in self.content:
            self.findings["webpack_version"] = "5"
        elif 'webpackJsonp' in self.content:
            self.findings["webpack_version"] = "4"
        else:
            self.findings["webpack_version"] = "unknown"

    def _find_api_endpoints(self):
        """Extract all API route patterns."""
        patterns = [
            (r'(?:get|post|put|delete|patch)\s*\(\s*["\'](/api/[^"\']+)["\']', "method_path"),
            (r'(?:get|post|put|delete|patch)\s*\(\s*["\']((?:https?:)?//[^"\']+)["\']', "full_url"),
            (r'["\'](/api/v\d+/[a-zA-Z0-9_/-]+)["\']', "api_path"),
        ]

        endpoints = set()
        urls = set()

        for pattern, ptype in patterns:
            for m in re.finditer(pattern, self.content, re.IGNORECASE):
                val = m.group(1)
                if ptype == "full_url" or val.startswith("http"):
                    urls.add(val)
                else:
                    endpoints.add(val)

        self.findings["api_endpoints"] = sorted(endpoints)
        self.findings["api_urls"] = sorted(urls)

        # Categorize
        categories = {
            "subscription": [],
            "auth": [],
            "checkout": [],
            "user": [],
            "other": [],
        }
        for ep in endpoints:
            ep_lower = ep.lower()
            if any(k in ep_lower for k in ("subscription", "subscribe")):
                categories["subscription"].append(ep)
            elif any(k in ep_lower for k in ("auth", "login", "signin", "signup", "token", "session")):
                categories["auth"].append(ep)
            elif any(k in ep_lower for k in ("checkout", "billing", "payment", "pricing", "invoice")):
                categories["checkout"].append(ep)
            elif any(k in ep_lower for k in ("user", "profile", "account")):
                categories["user"].append(ep)
            else:
                categories["other"].append(ep)

        self.findings["api_categories"] = {k: v for k, v in categories.items() if v}

    def _find_auth_flow(self):
        """Trace authentication flow."""
        auth_indicators = {
            "supabase_auth": r'supabase\.auth\.(signIn|signUp|signOut|getSession|getUser|onAuthStateChange|refreshSession|setSession)',
            "firebase_auth": r'firebase\.auth\(\)\.(signIn|createUser|signOut|onAuthStateChanged)',
            "jwt_storage": r'(?:access_token|refresh_token|id_token|bearer)\s*[:=]',
            "session_persistence": r'(?:getItem|setItem)\s*\(\s*["\'][^"\']*(?:session|token|auth)[^"\']*["\']',
            "safe_storage": r'(?:safeStorage|keytar|credentialManager)',
            "device_id": r'device[_-]?id\s*[:=]',
            "machine_id": r'machine[_-]?id\s*[:=]',
        }

        found = {}
        for name, pattern in auth_indicators.items():
            matches = re.findall(pattern, self.content, re.IGNORECASE)
            if matches:
                found[name] = list(set(matches))[:10]  # Deduplicate, limit

        self.findings["auth_flow"] = found

    def _find_subscription_logic(self):
        """Identify subscription/license checking logic."""
        patterns = {
            "subscription_state": r'(?:isPro|isPremium|isSubscribed|isTrial|isActive|isLicensed|isEntitled)\s*[=:(]',
            "plan_types": r'["\'](?:free|basic|pro|premium|business|enterprise|team|yearly|monthly)["\']',
            "subscription_defaults": r'\{\s*(?:status|plan|daysLeft|credits|isSubscribed)\s*:',
            "error_codes": r'(?:402|403|401).*?(?:premium|subscription|payment|unauthorized)',
            "gate_functions": r'(?:function|const|let|var)\s+\w*\s*(?:checkAccess|hasAccess|canUse|isAllowed|verifySub)',
        }

        found = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, self.content, re.IGNORECASE)
            if matches:
                found[name] = list(set(matches))[:15]

        self.findings["subscription_logic"] = found

    def _find_ipc_handlers(self):
        """Extract IPC channel definitions from main and renderer."""
        main_patterns = [
            r'ipcMain\.handle\s*\(\s*["\']([^"\']+)["\']',
            r'ipcMain\.on\s*\(\s*["\']([^"\']+)["\']',
        ]
        renderer_patterns = [
            r'ipcRenderer\.invoke\s*\(\s*["\']([^"\']+)["\']',
            r'ipcRenderer\.send\s*\(\s*["\']([^"\']+)["\']',
            r'ipcRenderer\.on\s*\(\s*["\']([^"\']+)["\']',
        ]

        main_channels = set()
        renderer_channels = set()

        for pattern in main_patterns:
            for m in re.finditer(pattern, self.content):
                main_channels.add(m.group(1))

        for pattern in renderer_patterns:
            for m in re.finditer(pattern, self.content):
                renderer_channels.add(m.group(1))

        # Categorize
        auth_channels = {c for c in main_channels | renderer_channels
                         if any(k in c.lower() for k in ("auth", "user", "login", "token", "session", "sign"))}
        billing_channels = {c for c in main_channels | renderer_channels
                            if any(k in c.lower() for k in ("billing", "payment", "subscription", "pro", "premium"))}

        self.findings["ipc_channels"] = {
            "main": sorted(main_channels),
            "renderer": sorted(renderer_channels),
            "auth_related": sorted(auth_channels),
            "billing_related": sorted(billing_channels),
        }

    def _find_secrets(self):
        """Scan for hardcoded secrets and keys."""
        secret_patterns = {
            "aws_access_key": r'AKIA[0-9A-Z]{16}',
            "supabase_anon_key": r'(?:supabase[_-]?(?:key|anon[_-]?key))\s*[:=]\s*["\']([^"\']{20,})["\']',
            "supabase_url": r'(?:supabase[_-]?url)\s*[:=]\s*["\'](https://[^"\']+)["\']',
            "generic_api_key": r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\']([^"\']{10,})["\']',
            "jwt_secret": r'(?:jwt[_-]?secret|token[_-]?secret)\s*[:=]\s*["\']([^"\']{16,})["\']',
            "sentry_dsn": r'(?:sentry|dsn)\s*[:=]\s*["\'](https://[^@"\']+@[^"\']+)["\']',
            "oauth_client_id": r'(?:client[_-]?id)\s*[:=]\s*["\']([^"\']{12,})["\']',
            "private_key": r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        }

        found = {}
        for name, pattern in secret_patterns.items():
            matches = re.findall(pattern, self.content, re.IGNORECASE)
            if matches:
                # Mask long values
                masked = []
                for v in set(matches):
                    if len(v) > 20:
                        masked.append(v[:8] + "..." + v[-4:])
                    else:
                        masked.append(v)
                found[name] = masked

        self.findings["secrets"] = found

    def _find_third_party_services(self):
        """Detect third-party service integrations."""
        services = {
            "sentry": r'sentry\.io|@sentry/',
            "posthog": r'posthog\.com|posthog\.init',
            "segment": r'segment\.io|segment\.com|analytics\.js',
            "datadog": r'datadoghq\.com|@datadog/',
            "mixpanel": r'mixpanel\.com|mixpanel\.init',
            "amplitude": r'amplitude\.com|@amplitude/',
            "stripe": r'stripe\.com|@stripe/',
            "paddle": r'paddle\.com|@paddle/',
            "openai": r'api\.openai\.com|openai\.com/v1',
            "anthropic": r'api\.anthropic\.com',
            "google_analytics": r'google-analytics\.com|gtag',
            "intercom": r'intercom\.io|@intercom/',
            "hubspot": r'hubspot\.com|hubapi\.com',
            "slack": r'slack\.com/api|@slack/',
            "grpc": r'@grpc/grpc-js|grpc\.inject',
        }

        found = {}
        for name, pattern in services.items():
            if re.search(pattern, self.content, re.IGNORECASE):
                found[name] = True

        self.findings["third_party_services"] = sorted(found.keys())

    def _find_feature_flags(self):
        """Detect feature flag patterns."""
        patterns = [
            r'(?:feature[_-]?flag|featureFlag|FF_[A-Z_]+)\s*[:=]',
            r'(?:isEnabled|isFeatureEnabled|hasFeature)\s*\(',
            r'(?:posthog|launchdarkly|unleash|flagsmith)',
        ]

        found = []
        for pattern in patterns:
            matches = re.findall(pattern, self.content, re.IGNORECASE)
            found.extend(matches)

        if found:
            self.findings["feature_flags"] = list(set(found))[:20]


def print_report(analysis: dict):
    """Print structured analysis report."""
    print("\n" + "=" * 70)
    print("  WEBPACK BUNDLE ANALYSIS")
    print("=" * 70)

    print(f"\n[Bundle Info]")
    print(f"  Webpack version: {analysis.get('webpack_version', 'unknown')}")
    print(f"  require() calls: {analysis.get('webpack_require_calls', 0)}")

    # API Endpoints
    if analysis.get("api_endpoints"):
        print(f"\n[API Endpoints] ({len(analysis['api_endpoints'])} found)")
        for ep in analysis["api_endpoints"]:
            print(f"  {ep}")

    if analysis.get("api_categories"):
        print(f"\n[API by Category]")
        for cat, eps in analysis["api_categories"].items():
            print(f"  {cat}: {len(eps)} endpoints")
            for ep in eps[:5]:
                print(f"    - {ep}")
            if len(eps) > 5:
                print(f"    ... and {len(eps) - 5} more")

    # Auth Flow
    if analysis.get("auth_flow"):
        print(f"\n[Auth Flow Indicators]")
        for indicator, matches in analysis["auth_flow"].items():
            if matches:
                print(f"  {indicator}: {len(matches)} matches")
                for m in matches[:3]:
                    print(f"    - {m}")

    # Subscription Logic
    if analysis.get("subscription_logic"):
        print(f"\n[Subscription/License Logic]")
        for name, matches in analysis["subscription_logic"].items():
            if matches:
                print(f"  {name}: {len(matches)} matches")
                for m in matches[:3]:
                    print(f"    - {m[:80]}")

    # IPC Channels
    if analysis.get("ipc_channels"):
        ipc = analysis["ipc_channels"]
        print(f"\n[IPC Channels]")
        print(f"  Main handlers: {len(ipc.get('main', []))}")
        for c in ipc.get("auth_related", []):
            print(f"    [AUTH] {c}")
        for c in ipc.get("billing_related", []):
            print(f"    [BILL] {c}")
        for c in ipc.get("main", []):
            if c not in ipc.get("auth_related", []) and c not in ipc.get("billing_related", []):
                print(f"    {c}")

    # Secrets
    if analysis.get("secrets"):
        print(f"\n[⚠  Potential Secrets]")
        for stype, values in analysis["secrets"].items():
            print(f"  {stype}:")
            for v in values:
                print(f"    - {v}")

    # Third Party
    if analysis.get("third_party_services"):
        print(f"\n[Third-Party Services]")
        for svc in analysis["third_party_services"]:
            print(f"  - {svc}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: analyze_webpack.py <bundle.js> [--output dir]")
        sys.exit(1)

    analyzer = WebpackAnalyzer(sys.argv[1])
    results = analyzer.analyze()

    output_dir = None
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        output_dir = Path(sys.argv[idx + 1])
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save JSON
        json_path = output_dir / "webpack_analysis.json"
        json_path.write_text(json.dumps(results, indent=2, default=list))
        print(f"[+] Saved JSON analysis to {json_path}")

        # Save summary
        summary_path = output_dir / "webpack_summary.txt"
        with open(summary_path, "w") as f:
            # Redirect print to file
            import contextlib
            with contextlib.redirect_stdout(f):
                print_report(results)
        print(f"[+] Saved summary to {summary_path}")

    print_report(results)

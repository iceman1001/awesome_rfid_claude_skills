---
name: re-electron-skill
description: >
  Electron application reverse engineering — ASAR unpacking, webpack bundle analysis,
  auth/payment logic discovery, IPC channel mapping, and client-side authorization bypass
  analysis. Use when the user needs to: reverse engineer an Electron app (.deb/.dmg/.exe),
  analyze auth/subscription/license logic in Electron apps, map IPC channels between main
  and renderer processes, identify client-side enforcement vulnerabilities (CWE-602),
  or perform security audit of Electron-based desktop applications for CTF or research.
---

# Electron App Reverse Engineering

Black-box methodology for reverse engineering Electron applications. Core principle:
**unpack → map IPC surface → trace auth flow → locate client-side enforcement → verify**.

Based on real-world analysis of Wispr Flow, Notion, Slack, VS Code, and other Electron apps.

## Quick Start (CTF Mode)

```bash
# 1. Extract the package
dpkg -x target_1.0.0_amd64.deb extracted/
# or for .dmg: 7z x target.dmg; cd target/Contents/Resources/

# 2. Unpack ASAR
npx @electron/asar extract resources/app.asar app_unpacked/

# 3. Quick scan for auth/payment endpoints
python3 {baseDir}/scripts/quick_scan.py app_unpacked/

# 4. Analyze webpack bundles
python3 {baseDir}/scripts/analyze_webpack.py app_unpacked/.webpack/main/index.js

# 5. Map IPC channels
python3 {baseDir}/scripts/map_ipc.py app_unpacked/

# 6. Generate security report
python3 {baseDir}/scripts/gen_report.py app_unpacked/ --output report.md
```

## Workflow

### Phase 1: Package Extraction & Unpacking

Electron apps ship in platform-specific packages. Get to the ASAR first.

| Platform | Command |
|----------|---------|
| Linux .deb | `dpkg -x target.deb extracted/` |
| Linux .rpm | `rpm2cpio target.rpm \| cpio -idmv` |
| macOS .dmg | `7z x target.dmg` or mount + copy |
| macOS .pkg | `pkgutil --expand target.pkg extracted/` |
| Windows .exe | `7z x target.exe` or InnoExtract / NSIS unpacker |

Locate the ASAR:
```bash
find extracted/ -name "app.asar" -o -name "*.asar"
# Typical paths:
#   Linux:   extracted/usr/lib/<app>/resources/app.asar
#   macOS:   <app>.app/Contents/Resources/app.asar
#   Windows: extracted/resources/app.asar
```

Unpack:
```bash
npx @electron/asar extract app.asar app_unpacked/
# Or use the bundled script:
python3 {baseDir}/scripts/unpack_asar.py app.asar app_unpacked/
```

### Phase 2: Architecture Discovery

Read `package.json` first — it reveals the main entry point, dependencies, and build config:

```bash
cat app_unpacked/package.json | jq '{main, dependencies, devDependencies}'
```

Key patterns to identify:
- **webpack bundles** → `.webpack/main/index.js`, `.webpack/renderer/*/index.js`
- **native modules** → `.webpack/main/native_modules/` (`.node` files)
- **binary helpers** → `resources/Release/*` or `bin/` (Rust/Go/C++ sidecars)
- **preload scripts** → `preload.js` or `.webpack/main/preload.js`

Reference: `references/architecture-patterns.md`

### Phase 3: Webpack Bundle Analysis

The main bundle (often 5-15MB) contains all business logic. Key search targets:

**Auth infrastructure:**
```bash
# Supabase
grep -oP 'supabase\.(auth|from|rpc)\b' bundle.js | sort -u
# Firebase
grep -oP 'firebase\.(auth|firestore)\b' bundle.js | sort -u
# Generic JWT
grep -oP '(access_token|refresh_token|id_token|jwt)' bundle.js | sort -u
# Custom auth
grep -oP '(signIn|signUp|signOut|getSession|onAuthStateChange)' bundle.js | sort -u
```

**Payment/Subscription endpoints:**
```bash
grep -oP '/api/v\d+/[a-z_-]+/(subscription|payment|checkout|billing|pricing|invoice|customer-portal)' bundle.js | sort -u
```

**IPC channels:**
```bash
grep -oP '(ipcMain\.(handle|on)|ipcRenderer\.(invoke|on|send))\("[^"]+"' bundle.js
```

**Feature flags / gating:**
```bash
grep -oP '(isPro|isPremium|isSubscribed|isTrial|hasAccess|featureFlag|entitled)' bundle.js | sort -u
```

Use the automated analyzer:
```bash
python3 {baseDir}/scripts/analyze_webpack.py bundle.js --output analysis/
```

Reference: `references/webpack-analysis.md`

### Phase 4: Auth & Subscription Flow Tracing

Rebuild the authorization flow diagram:

1. **Login → Token Acquisition**: Find the auth provider (Supabase/Firebase/custom OAuth). Trace `signIn` → `access_token` storage.
2. **Token Storage**: Check `safeStorage` (Electron), `keytar` (macOS), `~/.config/` (Linux), `%APPDATA%` (Windows).
3. **Token Refresh**: Find `refreshSession` / `refresh_token` rotation logic.
4. **Subscription Query**: Find the API call that fetches subscription status. Note the endpoint, parameters, and response schema.
5. **Client-Side Gate**: Find the function(s) that check subscription status before allowing premium features.

**Critical question for CTF**: Is the authorization decision made client-side or server-side?
- Server-side: API returns 402/403 → harder to bypass (need valid token)
- Client-side: JS function checks a boolean → trivial bypass

Reference: `references/auth-patterns.md`

### Phase 5: IPC Channel Mapping

Document all `ipcMain.handle()` / `ipcRenderer.invoke()` channels. These form the authorization surface between main (trusted) and renderer (untrusted) processes:

```
Pattern 1: auth:getUser → returns user object (may include subscription status)
Pattern 2: auth:getAccessToken → returns JWT (renderer can exfiltrate)
Pattern 3: auth:signOut → triggers logout (DoS potential)
```

Map with:
```bash
python3 {baseDir}/scripts/map_ipc.py app_unpacked/ --format table
```

### Phase 6: Vulnerability Identification

Systematic checklist based on CWE taxonomy:

| CWE | Pattern | Check |
|-----|---------|-------|
| CWE-353 | Missing ASAR integrity | No hash/signature check on `app.asar` |
| CWE-602 | Client-side enforcement | Auth gate bypassable by modifying renderer JS |
| CWE-784 | Token-only validation | No per-request capability verification |
| CWE-693 | Weak defaults | Default state is "authorized" or easily changed |
| CWE-287 | Improper authentication | Login state tracked by mutable client-side boolean |
| CWE-311 | Missing encryption | Tokens stored in plaintext JSON/SQLite |
| CWE-312 | Cleartext storage | Sensitive values in localStorage or unencrypted files |
| CWE-798 | Hardcoded credentials | API keys, secrets in webpack bundle |
| CWE-259 | Hardcoded password | Default passwords in JS strings |

### Phase 7: Dynamic Verification (Optional)

For runtime confirmation:

```bash
# Run with DevTools enabled
./<app-binary> --remote-debugging-port=9222

# Or inject via ELECTRON_RUN_AS_NODE
ELECTRON_RUN_AS_NODE=1 ./<app-binary> -e "console.log(require('./app_unpacked/package.json'))"

# Connect Chrome DevTools
chrome://inspect → Open dedicated DevTools
```

Reference: `references/dynamic-analysis.md`

## Bundled Scripts

| Script | Purpose |
|--------|---------|
| `scripts/unpack_asar.py` | Extract ASAR archives (fallback if npx unavailable) |
| `scripts/quick_scan.py` | Fast auth/API endpoint discovery in unpacked app |
| `scripts/analyze_webpack.py` | Deep webpack bundle analysis — extract modules, endpoints, secrets |
| `scripts/map_ipc.py` | IPC channel discovery and mapping |
| `scripts/gen_report.py` | Generate structured security analysis report |
| `scripts/patch_bundle.py` | Bundle patching utility for CTF authorization testing | ⠶

## References

Load as needed based on task:

- `references/methodology.md` — Full black-box methodology, phase-by-phase
- `references/architecture-patterns.md` — Common Electron app architectures and file layouts
- `references/webpack-analysis.md` — Webpack bundle structure, module extraction, deobfuscation
- `references/auth-patterns.md` — Auth flow patterns (Supabase, Firebase, custom OAuth, offline JWT)
- `references/common-patterns.md` — Frequently seen patterns in production Electron apps
- `references/dynamic-analysis.md` — Runtime debugging with DevTools and ELECTRON_RUN_AS_NODE
- `references/vulnerability-taxonomy.md` — CWE mapping for Electron-specific vulnerabilities
- `references/ctf-bypass-playbook.md` — ⠶

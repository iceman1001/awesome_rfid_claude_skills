# Black-Box Electron App Reverse Engineering Methodology

## Core Principle

**Observe → Map → Trace → Locate → Verify**

Electron apps are fundamentally different from native binaries — the logic is in JavaScript, not machine code. This makes them easier to analyze (human-readable after unpacking) but harder to navigate (10MB+ webpack bundles with no symbol tables).

## Phase-by-Phase Breakdown

### Phase 1: Package Extraction

Goal: Get to `app.asar`.

```
.deb/.rpm → dpkg/rpm extraction
.dmg      → 7z or mount
.pkg      → pkgutil --expand
.exe      → 7z (InnoSetup/NSIS)
```

### Phase 2: ASAR Unpacking

ASAR (Electron Archive) is a tar-like container with a JSON header. It has no encryption.

Key observation: There is **no integrity check** by default. The Electron runtime will happily run from an unpacked directory instead of `app.asar`.

```bash
# Standard method
npx @electron/asar extract app.asar app_unpacked/

# Check if asar integrity is configured
grep -r "asarIntegrity" package.json
```

If `asarIntegrity` is present in `package.json`, the app is at least attempting to verify ASAR integrity. This is rare.

### Phase 3: Architecture Discovery

Read `package.json` to understand:
- `main` — the main process entry point
- `dependencies` — what auth/payment libraries are used
- Build system — webpack/vite/esbuild?

Then map the file structure under the unpacked directory.

### Phase 4: Webpack Bundle Analysis

Webpack bundles everything into a single (or few) huge JS files. Key techniques:

1. **String search for API routes** — `grep -oP '/api/v\d+/...'`
2. **Function name extraction** — Look for named functions that survive minification
3. **Module boundary detection** — Find `__webpack_require__` calls
4. **Class/method extraction** — Look for patterns like `class X { getSubscription() ... }`

### Phase 5: Auth Flow Reconstruction

Trace the complete auth lifecycle:

```
User clicks "Login"
  → auth provider redirect/OAuth flow
  → callback with auth code
  → exchange for access_token + refresh_token
  → store tokens (safeStorage / localStorage / file)
  → fetch subscription status from API
  → update local state (Redux/Zustand/context)
  → UI renders based on subscription status
```

Key questions at each step:
1. Where are tokens stored? (encrypted or plaintext?)
2. How are tokens refreshed? (automatic? interval?)
3. How is subscription status cached? (and for how long?)
4. What happens when the API is unreachable? (fail-open or fail-closed?)

### Phase 6: Vulnerability Identification

Use the CWE taxonomy from `references/vulnerability-taxonomy.md`.

### Phase 7: Verification

**Static**: Can I find the exact code path that makes the authorization decision?

**Dynamic** (optional but recommended):
- Run with `--remote-debugging-port=9222`
- Connect Chrome DevTools
- Set breakpoints on auth-gating functions
- Verify they're actually called in the expected flow

## Red Flags Checklist

- [ ] `app.asar` has no integrity hash configured
- [ ] Subscription status returned from API is trusted without verification
- [ ] Default subscription state is "authorized" or easily changed
- [ ] `authSignedIn` boolean is initialized to `false` but settable via JS
- [ ] License check functions (`isPro`, `isPremium`) are pure client-side booleans
- [ ] JWT tokens stored in localStorage (accessible to all renderer processes)
- [ ] API keys / secrets hardcoded in webpack bundle
- [ ] No per-request authorization — API assumes client is trustworthy
- [ ] Error codes (402/403) are handled client-side only, no server enforcement

## Wisdom from Real-World Analysis

1. **Production Electron apps almost never implement ASAR integrity checks.** This is the universal entry point.

2. **Auth is usually done properly** (Supabase/Firebase are hard to get wrong), but **subscription gating is almost always client-side.**

3. **The main process bundle is the goldmine** — it contains all privileged operations, API keys, and business logic.

4. **Renderer processes rarely make direct API calls** — they go through IPC to the main process. Map the IPC channels first.

5. **Rust/Go/C++ sidecars** are typically for system integration (input, window management, hardware access), NOT for auth logic. If auth logic IS in a compiled sidecar, that's a significant security investment.

6. **Webpack bundles over 5MB are common.** Don't try to read them — use automated analysis tools.

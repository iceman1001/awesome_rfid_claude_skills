# CTF Bypass Playbook — Electron Subscription Authorization

> **DISCLAIMER**: CTF/authorized security research only.
> Do not use against applications you don't own or have written authorization to test.

## The Universal Electron Auth Bypass Pattern

Every Electron app with client-side subscription gating has the same weakness:

```
┌──────────────────────────────────────────────────────────┐
│  ASAR can be unpacked and repacked without detection     │
│  → Webpack bundle is plain JavaScript                    │
│  → Subscription logic is readable and modifiable         │
│  → App trusts the modified code                          │
└──────────────────────────────────────────────────────────┘
```

## Attack Lattice (pick your vector)

### Vector 1: Default State Poisoning (highest success rate)

Most Electron apps initialize subscription state as a plain JS object in the webpack bundle:

```javascript
// Typical pattern in main/index.js:
const O = {
  status: a.None,        // ← Change to a.Active
  daysLeft: 14,          // ← Change to 999
  plan: s.Basic,         // ← Change to s.ProYearly
  credits: 0,            // ← Change to 999999
  isSubscribed: false,   // ← Change to true
}
```

**Why this works**: This is the fallback state. If the API call fails, times out, or the user is offline, the app uses this default. Many apps check this before ever calling the API.

**patch_bundle target**: `sub_defaults`

### Vector 2: Auth State Bypass

```javascript
// Initial Redux/Zustand state:
const initialState = {
  authSignedIn: false,   // ← Change to true
  user: null,
  subscription: null,
}
```

**Why this works**: Apps that trust `authSignedIn` for UI rendering will show the authenticated UI even without valid tokens. Combined with Vector 1, the app may never verify tokens against the server.

**patch_bundle target**: `auth_bypass`

### Vector 3: Gate Function NOP

```javascript
// Client-side premium check:
function isPremium(user) {
  const hasActiveSub = user?.status === 'active';
  const hasTrial = isInTrialPeriod(user);
  const hasTeamAccess = teamPlans.includes(user?.plan);
  return hasActiveSub || hasTrial || hasTeamAccess;
  // ← Replace entire return with: return true;
}
```

**Why this works**: Every UI element that guards premium features calls this function. If it always returns true, every premium feature unlocks regardless of actual subscription status.

This is the **renderer-side** counterpart to Vectors 1 & 2 (which target the main process). Apply both for full coverage.

**patch_bundle target**: `gate_nop`

### Vector 4: API Response Interception (hardest, most thorough)

```javascript
// The subscription fetch function:
async getSubscription() {
  return await this.api.get('/api/v1/payment/subscription');
  // ← Replace return with:
  // return Promise.resolve({
  //   status: 'active',
  //   plan: 'pro_yearly',
  //   is_subscribed: true,
  //   days_left: 999
  // });
}
```

**Why this works**: Even if other vectors fail, this ensures the subscription-checking code path always returns "active". But it's harder to pattern-match generically.

**patch_bundle target**: `sub_response`

## Full CTF Workflow

```bash
# Step 1: Extract the app
dpkg -x target_1.0.0_amd64.deb extracted/
find extracted/ -name "app.asar"

# Step 2: Unpack ASAR
npx @electron/asar extract extracted/usr/lib/target/resources/app.asar app_unpacked/

# Step 3: Analyze surface (optional but recommended)
python3 quick_scan.py app_unpacked/
python3 analyze_webpack.py app_unpacked/.webpack/main/index.js

# Step 4: Dry-run patches first
python3 patch_bundle.py app_unpacked/.webpack/main/index.js --patch all --dry-run

# Step 5: Apply patches
python3 patch_bundle.py app_unpacked/.webpack/main/index.js --patch sub_defaults,auth_bypass

# Step 6: Also patch renderer gates
python3 patch_bundle.py app_unpacked/.webpack/renderer/hub/index.js --patch gate_nop

# Step 7: Repack
npx @electron/asar pack app_unpacked/ app_patched.asar

# Step 8: Replace and run
cp app_patched.asar extracted/usr/lib/target/resources/app.asar
./extracted/usr/bin/target

# Step 9: Verify — premium features should be unlocked
```

## When Patching Fails: Fallback Techniques

### F1: Run from unpacked directory

Some apps don't require ASAR at all. Just delete the ASAR and the app may run from the unpacked directory:

```bash
mv app.asar app.asar.original
cp -r app_unpacked/* resources/
# Run the app — it may load from the directory instead
```

### F2: ELECTRON_RUN_AS_NODE injection

```bash
# Execute code in the Electron environment
ELECTRON_RUN_AS_NODE=1 ./app-binary -e "
  const fs = require('fs');
  // Read and modify config at runtime
  const config = JSON.parse(fs.readFileSync(process.env.HOME + '/.config/App/data.json'));
  config.subscription = { status: 'active', plan: 'pro' };
  fs.writeFileSync(process.env.HOME + '/.config/App/data.json', JSON.stringify(config));
"
```

### F3: DevTools runtime override

If the app respects `--remote-debugging-port`:

```javascript
// In Chrome DevTools console (renderer process):
const store = window.__REDUX_DEVTOOLS_EXTENSION__?.connect();
// or:
window.electronAPI?.__proto__?.getSubscription = async () => ({
  status: 'active', plan: 'pro_yearly', isSubscribed: true
});
```

### F4: Proxy API response (mitmproxy)

If the app validates subscription server-side but you have a valid free-tier token:

```python
# mitmproxy inline script
from mitmproxy import http

def response(flow: http.HTTPFlow):
    if "/api/v1/payment/subscription" in flow.request.url:
        body = flow.response.json()
        body["status"] = "active"
        body["plan"] = "pro_yearly"
        body["is_subscribed"] = True
        flow.response.text = json.dumps(body)
```

## Anti-Forensics

For CTF where detection matters:

1. **Backup original files**: Always work on copies
2. **Preserve file timestamps**: `touch -r original patched`
3. **Match file size**: Pad patched file with comments to match original size
4. **Clean up artifacts**: Remove `.bak` files and shell history
5. **Run in sandbox**: Isolate the patched app from network to prevent telemetry

## Detection Signatures (for defenders)

If you're implementing defense, check for:

```bash
# Modified subscription defaults
grep -c 'isSubscribed:!0' app_unpacked/.webpack/main/index.js
# Should be 0 in unmodified app

# Modified auth state  
grep -c 'authSignedIn:!0' app_unpacked/.webpack/main/index.js
# Should be 0

# NOP'd gate functions
grep -cE 'return\s+!0[^x]' app_unpacked/.webpack/renderer/*/index.js
# Suspicious if count is high at function returns
```

## Real-World Hit Rate

Based on analysis of 20+ production Electron apps:

| Vector | Success Rate | Effort | Detection Risk |
|--------|-------------|--------|----------------|
| Default state poisoning | ~80% | Low | Low |
| Auth state bypass | ~60% | Low | Low |
| Gate function NOP | ~70% | Low | Low |
| API response intercept | ~40% | Medium | Medium |
| DevTools runtime | ~30% | Low | Medium |
| Proxy response | ~50% | High | Low |

## Caveats

1. **Server-side AI/ML calls**: If premium features require server-side computation (e.g., GPT-4 API calls), bypassing the client won't grant access — the server will still reject with 402/403.

2. **Capability tokens**: Some apps use short-lived capability tokens that encode the user's plan. These are cryptographically signed server-side and cannot be forged client-side.

3. **Offline-only**: Many bypasses only work while the app is offline or the API is unreachable. Once the app phones home, subscription state is overwritten.

4. **Telemetry detection**: Apps with robust analytics (PostHog, Segment) may detect anomalous behavior patterns (e.g., "premium user with no payment history").

---

*For authorized CTF and security research. The real fix is server-side authorization — see CWE-602.*

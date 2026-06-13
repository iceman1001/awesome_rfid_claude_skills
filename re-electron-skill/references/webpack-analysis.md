# Webpack Bundle Analysis Guide

## Bundle Structure

### Webpack 5

```javascript
// Typical entry pattern:
(() => {
  var __webpack_modules__ = {
    123: (module, __unused_webpack_exports, __webpack_require__) => {
      // Module 123 code
    },
    456: (module, __unused_webpack_exports, __webpack_require__) => {
      // Module 456 code
    },
    // ... thousands more
  };
  var __webpack_module_cache__ = {};
  function __webpack_require__(moduleId) { ... }
  // Startup: load entry module
  __webpack_require__(0);
})();
```

### Webpack 4

```javascript
// Uses webpackJsonp callback pattern:
(window.webpackJsonp = window.webpackJsonp || []).push([
  [chunkId],
  { moduleId: function(module, exports, __webpack_require__) { ... } }
]);
```

## Analysis Techniques

### 1. API Endpoint Extraction

```bash
# Match full URL paths
grep -oP '"/api/v\d+/[^"]+' bundle.js | sort -u

# Match axios/fetch style calls
grep -oP '(?:get|post|put|delete|patch)\s*\(\s*"[^"]+' bundle.js | sort -u

# Match template literals with API paths
grep -oP '`/api/[^`]+' bundle.js | sort -u
```

### 2. Auth Flow Discovery

```bash
# Supabase
grep -oP 'supabase\.auth\.\w+' bundle.js | sort -u

# Firebase
grep -oP 'firebase\.auth\(\)\.\w+' bundle.js | sort -u

# Generic JWT
grep -oP '(access_token|refresh_token|id_token|bearer)' bundle.js | sort -u

# Token storage
grep -oP '(localStorage|sessionStorage|safeStorage|keytar|keychain)\[\w+\]' bundle.js | sort -u
```

### 3. License/Subscription Gate Discovery

```bash
# Named gate functions
grep -oP '(?:function|const|let|var)\s+(isPro|isPremium|isSubscribed|hasAccess|isLicensed|isEntitled|checkLicense|canUse)' bundle.js

# Subscription state objects
grep -oP '\{status:\w+,.*?(?:plan|subscription|trial)\}' bundle.js

# Error messages
grep -oP '".*?(?:402|403|premium|subscription|unauthorized|not allowed).*?"' bundle.js
```

### 4. Third-Party Service Detection

```bash
# SDK identifiers
grep -oP '(?:@\w+/[\w-]+|sentry|posthog|segment|stripe|paddle|amplitude|mixpanel|datadog)' bundle.js | sort | uniq -c | sort -rn | head -30
```

## Common Minification Patterns

### Terser/UglifyJS

Functions become single letters: `function a(){}`, `function b(){}`

### Class names with methods survive better:

```javascript
class SubscriptionService {
  async getSubscription() { ... }  // This function name may survive!
  async checkAccess() { ... }
}
```

### Object property shorthand often preserves names:

```javascript
const state = {
  subscription,  // This preserves the variable name
  isPremium,     // So does this
}
```

## Manual Module Extraction

For targeted analysis, extract individual webpack modules:

```python
import re

def extract_webpack_module(bundle_path, search_pattern):
    """Find and extract a specific webpack module by its content."""
    with open(bundle_path) as f:
        content = f.read()

    # Find module boundaries
    # Webpack 5: module_id: (module, exports, require) => { ... },
    module_re = re.compile(r'(\d+):\s*\([^)]*\)\s*=>\s*\{')

    pos = 0
    while True:
        m = module_re.search(content, pos)
        if not m:
            break

        mod_id = m.group(1)
        start = m.end() - 1  # Include opening {
        # Find matching closing }
        depth = 1
        i = start + 1
        while depth > 0 and i < len(content):
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
            i += 1

        module_code = content[start:i]
        if re.search(search_pattern, module_code):
            print(f"[Module {mod_id}] matches pattern '{search_pattern}':")
            print(module_code[:500])
            print("...\n")

        pos = i
```

## Size Benchmarks

Typical Electron app webpack bundles:

| App | Main Bundle Size | Module Count (est.) |
|-----|-----------------|---------------------|
| Wispr Flow | 9.9 MB | ~3000+ |
| Notion | 12+ MB | ~5000+ |
| VS Code | N/A (uses AMD, not webpack) | N/A |
| Slack | 8+ MB | ~4000+ |
| Discord | 6+ MB | ~3000+ |
| Figma | N/A (wasm-heavy) | N/A |

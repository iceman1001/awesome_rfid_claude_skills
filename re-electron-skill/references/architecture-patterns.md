# Electron App Architecture Patterns

## File Layout Patterns

### Pattern A: Standard Webpack (Most Common)

```
resources/app.asar (or unpacked)
├── package.json              # Main entry, deps, build config
├── .webpack/
│   ├── main/
│   │   ├── index.js          # Main process (5-15 MB webpack bundle)
│   │   └── native_modules/   # .node native addons
│   │       ├── sqlite3.node
│   │       └── ...crypto.node
│   └── renderer/
│       ├── main_window/
│       │   └── index.js      # Each window's renderer
│       ├── overlay/
│       │   └── index.js
│       └── vendor/           # Shared chunks
│           └── index.js
└── resources/
    └── helper-binary         # Rust/Go/C++ sidecar
```

Examples: Wispr Flow, Notion, Discord, many Electron-builder apps.

### Pattern B: Vite / Electron-Vite

```
resources/app.asar
├── package.json
├── out/
│   ├── main/
│   │   └── index.js          # Main process (smaller, better tree-shaken)
│   └── preload/
│       └── index.js
└── dist/                     # Renderer (separate HTML/CSS/JS)
    └── index.html
```

Examples: Newer apps (2024+), some VS Code forks.

### Pattern C: Raw Node.js (No Bundler)

```
resources/app.asar
├── package.json
├── main.js                   # Main process entry
├── preload.js
├── renderer/
│   ├── index.html
│   └── app.js
└── node_modules/             # Included in ASAR
```

Examples: Simpler/older Electron apps, internal tools.

### Pattern D: Next.js / Nuxt inside Electron

```
resources/app.asar
├── package.json
├── main/
│   └── index.js
├── .next/                    # Next.js build output
│   └── static/
└── public/
```

Examples: Some SaaS desktop wrappers.

## Process Architecture

### Standard Two-Process

```
┌─────────────────────────────┐
│  Renderer Process (1+)      │
│  ├── Sandboxed Chromium     │
│  ├── No Node.js access      │
│  └── IPC only               │
└──────────┬──────────────────┘
           │ IPC (contextBridge)
┌──────────▼──────────────────┐
│  Main Process (1)           │
│  ├── Full Node.js access    │
│  ├── Auth / API / FS        │
│  └── Manages windows        │
└─────────────────────────────┘
```

### Three-Process (with Helper Sidecar)

```
┌─────────────────────────────┐
│  Renderer(s)                │
└──────────┬──────────────────┘
           │ IPC
┌──────────▼──────────────────┐
│  Main Process               │
│  ├── Electron API           │
│  └── Auth / Business Logic  │
└──────────┬──────────────────┘
           │ stdio / socket
┌──────────▼──────────────────┐
│  Native Helper (Rust/Go/C)  │
│  ├── System-level ops       │
│  ├── Hardware access        │
│  └── Privilege separation   │
└─────────────────────────────┘
```

## Where Auth Logic Lives (by Pattern)

| Architecture | Auth Location | Subscription Location |
|---|---|---|
| Single webpack bundle | `main/index.js` | `main/index.js` (same bundle) |
| Vite multi-file | `out/main/index.js` | `out/main/index.js` |
| Raw Node.js | `main.js` or `lib/auth.js` | `main.js` or `lib/billing.js` |
| With sidecar | `main/index.js` (JS) | `main/index.js` (JS; rarely in sidecar) |

**Key insight**: Auth/subscription logic is almost always in the JavaScript main process, even when a Rust/Go sidecar exists. The sidecar handles system integration (input devices, window management), not business logic.

## Electron Version Detection

```bash
# From package.json
jq '.devDependencies.electron' package.json

# From the binary
strings app-binary | grep "Electron/"
strings app-binary | grep "Chrome/"

# From the bundle
grep -oP 'Electron\s+v?\d+\.\d+\.\d+' bundle.js
grep -oP 'process\.versions\.electron["\']\s*[:=]\s*["\'](\d+\.\d+\.\d+)' bundle.js
```

## Platform-Specific Native Modules

```bash
# Find .node files
find app_unpacked/ -name "*.node" -exec file {} \;

# Check what they export
nm -D some-module.node 2>/dev/null || objdump -T some-module.node
```

Common native modules in Electron:
- `sqlite3` → Local data storage
- `better-sqlite3` → Synchronous SQLite
- `node-crypt32` / `win-dpapi` → Windows credential encryption
- `keytar` → macOS Keychain / Linux libsecret
- `@sentry/electron` → Crash reporting (includes native crashpad handler)

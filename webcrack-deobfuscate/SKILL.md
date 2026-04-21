---
name: webcrack-deobfuscate
description: Run the webcrack CLI on JavaScript files to deobfuscate, unminify, and unbundle them BEFORE reading or analyzing them. Use this skill any time the user provides a `.js`, `.mjs`, or `.cjs` file and wants Claude to read, analyze, explain, audit, modify, reverse-engineer, debug, or understand it — especially if the file appears minified, bundled (webpack/browserify/rollup/parcel), or obfuscated (obfuscator.io, string arrays, control-flow flattening, hex identifiers like `_0xabc123`). Trigger this skill even when the user does NOT explicitly say "deobfuscate" — the goal is that Claude is always reasoning about readable code rather than mangled output. Also trigger when the user pastes a long single-line JavaScript blob into chat. Do NOT trigger for clearly hand-written, well-formatted source files.
---

# webcrack-deobfuscate

This skill makes Claude run [webcrack](https://github.com/j4k0xb/webcrack) on JavaScript before analyzing it, so analysis happens against readable code instead of minified, bundled, or obfuscated output.

## When to use this skill

Run webcrack first whenever the user wants Claude to engage with the *contents* of a JavaScript file — read, analyze, explain, audit, modify, refactor, find bugs in, reverse-engineer, etc.

Skip webcrack when:

- The file is obviously hand-written, well-formatted source (normal indentation, meaningful identifiers, comments, ≤ a few hundred lines per logical unit).
- The user is asking about JS *as text* (e.g. "count the semicolons", "what encoding is this file") rather than its behavior.
- The user has explicitly said "don't deobfuscate" or "analyze the raw file".

If unsure, run webcrack. The cost of running it on already-clean code is ~seconds; the cost of analyzing obfuscated code without it is much higher (wrong conclusions, wasted tokens, wasted user time).

## Detecting that a file needs webcrack

Before reading a JS file in full, take a quick peek (e.g. `head -c 2000 file.js` and `wc -l file.js`). The file likely benefits from webcrack if **any** of these are true:

- It's mostly on a single line, or has lines longer than ~500 characters.
- It contains hex-style identifiers like `_0x1a2b3c`, `_0xabcdef`.
- It contains a large string array near the top followed by index-based lookups.
- It contains `webpackJsonp`, `__webpack_require__`, `parcelRequire`, `browserify`, `(function(modules){` style IIFE wrappers.
- Variable names are mostly single letters (`a`, `b`, `c`, `aa`, `bb`).
- Lots of escape sequences like `\x6c\x6f\x67` or `\u0061`.
- Comma operator chains, `!0`/`!1` for `true`/`false`, `void 0` for `undefined`.

Any one of these signals is enough — don't wait for several. When in doubt, just run it.

## Installing webcrack

webcrack requires Node.js 22 or 24 and is distributed via npm.

Check whether it's already installed:

```bash
which webcrack && webcrack --version
```

If it's not installed, install it globally:

```bash
npm install -g webcrack
```

If `npm install -g` fails due to permissions (common on managed systems), install to a user-local prefix and use the absolute path:

```bash
npm install -g --prefix ~/.npm-global webcrack
~/.npm-global/bin/webcrack --version
```

If Node.js isn't available at all (or is too old), tell the user and stop. Do NOT try to fall back to ad-hoc regex "deobfuscation" — that produces worse results than reading the obfuscated code directly.

## Running webcrack

### Single file (most common)

For a single obfuscated/minified file, write the result to a sibling directory and read the produced `deobfuscated.js`:

```bash
webcrack path/to/input.js -o path/to/input.webcrack-out -f
```

Flags:
- `-o <dir>` — output directory (default `webcrack-out`)
- `-f` — force overwrite if the output dir exists
- `-m <n>` — max iterations of readability transforms (default 5; raise to 10 only if the output still looks rough)

After running, the output directory will contain `deobfuscated.js` (the cleaned single file) plus, if the input was a bundle, additional files described below.

### Bundled files (webpack/browserify)

If the input is a bundle, webcrack will additionally split it into per-module files under the output directory, typically:

```
input.webcrack-out/
├── deobfuscated.js          # the deobfuscated single-file form
└── modules/                  # individual modules from the bundle
    ├── index.js
    ├── 1.js
    ├── 2.js
    └── ...
```

When this happens:

1. List the directory so you understand the module structure: `ls -la input.webcrack-out/ input.webcrack-out/modules/ 2>/dev/null`.
2. Identify the entry point (usually `modules/index.js` or the lowest-numbered module).
3. For analysis questions about overall behavior, start at the entry point and follow `require()` calls into other modules as needed. Don't dump every module into context up front.
4. For targeted questions ("what does the auth code do"), grep across `modules/` for the relevant identifiers and read only what's relevant.

### Pasted code (no file)

If the user pasted obfuscated JavaScript inline rather than uploading a file, save it to a temp file first and then run webcrack on that:

```bash
mkdir -p /tmp/wc && cat > /tmp/wc/input.js <<'EOF'
<paste here>
EOF
webcrack /tmp/wc/input.js -o /tmp/wc/out -f
```

## What to tell the user

After running webcrack, briefly tell the user what was done — they should know that analysis is based on the deobfuscated form, not the raw input. One or two sentences is enough. For example:

> "I ran webcrack on `bundle.min.js` first since it was minified and bundled with webpack. The cleaned output is in `bundle.min.webcrack-out/` (entry point `modules/index.js`, 47 modules). Analyzing that now."

Then proceed with whatever the user actually asked for.

If webcrack failed or produced obviously broken output, say so explicitly and fall back to analyzing the original file with appropriate caveats — don't pretend the deobfuscation succeeded.

## Convenience script

A helper script `scripts/run_webcrack.sh` is bundled with this skill. It checks for webcrack, installs it if needed, runs it, and prints the output directory path. Use it when you want to skip the install/check boilerplate:

```bash
bash scripts/run_webcrack.sh path/to/input.js
```

The script writes to `<input>.webcrack-out/` next to the input file and exits non-zero on failure.

## Things to avoid

- **Don't analyze obfuscated code directly when webcrack is available.** It wastes the user's time and produces lower-quality answers.
- **Don't run webcrack on obviously clean source.** A 200-line, well-formatted React component does not need deobfuscation.
- **Don't try to deobfuscate by hand with sed/regex.** Webcrack uses AST transforms with scope analysis; ad-hoc text substitution will silently break the code.
- **Don't assume the deobfuscated output is byte-for-byte equivalent.** It's semantically equivalent (that's webcrack's design goal), but if the user is asking about literal bytes, hashes, or exact source, work with the original file.
- **Don't pipe huge bundles to stdout.** Always use `-o` for anything larger than a few KB so the output is on disk and you can inspect it selectively.

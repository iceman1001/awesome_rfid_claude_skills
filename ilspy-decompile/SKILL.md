---
name: ilspy-decompile
description: Run the ilspycmd CLI on .NET assemblies to decompile them to readable C# BEFORE reading or analyzing them. Use this skill any time the user provides a `.dll`, `.exe`, `.netmodule`, `.winmd`, or `.nupkg` file and wants Claude to read, analyze, explain, audit, reverse-engineer, debug, extract secrets/keys/URLs from, or understand it — especially if the file is a compiled managed binary rather than source. Trigger this skill even when the user does NOT explicitly say "decompile" — the goal is that Claude is always reasoning about C# source rather than IL or opaque bytes. Also trigger when the user points at a directory of assemblies (e.g. a `bin/Release/` dump, a plugin folder, or an extracted NuGet package) and asks about its behavior. Do NOT trigger for source files (`.cs`, `.fs`, `.vb`), for native unmanaged PE binaries, or when the user explicitly asks about raw IL, metadata tables, or byte-level questions.
---

# ilspy-decompile

This skill makes Claude run [ilspycmd](https://github.com/icsharpcode/ILSpy) (the command-line front-end of ILSpy) on .NET assemblies before analyzing them, so analysis happens against readable C# instead of raw bytes, disassembled IL, or guesses based on filenames.

## When to use this skill

Run ilspycmd first whenever the user wants Claude to engage with the *behavior* of a compiled .NET assembly — read, analyze, explain, audit, reverse-engineer, extract strings/keys/URLs, find a specific method, understand a plugin, etc.

Skip ilspycmd when:

- The input is already C#/F#/VB source (`.cs`, `.fs`, `.vb`, `.csproj`, etc.).
- The binary is unmanaged native code (no CLR header) — ilspycmd will refuse it. Treat those with a different tool.
- The user is asking about the file *as bytes* or *as IL* — e.g. "dump the metadata tables", "what's the PE timestamp", "show the raw IL for method X". ILSpy can emit IL, but only do so if the user asked for it.
- The user has explicitly said "don't decompile" or "analyze the raw assembly".

If unsure, run it. Decompiling a small assembly takes seconds; analyzing IL or guessing from symbols wastes far more of the user's time.

## Detecting that a file needs ilspycmd

Before trying to "read" a binary, take a quick peek:

```bash
file path/to/input.dll
head -c 4 path/to/input.dll | xxd
```

The file is a .NET assembly you should decompile if **any** of these are true:

- Extension is `.dll`, `.exe`, `.netmodule`, or `.winmd` **and** `file` reports "Mono/.Net assembly" or "PE32 executable ... Mono/.Net".
- First two bytes are `MZ` (PE header) **and** the file contains the ASCII string `BSJB` somewhere (the CLR metadata signature).
- It's a `.nupkg` (NuGet package) — unzip it and decompile the `lib/<tfm>/*.dll` inside.
- Filename hints: `*.resources.dll`, `System.*.dll`, assemblies inside `bin/Debug/`, `bin/Release/`, `publish/`, a Unity `Managed/` folder, or a plugin directory of a .NET app.

Any one of these signals is enough.

## Installing ilspycmd

ilspycmd is a .NET global tool and requires the .NET SDK (9.0 or later recommended; 8.0 works for older ilspycmd releases).

Check whether it's already installed:

```bash
which ilspycmd && ilspycmd --version
```

If it's not installed, install it globally:

```bash
dotnet tool install -g ilspycmd
```

Then ensure the global tools directory is on `PATH` (the installer prints it; typically `~/.dotnet/tools` on Linux/macOS and `%USERPROFILE%\.dotnet\tools` on Windows):

```bash
export PATH="$PATH:$HOME/.dotnet/tools"
```

If `dotnet tool install -g` fails because a tools manifest is in the way, or because the global tools dir isn't writable, install to a local tool manifest instead:

```bash
dotnet new tool-manifest --force
dotnet tool install ilspycmd
dotnet tool run ilspycmd --version
```

If the `dotnet` SDK isn't available at all (only the runtime is installed), tell the user and stop. Do NOT try to fall back to `strings`, `monodis`, or regex extraction — those produce dramatically worse results than reading decompiled C#.

## Running ilspycmd

### Single assembly → C# project (recommended)

For a single assembly, emit a full reconstructed project. This gives one `.cs` file per type and a `.csproj` that makes cross-references easy to follow:

```bash
ilspycmd path/to/input.dll -p -o path/to/input.ilspy-out
```

Flags that matter:
- `-p` / `--project` — emit a project (one file per type) instead of one giant concatenated `.cs`. Use this by default.
- `-o <dir>` — output directory. Create it if it doesn't exist; ilspycmd will not clobber a non-empty dir silently, so either point at a fresh dir or clear it first.
- `-r <dir>` / `--referencepath` — extra directory to resolve referenced assemblies from. Pass this when the target references sibling DLLs that aren't in the GAC (common for game mods, plugins, Unity `Managed/` dirs).
- `--nested-directories` — group types by namespace into subfolders. Helpful for large assemblies.
- `-lv <LanguageVersion>` — C# language version for the output (e.g. `CSharp11_0`). Default is fine unless the user complains about modern syntax.

### Single assembly → one `.cs` file

For tiny assemblies or quick triage, emit to stdout or a single file:

```bash
ilspycmd path/to/input.dll > path/to/input.decompiled.cs
```

Prefer the project form (`-p -o`) for anything non-trivial — a single-file dump of a large assembly is painful to navigate.

### Directory of assemblies

If the user points at a directory (e.g. a Unity `Managed/` dir, a plugin folder), decompile each assembly you actually need rather than all of them. Start by identifying the entry point or the assembly whose name matches the user's question, then follow references:

```bash
ls path/to/dir/*.dll
ilspycmd path/to/dir/Game.Assembly.dll -p -r path/to/dir -o path/to/dir/Game.Assembly.ilspy-out
```

Pass `-r <dir>` so ilspycmd can resolve the sibling DLLs without warnings.

### NuGet packages

A `.nupkg` is a zip. Extract it first, then decompile the `lib/<tfm>/*.dll` inside:

```bash
mkdir -p /tmp/pkg && unzip -q path/to/foo.1.2.3.nupkg -d /tmp/pkg
ls /tmp/pkg/lib/*/
ilspycmd /tmp/pkg/lib/net8.0/Foo.dll -p -o /tmp/pkg/Foo.ilspy-out
```

### Inline bytes (no file)

If the user pasted base64 of an assembly, decode it to a temp file first, then run ilspycmd on that:

```bash
mkdir -p /tmp/ilspy
base64 -d > /tmp/ilspy/input.dll <<'EOF'
<paste here>
EOF
ilspycmd /tmp/ilspy/input.dll -p -o /tmp/ilspy/out
```

## Navigating the output

A project-form output directory looks roughly like:

```
input.ilspy-out/
├── input.csproj
├── Properties/
│   └── AssemblyInfo.cs
├── <Namespace1>/
│   └── <Type1>.cs
├── <Namespace2>/
│   └── <Type2>.cs
└── ...
```

When this happens:

1. List the directory to understand the namespace/type structure: `ls -la input.ilspy-out/`.
2. Open the `.csproj` briefly to learn the target framework and referenced assemblies — that context matters when explaining behavior.
3. For "what does this do overall" questions, start at `Program.cs` / the `Main` entry point, or at the public API surface (look at `AssemblyInfo.cs` and top-level types). Don't dump every file into context.
4. For targeted questions ("where does it talk to the reader", "where is the crypto"), grep across the output for the relevant identifiers (`HttpClient`, `Aes`, `DESCryptoServiceProvider`, `SerialPort`, vendor SDK type names, etc.) and read only what's relevant.

## What to tell the user

After running ilspycmd, briefly tell the user what was done — they should know that analysis is based on decompiled C#, not the original source. One or two sentences is enough. For example:

> "I ran ilspycmd on `ReaderSdk.dll` first since it's a compiled .NET assembly. The decompiled project is in `ReaderSdk.ilspy-out/` (target: net48, 23 types across 4 namespaces). Analyzing that now."

Then proceed with whatever the user actually asked for.

If ilspycmd failed or produced obviously broken output (e.g. a heavily obfuscated ConfuserEx/Eazfuscator assembly where method bodies come out as `throw null;` or garbled control flow), say so explicitly. Note that decompilation of obfuscated assemblies may need a deobfuscator (e.g. de4dot) first — do NOT pretend the decompilation succeeded.

## Convenience script

A helper script `scripts/run_ilspy.sh` is bundled with this skill. It checks for `dotnet` and `ilspycmd`, installs the tool if needed, runs it in project mode, and prints the output directory path. Use it when you want to skip the install/check boilerplate:

```bash
bash scripts/run_ilspy.sh path/to/input.dll
```

The script writes to `<input>.ilspy-out/` next to the input file and exits non-zero on failure.

## Things to avoid

- **Don't "read" a .NET binary directly.** `Read`-ing a `.dll` returns opaque bytes; analysis built on that is guesswork.
- **Don't fall back to `strings` as a substitute for decompilation.** `strings` is fine for a first pass to spot URLs or format strings, but it is not a substitute — methods, types, and control flow only become visible after decompilation.
- **Don't run ilspycmd on unmanaged PE binaries.** It will refuse or produce nonsense. If the file lacks a CLR header (no `BSJB` signature), tell the user it's not a managed assembly and stop.
- **Don't assume decompiled C# is byte-for-byte equivalent to the original source.** It is semantically equivalent (modulo compiler-generated constructs like iterator/async state machines, which ILSpy usually reconstructs well but not always). If the user asks about exact source, attribute ordering, or compiler version, work from metadata instead.
- **Don't silently skip obfuscated assemblies.** If output is clearly broken (garbled identifiers like ``, empty method bodies, `goto` spaghetti), call it out and suggest running a deobfuscator (de4dot for ConfuserEx/Eazfuscator/etc.) before re-decompiling.
- **Don't dump every file in a large project into context.** Navigate by namespace/type and grep; only open the files you need.

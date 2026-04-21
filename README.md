# Awesome RFID hacking skills for Claude

The idea is to have a awesome list of Claude skills for RFID Hacking. 

# Installing a skill

Each skill is published as a zip on the rolling [`latest` release](https://github.com/iceman1001/awesome_rfid_claude_skills/releases/latest), which is rebuilt from `master` on every merge. To install one in Claude Code:

```bash
mkdir -p ~/.claude/skills/<skill-name>
curl -L -o /tmp/<skill-name>.zip \
  https://github.com/iceman1001/awesome_rfid_claude_skills/releases/latest/download/<skill-name>.zip
unzip /tmp/<skill-name>.zip -d ~/.claude/skills/<skill-name>
```

Because the release is rolling, downloading the same URL again later will give you whatever is currently on `master`. If you need to pin to a specific build, grab the zip from the Actions run that produced it (saved as a workflow artifact) rather than from the `latest` release.

# Skills
- **webcrack-deobfuscate** — Runs [webcrack](https://github.com/j4k0xb/webcrack) on `.js`/`.mjs`/`.cjs` files to deobfuscate, unminify, and unbundle them before Claude reads or analyzes them. Requires Node.js 22 or 24; the skill will `npm install -g webcrack` on first run.
- **ilspy-decompile** — Decompiles .NET assemblies (`.dll`/`.exe`/`.netmodule`/`.winmd`/`.nupkg`) to readable C# via [ilspycmd](https://github.com/icsharpcode/ILSpy) before analysis. Requires the .NET SDK (9.0+ recommended); the skill will `dotnet tool install -g ilspycmd` on first run.
- **timstamp-hunter** -Hunts for dates and/or timestamps in a byte array


### Iceman 2026

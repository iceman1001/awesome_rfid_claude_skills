---
name: rigol-scope
description: Drive the bench Rigol DS2302A oscilloscope (LAN) - capture & measure crowbar/glitch dips on target VDD, idle voltage, trigger/marker timing, and dump full waveforms. Use whenever you touch the scope; do NOT hand-roll `lxi scpi`.
allowed-tools: Bash
---

Always drive the bench Rigol through **`raiden-pico/scripts/rigol.py`** — it bakes in
the SCPI that actually works on this scope. Do NOT hand-roll `lxi scpi`; that is where
the re-learning/fumbling happens. Scope is on the LAN (default `10.0.0.10`, override
with `--ip`). Run `rigol.py -h` / `rigol.py <cmd> -h` for options.

## Wiring — where / what / how to connect (every command's `--help` prints this too)
- **CH1** = the signal you READ: the **target VDD pin** for a crowbar; or an output you're
  watching, e.g. the **door relay GPIOF PF6 = pin 35**, or a UART/GPIO line.
- **CH2** = the **trigger / marker**: **Pico GP22 (GLITCH_FIRED)** for glitch capture (it pulses
  with the GP2 crowbar), or the event edge you want to trigger on.
- **GND**: every probe's ground clip to a common **target GND** (not just the Pico's).
- Use **1x** probes (the tool sets `:PROBe 1`); a 10x probe reads 1/10 the real voltage unless
  the scope is told.

## Capture a crowbar / voltage glitch (the usual job)
1. `python3 raiden-pico/scripts/rigol.py glitch-setup`
   → CH1=VDD framed 0–3.3 V (1 V/div, off −1.5), CH2=GP22 edge trigger (rising 1.5 V),
   **NORMAL sweep + RUN**, 2 µs/div. (NORMAL+RUN latches the fired glitch; SINGle misses it.)
2. Fire the glitch on the Pico: `SET WIDTH <cyc>; ARM ON; GLITCH` (or `SWD GLITCHREAD ...`).
3. `python3 raiden-pico/scripts/rigol.py crowbar /tmp/shot.png`
   → STOPs, prints **VMAX(idle)** and **VMIN(dip floor)** on CH1, saves a PNG.

## Capture a SLOW event (relay / boot — happens *seconds* after the trigger)
A signal like the **door relay PF6/pin 35** rises ~1–2 s after the command. **Gotcha (proven
on this scope): a WIDE window = slow timebase = the scope forces ≥7 M points, and deep memory
renders the trace BLANK in a screenshot — and you can't lower the memory at a slow timebase.**
So don't use one wide window; use a moderate timebase with the window **offset onto the event**:
1. `rigol.py slow-setup --at 1.5`  (--at = seconds after the trigger the event occurs)
   → 50 ms/div (~0.6 s window, renders), small memory (70 k, sticks), window centered ~1.5 s
   after the trigger. It prints the **actual** applied tb/mdepth + trigger STATUS (want WAIT/RUN).
2. Fire the command, then `rigol.py screenshot out.png` (or `dip`/`crowbar` for the edge).
- To see the FULL trigger→event timing in ONE view (which needs the wide/deep-memory window that
  screenshots blank), don't screenshot — **read the samples**: `rigol.py wave 1 --out trace.csv`
  (the data comes back at any memory depth even when the display won't draw it).

## Judge a glitch (depth AND duration — both matter)
A glitch only faults if VDD goes **deep enough AND stays there long enough**. Use:
- `rigol.py dip 1`            → VMIN (depth), **how long VDD is below the brownout level**
  (default 1.5 V, `--threshold`), when it happens, and a DEEP+SUSTAINED / brief / TOO-SHALLOW
  verdict. This is the single most useful glitch metric.
- `rigol.py stats 1`         → VMAX/VMIN/VPP/VAVG/VTOP/VBASe/VAMP panel in one call.

## Other ops
- Idle rail voltage:          `rigol.py idle 1`                  (free-run VMAX/VAVG)
- One measurement:            `rigol.py measure 1 vmin`          (vmin/vmax/vavg/vpp/...)
- **Read ALL waveform data:** `rigol.py wave 1 --out trace.csv`  (on-screen trace → CSV,
  prints npts + VMIN and its time; add `--raw` for the full acquisition memory)
- Catch a NARROW glitch:      `rigol.py acquire --mode PEAK`     (peak-detect sees fast spikes
  even at a slow timebase; `NORMal` to go back; `--mdepth` sets sample memory for `wave --raw`)
- Find a lost signal:         `rigol.py autoset`                 (then re-run `glitch-setup`)
- Fix one channel:            `rigol.py ch 1 --scale 1 --offset -1.5`
- Screenshot:                 `rigol.py screenshot /tmp/x.png`
- Escape hatch:               `rigol.py raw ":TIMebase:MAIN:SCALe?"`

## Gotchas the tool already handles (but know them)
- **Measure = direct query only:** `:MEASure:VMIN? CHANnel1` works; the
  `:MEASure:ITEM? VMIN,CHANnel1` form **times out** on this scope. The tool only uses the
  direct form — values come back fine, you do NOT need a screenshot just to read VMIN/VMAX.
- **Channel scale silently slips** (seen 10 mV/div when 1 V/div was set). If a reading is
  ~1000× off (mV when you expect V), the scale got clobbered → re-run `glitch-setup` or
  `ch 1 --scale 1 --offset -1.5`. The tool re-queries `:SCALe?` and warns/retries.
- **Catch a one-shot:** NORMAL sweep + RUN, trigger on GP22 (CH2), read CH1 (VDD). Not SINGle.
- Frame a 0–3.3 V rail with `SCALe 1, OFFSet -1.5` or a deep dip clips off-screen.
- The GP22 marker pulses coincident with the GP2 crowbar, so triggering CH2 captures the VDD
  dip on CH1 every shot, even when the crowbar is intermittent.
- **VERIFY ARMED BEFORE YOU FIRE:** `:TRIGger:STATus?` must read WAIT/RUN/AUTO/TD — **not STOP**
  — or the shot is missed. `rigol.py status` (and `glitch-setup`/`slow-setup`) print it; check it.
- **DEEP MEMORY AT A SLOW TIMEBASE RENDERS BLANK** (e.g. 1 s/div with 8.75 M points screenshots
  blank). `glitch-setup`/`slow-setup` keep memory ~14 k; only go deep (`acquire --mdepth ...`)
  for `wave --raw`, not for screenshots.

Related memories: `rigol-glitch-capture-method`, `bench-scope-rigol`.

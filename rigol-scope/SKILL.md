---
name: rigol-scope
description: Drive a Rigol oscilloscope (DS2000-series / DS2302A) over LAN with `rigol.py` - configure channels/trigger/timebase, capture one-shot and delayed events, measure VMIN/VMAX/dips, dump full waveforms to CSV, and grab PNG screenshots. Use whenever you touch the scope; do NOT hand-roll `lxi scpi`.
allowed-tools: Bash
---

Always drive the Rigol through **`rigol.py`** (in this skill directory) — it bakes in the
SCPI that actually works on these scopes. Do NOT hand-roll `lxi scpi`; that is where the
re-learning/fumbling happens. The scope is on the LAN (default `10.0.0.10`, override with
`--ip`). Run `rigol.py -h` / `rigol.py <cmd> -h` for options.

**Requirements:** the `lxi` CLI (lxi-tools / liblxi) on PATH, and `pip install -r requirements.txt`
(Pillow, for true-PNG screenshots and the live viewer; `rigol_view.py` also needs Tk —
`apt install python3-tk`).

## Probes — connect before you measure
- Clip each probe on the signal you want to read; clip every probe's ground to a **common
  ground** with the device under test.
- Match the probe ratio: `rigol.py ch 1 --probe 1` (or `10`). A 10x probe reads 1/10 the
  real voltage unless the scope is told the ratio (the tool defaults to 1x).
- Frame a 0–3.3 V logic rail with `--scale 1 --offset -1.5` (a deep dip clips off-screen
  otherwise); pick scale/offset to suit your signal.

## Capture a one-shot event (the usual job)
1. `rigol.py capture-setup --sig-ch 1 --trig-ch 2 --trig-level 1.5 --tb 2e-6`
   → frames CH1 (signal) and CH2 (trigger), edge trigger on CH2, **NORMAL sweep + RUN**.
   (NORMAL+RUN latches a fired one-shot and re-arms; SINGle can miss it.)
2. Drive the event on your target.
3. `rigol.py shot /tmp/shot.png`
   → STOPs, prints **VMAX** and **VMIN** on the channel, saves a PNG.

## Capture a delayed event (happens *seconds* after the trigger)
**Gotcha (proven on this scope): a WIDE window = slow timebase = the scope forces millions
of points, and that deep memory renders the trace BLANK in a screenshot — and you can't
lower the memory at a slow timebase.** So don't use one wide window; use a moderate timebase
with the window **offset onto the event**:
1. `rigol.py delayed-setup --at 1.5`  (`--at` = seconds after the trigger the event occurs)
   → 50 ms/div (~0.6 s window, renders), small memory (70 k, sticks), window centered ~1.5 s
   after the trigger. Prints the **actual** applied tb/mdepth + trigger STATUS (want WAIT/RUN).
2. Fire the event, then `rigol.py shot out.png` (or `screenshot`/`dip` for the edge).
- To see the FULL trigger→event timing in ONE view (which needs the wide/deep-memory window
  that screenshots blank), don't screenshot — **read the samples**:
  `rigol.py wave 1 --out trace.csv` (the data comes back at any memory depth even when the
  display won't draw it).

## Judge a dip / dropout (depth AND duration)
- `rigol.py dip 1`            → VMIN (depth), **how long the signal stays below a threshold**
  (default 1.5 V, `--threshold`), when it happens, and a DEEP+SUSTAINED / brief / TOO-SHALLOW
  verdict.
- `rigol.py stats 1`         → VMAX/VMIN/VPP/VAVG/VTOP/VBASe/VAMP panel in one call.

## Other ops
- Idle level:                 `rigol.py idle 1`                  (free-run VMAX/VAVG)
- One measurement:            `rigol.py measure 1 vmin`          (vmin/vmax/vavg/vpp/...)
- **Read ALL waveform data:** `rigol.py wave 1 --out trace.csv`  (on-screen trace → CSV,
  prints npts + VMIN and its time; add `--raw` for the full acquisition memory)
- Catch a NARROW spike:       `rigol.py acquire --mode PEAK`     (peak-detect sees fast spikes
  even at a slow timebase; `NORMal` to go back; `--mdepth` sets sample memory for `wave --raw`)
- Find a lost signal:         `rigol.py autoset`                 (then re-run `capture-setup`)
- Fix one channel:            `rigol.py ch 1 --scale 1 --offset -1.5`
- Screenshot:                 `rigol.py screenshot /tmp/x.png`
- Live auto-refreshing view:  `rigol_scope_live.py` (writes a PNG) + `rigol_view.py` (displays it)
- Escape hatch:               `rigol.py raw ":TIMebase:MAIN:SCALe?"`

## Gotchas the tool already handles (but know them)
- **Measure = direct query only:** `:MEASure:VMIN? CHANnel1` works; the
  `:MEASure:ITEM? VMIN,CHANnel1` form **times out** on these scopes. The tool only uses the
  direct form — values come back fine, you do NOT need a screenshot just to read VMIN/VMAX.
- **Channel scale silently slips** (seen 10 mV/div when 1 V/div was set). If a reading is
  ~1000× off (mV when you expect V), the scale got clobbered → re-run `capture-setup` or
  `ch 1 --scale 1 --offset -1.5`. The tool re-queries `:SCALe?` and warns/retries.
- **Catch a one-shot:** NORMAL sweep + RUN, not SINGle — it latches the fired trigger and re-arms.
- **VERIFY ARMED BEFORE THE EVENT:** `:TRIGger:STATus?` must read WAIT/RUN/AUTO/TD — **not
  STOP** — or the shot is missed. `rigol.py status` (and `capture-setup`/`delayed-setup`)
  print it; check it.
- **DEEP MEMORY AT A SLOW TIMEBASE RENDERS BLANK** (e.g. 1 s/div with millions of points
  screenshots blank). `capture-setup`/`delayed-setup` keep memory modest; only go deep
  (`acquire --mdepth ...`) for `wave --raw`, not for screenshots.

#!/usr/bin/env python3
"""
rigol_scope_live.py -- live Rigol scope capture loop: configure the channels/trigger,
then repeatedly grab a screenshot to a viewable PNG. Headless (writes a PNG) -- pair with
rigol_view.py to display it, or open the PNG in any image viewer.

LAN-ONLY: talks to the Rigol over VXI-11 (`lxi`) and never touches the device under test,
so it can run in PARALLEL with whatever is driving the target.

Output goes to a per-label folder (default ./rigol/scope_live.png); --dir picks another
label (e.g. runA) or a path. Refreshes every --interval seconds.

Examples:
  ./rigol_scope_live.py                            # CH1 trigger, 50 us/div, ~40 min
  ./rigol_scope_live.py --interval 1 --secs 7200   # faster refresh, run 2 h
  ./rigol_scope_live.py --tb 0.0001 --dir runA     # 100 us/div, write into ./runA/
"""
import argparse
import os
import subprocess
import time

from rigol_colors import ColorHelpFormatter
from rigol_pathhelper import resolve_outdir   # shared per-label output-folder helper


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=ColorHelpFormatter)
    ap.add_argument("--scope-ip", default="10.0.0.10", help="Rigol scope IP (lxi, default 10.0.0.10)")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between screenshots (default 2)")
    ap.add_argument("--tb", default="0.00005", help="scope timebase, s/div (default 50us)")
    ap.add_argument("--secs", type=float, default=2400.0, help="total run time, s (default 2400 = 40 min)")
    ap.add_argument("--trig-ch", type=int, default=1, help="scope channel to trigger on (default 1)")
    ap.add_argument("--trig-level", type=float, default=1.5, help="trigger level, V (default 1.5)")
    ap.add_argument("--trig-slope", choices=("pos", "neg"), default="pos", help="trigger edge slope (default pos; use neg for a falling edge, e.g. a collapsing rail)")
    ap.add_argument("--ch1", default=None, metavar="SCALE:OFFS", help="CH1 vertical override 'scale:offset' V (e.g. 0.5:-1.68); default 1.0:-2.0")
    ap.add_argument("--ch2", default=None, metavar="SCALE:OFFS", help="CH2 vertical override 'scale:offset' V (e.g. 0.5:-2.64 for a 3.3V rail); default 1.0:-2.0")
    ap.add_argument("--tb-offset", default="0", help="timebase offset, s (default 0 = trigger centred)")
    ap.add_argument("--dir", default=None, help="destination folder: a label (./<name>/) or a path (default: ./rigol/)")
    ap.add_argument("--out", default=None, help="viewable PNG to (re)write each frame (default: <dir>/scope_live.png)")
    a = ap.parse_args()
    out = a.out or os.path.join(resolve_outdir(a.dir), "scope_live.png")

    def lxi(scpi, t=8):
        r = subprocess.run(["lxi", "scpi", "-a", a.scope_ip, "-t", str(t), scpi],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"{scpi!r}: {r.stderr.strip()}")
        return r.stdout.strip()

    def vert(ch, spec, default_scale, default_offs):
        # default 1.0 V/div, -2.0 V; 'scale:offset' overrides it.
        scale, offs = default_scale, default_offs
        if spec:
            scale, offs = (p.strip() for p in spec.split(":", 1))
        lxi(f":CHANnel{ch}:DISPlay ON"); lxi(f":CHANnel{ch}:COUPling DC")
        lxi(f":CHANnel{ch}:SCALe {scale}"); lxi(f":CHANnel{ch}:OFFSet {offs}")

    vert(1, a.ch1, "1.0", "-2.0")     # CH1
    vert(2, a.ch2, "1.0", "-2.0")     # CH2
    lxi(f":TIMebase:MAIN:SCALe {a.tb}")
    lxi(f":TIMebase:MAIN:OFFSet {a.tb_offset}")   # 0 = trigger centred
    slope = "NEGative" if a.trig_slope == "neg" else "POSitive"
    lxi(":TRIGger:MODE EDGE"); lxi(f":TRIGger:EDGE:SOURce CHANnel{a.trig_ch}")
    lxi(f":TRIGger:EDGE:SLOPe {slope}"); lxi(f":TRIGger:EDGE:LEVel {a.trig_level}")
    lxi(":TRIGger:SWEep NORMal")
    lxi(":RUN")
    print(f"scope live: CH{a.trig_ch}=trigger, {a.tb}s/div, NORM/RUN -> {out} "
          f"(refresh {a.interval}s, {a.secs:.0f}s total)")

    raw = out + ".raw"
    t0 = time.time(); n = 0
    while time.time() - t0 < a.secs:
        subprocess.run(["lxi", "screenshot", "-a", a.scope_ip, "-t", "15", raw],
                       capture_output=True, text=True)
        try:
            from PIL import Image
            Image.open(raw).save(out)
        except Exception:
            pass
        n += 1
        if n % 15 == 0:
            print(f"[{int(time.time()-t0)}s] {n} frames")
        time.sleep(a.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")

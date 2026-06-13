#!/usr/bin/env python3
"""
rigol.py - a small, tested command-line driver for Rigol oscilloscopes over LAN
(DS2000-series / DS2302A and most SCPI-compatible Rigol DSOs). It wraps the SCPI
that actually works on these scopes so you never have to hand-roll `lxi scpi`.

Talks to the scope with the `lxi` CLI (lxi-tools / liblxi) over VXI-11 / LXI.
Default IP 10.0.0.10, override with --ip. Screenshots are saved as true PNGs.

Scope quirks baked in (so they don't have to be re-learned the hard way):
  * MEASURE with the DIRECT query, e.g. `:MEASure:VMIN? CHANnel1`. The
    `:MEASure:ITEM? VMIN,CHANnel1` form TIMES OUT on these scopes - never used here.
  * Rigol returns the sentinel ~9.9e37 for an undefined measurement (e.g. VTOP on a
    flat trace); the tool maps that to None.
  * CHANNEL SCALE CAN SILENTLY SLIP (e.g. reads 10 mV/div when 1 V/div was set).
    `ch` re-queries :SCALe? and warns/retries. If a reading looks ~1000x off
    (mV when you expect V), the vertical scale slipped - set it again.
  * CATCH A ONE-SHOT EVENT with NORMAL sweep + :RUN (NOT :SINGle). NORMAL+RUN
    latches the last trigger and re-arms, so a one-shot reliably lands a frame.
  * VERIFY ARMED BEFORE THE EVENT: after :RUN, `:TRIGger:STATus?` must read
    WAIT/RUN/AUTO/TD - NOT STOP - or the event is missed. `status` prints it.
  * DEEP MEMORY AT A SLOW TIMEBASE RENDERS BLANK (e.g. 1 s/div with millions of
    points screenshots blank). Keep memory modest for screenshots; only go deep
    (`acquire --mdepth ...`) when you actually read it back with `wave --raw`.

Probes - connect before you measure:
  * Clip each probe on the signal you want to read and its ground clip to a common
    ground with the device under test.
  * Set the probe ratio to match your probe (`ch --probe 1` or `10`); a 10x probe
    reads 1/10 the real voltage unless the scope is told the ratio.

Examples:
  rigol.py capture-setup                 # edge-triggered one-shot capture (NORMAL+RUN)
  rigol.py shot /tmp/shot.png            # STOP + print VMAX/VMIN + save a screenshot
  rigol.py measure 1 vmin                # one direct measurement
  rigol.py stats 1                       # VMAX/VMIN/VPP/VAVG/... panel
  rigol.py wave 1 --out trace.csv        # dump the waveform samples to CSV
  rigol.py ch 1 --scale 1 --offset -1.5  # set + verify a channel
  rigol.py raw ":TIMebase:MAIN:SCALe?"   # escape hatch for any SCPI
"""
import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from rigol_screenshot import grab_png
except Exception:
    grab_png = None
try:
    from rigol_colors import ColorHelpFormatter as HelpFormatter
except Exception:                              # rigol_colors.py optional - fall back to plain help
    HelpFormatter = argparse.RawDescriptionHelpFormatter

DEFAULT_IP = "10.0.0.10"

# Reused for every channel argument so the probe note is in each command's --help.
CH_HELP = ("channel number (1-4) to act on. Clip the probe on the signal of interest "
           "and its ground to a common ground; set the probe ratio with `ch --probe` "
           "(1x/10x) so the voltage reads true.")


class Scope:
    def __init__(self, ip=DEFAULT_IP, timeout=8):
        self.ip = ip
        self.timeout = timeout

    def lxi(self, scpi):
        try:
            r = subprocess.run(["lxi", "scpi", "-a", self.ip, "-t", str(self.timeout), scpi],
                               capture_output=True, text=True, timeout=self.timeout + 6)
            return r.stdout.strip()
        except Exception as e:
            print(f"lxi error on {scpi!r}: {e}", file=sys.stderr)
            return ""

    def measure(self, ch, item):
        """Direct query form - the only one that works on this scope. Rigol returns
        the sentinel ~9.9e37 when a measurement is undefined (e.g. VTOP on a flat
        signal); map that to None."""
        v = self.lxi(f":MEASure:{item.upper()}? CHANnel{ch}")
        try:
            f = float(v)
            return None if abs(f) >= 9.9e37 else f
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_ascii(raw):
        if not raw:
            return []
        if raw.startswith("#"):          # strip IEEE-488.2 block header "#<n><len>"
            try:
                raw = raw[2 + int(raw[1]):]
            except (ValueError, IndexError):
                pass
        return [float(x) for x in raw.replace("\n", "").split(",") if x.strip()]

    def wave(self, ch, raw=False):
        """Read ALL waveform sample points from a channel -> (times[], volts[]).
        Default = the on-screen trace (~1200 pts, fast, ASCII). raw=True = the full
        acquisition memory (STOPs the scope, MODE RAW, chunked - slower/larger)."""
        self.lxi(f":WAVeform:SOURce CHANnel{ch}")
        self.lxi(":WAVeform:FORMat ASCii")
        if raw:
            self.stop()
            self.lxi(":WAVeform:MODE RAW")
        else:
            self.lxi(":WAVeform:MODE NORMal")
        xinc = float(self.lxi(":WAVeform:XINCrement?") or 0)
        xorig = float(self.lxi(":WAVeform:XORigin?") or 0)
        if not raw:
            v = self._parse_ascii(self.lxi(":WAVeform:DATA?"))
        else:
            pre = self.lxi(":WAVeform:PREamble?").split(",")
            npts = int(float(pre[2])) if len(pre) > 2 and pre[2].strip() else 0
            v, start, CHUNK = [], 1, 100000
            while npts and start <= npts:
                self.lxi(f":WAVeform:STARt {start}")
                self.lxi(f":WAVeform:STOP {min(start + CHUNK - 1, npts)}")
                chunk = self._parse_ascii(self.lxi(":WAVeform:DATA?"))
                if not chunk:
                    break
                v += chunk
                start += len(chunk)
        return [xorig + i * xinc for i in range(len(v))], v

    def channel(self, ch, scale=None, offset=None, probe=1, coupling="DC"):
        self.lxi(f":CHANnel{ch}:DISPlay ON")
        self.lxi(f":CHANnel{ch}:PROBe {probe}")
        self.lxi(f":CHANnel{ch}:COUPling {coupling}")
        if scale is not None:
            self.lxi(f":CHANnel{ch}:SCALe {scale}")
            got = self.lxi(f":CHANnel{ch}:SCALe?")
            try:
                if abs(float(got) - float(scale)) > 1e-6:
                    print(f"WARN: CH{ch} SCALe set to {scale} but reads {got}; retrying once",
                          file=sys.stderr)
                    self.lxi(f":CHANnel{ch}:SCALe {scale}")
            except (ValueError, TypeError):
                pass
        if offset is not None:
            self.lxi(f":CHANnel{ch}:OFFSet {offset}")

    def trigger(self, source=2, slope="POSitive", level=1.5, sweep="NORMal"):
        self.lxi(":TRIGger:MODE EDGE")
        self.lxi(f":TRIGger:EDGe:SOURce CHANnel{source}")
        self.lxi(f":TRIGger:EDGe:SLOPe {slope}")
        self.lxi(f":TRIGger:EDGe:LEVel {level}")
        self.lxi(f":TRIGger:SWEep {sweep}")

    def timebase(self, scale, offset=0):
        self.lxi(f":TIMebase:MAIN:SCALe {scale}")
        self.lxi(f":TIMebase:MAIN:OFFSet {offset}")

    def run(self):    self.lxi(":RUN")
    def stop(self):   self.lxi(":STOP")
    def single(self): self.lxi(":SINGle")

    def screenshot(self, path):
        if grab_png:
            return grab_png(self.ip, path, self.timeout + 7)
        subprocess.run(["lxi", "screenshot", "-a", self.ip, "-t", "15", path], capture_output=True)
        return path


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=HelpFormatter)
    ap.add_argument("--ip", default=DEFAULT_IP, help=f"scope IP for lxi (default {DEFAULT_IP})")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="<command>")

    p = sub.add_parser("capture-setup",
                       help="edge-triggered one-shot capture: frame a signal channel, set an edge trigger, NORMAL sweep + RUN")
    p.add_argument("--sig-ch", type=int, default=1, help="channel to read/frame (default CH1)")
    p.add_argument("--trig-ch", type=int, default=2, help="channel to trigger on (default CH2)")
    p.add_argument("--scale", type=float, default=1.0, help="V/div for the channels (default 1)")
    p.add_argument("--offset", type=float, default=-1.5,
                   help="vertical offset V (default -1.5; with scale 1 this frames a 0-3.3 V logic rail)")
    p.add_argument("--trig-level", type=float, default=1.5, help="trigger level V (default 1.5)")
    p.add_argument("--trig-slope", default="POSitive", help="POSitive | NEGative (default POSitive)")
    p.add_argument("--tb", default="2e-6", help="timebase s/div (default 2us, fits a ~1-2us pulse)")

    p = sub.add_parser("delayed-setup",
                       help="capture an event that happens N seconds AFTER the trigger: a RENDERABLE moderate "
                            "timebase + small memory, with the window offset ONTO the event")
    p.add_argument("--sig-ch", type=int, default=1, help="channel on the signal to watch (default CH1)")
    p.add_argument("--trig-ch", type=int, default=2, help="channel on the trigger edge (default CH2)")
    p.add_argument("--at", type=float, default=0.2,
                   help="seconds after the trigger to CENTER the window on (e.g. 1.5)")
    p.add_argument("--tb", default="0.05",
                   help="timebase s/div (default 0.05=50ms -> ~0.6s window). NOTE: a small mdepth only sticks at "
                        "<=~50ms/div; a wider/slower tb forces millions of points which renders the trace BLANK.")
    p.add_argument("--mdepth", default="70000", help="acquisition memory (kept small so the screenshot renders)")

    p = sub.add_parser("measure", help="one direct measurement (vmin/vmax/vavg/vpp/...)")
    p.add_argument("ch", type=int, help=CH_HELP)
    p.add_argument("item")

    p = sub.add_parser("wave", help="read ALL waveform data points from a channel -> CSV + min/max summary")
    p.add_argument("ch", type=int, help=CH_HELP)
    p.add_argument("--out", help="save CSV (time_s,volt) to this path")
    p.add_argument("--raw", action="store_true", help="full acquisition memory (STOP+RAW, slow) vs on-screen")

    p = sub.add_parser("stats", help="panel of measurements (VMAX/VMIN/VPP/VAVG/VTOP/VBASe/VAMP)")
    p.add_argument("ch", type=int, help=CH_HELP)

    p = sub.add_parser("dip",
                       help="transient analysis: depth (VMIN) + how long the signal stays below a threshold + timing")
    p.add_argument("ch", type=int, help=CH_HELP)
    p.add_argument("--threshold", type=float, default=1.5, help="threshold level in V (default 1.5)")
    p.add_argument("--raw", action="store_true", help="use full acquisition memory")

    sub.add_parser("autoset", help="scope :AUToscale to find a lost signal (re-run your setup after)")

    p = sub.add_parser("acquire", help="get/set acquisition type + memory depth")
    p.add_argument("--mode", help="NORMal | PEAK | AVERages | HRESolution  (PEAK catches narrow spikes)")
    p.add_argument("--mdepth", help="memory depth: AUTO or a number (deeper = more samples in `wave --raw`; "
                                    "BUT a big depth at a slow timebase makes screenshots render blank)")

    sub.add_parser("status", help="trigger status + sweep + timebase + channel scales - CHECK trig != STOP before an event")

    p = sub.add_parser("idle", help="free-run level on a channel (VMAX + VAVG)")
    p.add_argument("ch", type=int, help=CH_HELP)

    p = sub.add_parser("shot", help="STOP + print VMAX/VMIN on a channel + screenshot")
    p.add_argument("path")
    p.add_argument("--ch", type=int, default=1, help="channel to measure (default CH1)")

    p = sub.add_parser("screenshot", help="save a PNG of the display")
    p.add_argument("path")

    p = sub.add_parser("ch", help="set a channel (scale verified)")
    p.add_argument("ch", type=int, help=CH_HELP)
    p.add_argument("--scale", type=float)
    p.add_argument("--offset", type=float)
    p.add_argument("--probe", default=1)
    p.add_argument("--coupling", default="DC")

    p = sub.add_parser("trigger", help="set edge trigger")
    p.add_argument("--source", type=int, default=2)
    p.add_argument("--slope", default="POSitive")
    p.add_argument("--level", type=float, default=1.5)
    p.add_argument("--sweep", default="NORMal")

    p = sub.add_parser("timebase", help="set main timebase")
    p.add_argument("scale")
    p.add_argument("--offset", default=0)

    sub.add_parser("run", help="start acquisition (:RUN)")
    sub.add_parser("stop", help="stop acquisition (:STOP)")
    sub.add_parser("single", help="single-shot acquisition (:SINGle)")

    p = sub.add_parser("raw", help="send a raw SCPI string (query or set)")
    p.add_argument("scpi")

    a = ap.parse_args()
    s = Scope(a.ip)

    if a.cmd == "capture-setup":
        s.channel(a.sig_ch, scale=a.scale, offset=a.offset, probe=1, coupling="DC")
        s.channel(a.trig_ch, scale=a.scale, offset=a.offset, probe=1, coupling="DC")
        s.trigger(source=a.trig_ch, slope=a.trig_slope, level=a.trig_level, sweep="NORMal")
        s.timebase(a.tb, 0)
        s.run()
        st = s.lxi(":TRIGger:STATus?")
        print(f"capture-setup: CH{a.sig_ch}=signal, CH{a.trig_ch}=trigger "
              f"({a.trig_slope} {a.trig_level} V), NORMAL+RUN, {a.tb} s/div.")
        print(f"  trigger STATUS = {st}  (want WAIT/RUN, NOT STOP, before the event)")
        print("  Drive the event, then `rigol.py shot out.png` to capture + measure it.")
    elif a.cmd == "delayed-setup":
        s.channel(a.sig_ch, scale=1, offset=-1.5, probe=1, coupling="DC")
        s.channel(a.trig_ch, scale=1, offset=-1.5, probe=1, coupling="DC")
        s.trigger(source=a.trig_ch, slope="POSitive", level=1.5, sweep="NORMal")
        s.timebase(a.tb, a.at)               # center the window ~a.at s after the trigger (offset onto the event)
        s.lxi(f":ACQuire:MDEPth {a.mdepth}")
        s.run()
        tb_act = s.lxi(":TIMebase:MAIN:SCALe?")
        md_act = s.lxi(":ACQuire:MDEPth?")
        win = float(tb_act) * 12 if tb_act else 0
        print(f"delayed-setup: CH{a.sig_ch}=signal, CH{a.trig_ch}=trigger.")
        print(f"  ACTUAL: {float(tb_act)*1e3:.0f} ms/div (~{win:.2f}s window) centered ~{a.at}s after trigger, "
              f"mdepth={md_act}, NORMAL+RUN, status={s.lxi(':TRIGger:STATus?')}")
        try:
            if int(float(md_act)) > 200000:
                print(f"  WARN: mdepth {md_act} is DEEP -> the trace may render BLANK in a screenshot. Use a "
                      f"faster --tb (<=0.05) so a small mdepth sticks; or just read the data with "
                      f"`rigol.py wave {a.sig_ch} --out trace.csv` (data works regardless of the display).")
        except (ValueError, TypeError):
            pass
    elif a.cmd == "measure":
        v = s.measure(a.ch, a.item)
        print(f"CH{a.ch} {a.item.upper()} = {v if v is not None else '(query failed)'}")
    elif a.cmd == "wave":
        t, v = s.wave(a.ch, raw=a.raw)
        if not v:
            print("no waveform data (check channel / connection / that the scope has a trace)")
        else:
            vmin = min(v); vmax = max(v); imin = v.index(vmin)
            print(f"CH{a.ch}: {len(v)} pts  t=[{t[0]:.3e}, {t[-1]:.3e}] s  "
                  f"VMIN={vmin:.4f} V @ {t[imin]:.3e} s  VMAX={vmax:.4f} V")
            if a.out:
                with open(a.out, "w") as f:
                    f.write("time_s,volt\n")
                    for ti, vi in zip(t, v):
                        f.write(f"{ti:.9e},{vi:.6f}\n")
                print(f"saved {len(v)} samples -> {a.out}")
    elif a.cmd == "stats":
        for it in ("VMAX", "VMIN", "VPP", "VAVG", "VTOP", "VBASe", "VAMP"):
            v = s.measure(a.ch, it)
            print(f"  CH{a.ch} {it:6} = {'n/a' if v is None else v}")
    elif a.cmd == "dip":
        t, v = s.wave(a.ch, raw=a.raw)
        if not v:
            print("no waveform data (check the channel / that a trace is captured)")
        else:
            vmin = min(v); vmax = max(v); imin = v.index(vmin)
            below = [ti for ti, vi in zip(t, v) if vi < a.threshold]
            dur = (max(below) - min(below)) if below else 0.0
            if vmax < a.threshold:
                verdict = "signal stays BELOW threshold the whole time (idle low - right channel? signal powered?)"
            elif vmin < a.threshold and dur > 0.5e-6:
                verdict = "DEEP+SUSTAINED dropout"
            elif below:
                verdict = "brief dip"
            else:
                verdict = "TOO SHALLOW (never below threshold)"
            print(f"CH{a.ch}: VMIN(dip)={vmin:.4f} V @ {t[imin]:.3e} s | "
                  f"below {a.threshold} V for {dur*1e6:.2f} us ({len(below)} pts) | "
                  f"idle~VMAX={vmax:.3f} V | {verdict}")
    elif a.cmd == "autoset":
        s.lxi(":AUToscale")
        print("AUToscale sent — re-run `capture-setup` to restore your framing")
    elif a.cmd == "acquire":
        if a.mode:
            s.lxi(f":ACQuire:TYPE {a.mode}")
        if a.mdepth:
            s.lxi(f":ACQuire:MDEPth {a.mdepth}")
        print(f"acquire: TYPE={s.lxi(':ACQuire:TYPE?')}  MDEPth={s.lxi(':ACQuire:MDEPth?')}")
    elif a.cmd == "status":
        st = s.lxi(":TRIGger:STATus?")
        flag = "" if st.upper() in ("WAIT", "RUN", "AUTO", "TD") else "  <-- NOT ARMED (won't capture an event)"
        print(f"trigger STATUS = {st}{flag}")
        print(f"  sweep={s.lxi(':TRIGger:SWEep?')}  timebase={s.lxi(':TIMebase:MAIN:SCALe?')} s/div  "
              f"mdepth={s.lxi(':ACQuire:MDEPth?')}  acq={s.lxi(':ACQuire:TYPE?')}")
        for ch in (1, 2):
            print(f"  CH{ch}: disp={s.lxi(f':CHANnel{ch}:DISPlay?')} scale={s.lxi(f':CHANnel{ch}:SCALe?')} "
                  f"offset={s.lxi(f':CHANnel{ch}:OFFSet?')}")
    elif a.cmd == "idle":
        s.lxi(":TRIGger:SWEep AUTO")
        s.run()
        time.sleep(0.4)
        print(f"CH{a.ch} idle: VMAX={s.measure(a.ch,'VMAX')}  VAVG={s.measure(a.ch,'VAVG')}")
    elif a.cmd == "shot":
        s.stop()
        vmax, vmin = s.measure(a.ch, "VMAX"), s.measure(a.ch, "VMIN")
        path = s.screenshot(a.path)
        print(f"CH{a.ch} VMAX={vmax}  VMIN={vmin}  -> {path}")
    elif a.cmd == "screenshot":
        print("saved", s.screenshot(a.path))
    elif a.cmd == "ch":
        s.channel(a.ch, scale=a.scale, offset=a.offset, probe=a.probe, coupling=a.coupling)
        print(f"CH{a.ch} set; SCALe now {s.lxi(f':CHANnel{a.ch}:SCALe?')}")
    elif a.cmd == "trigger":
        s.trigger(a.source, a.slope, a.level, a.sweep); print("trigger set")
    elif a.cmd == "timebase":
        s.timebase(a.scale, a.offset); print("timebase set")
    elif a.cmd == "run":
        s.run(); print("RUN")
    elif a.cmd == "stop":
        s.stop(); print("STOP")
    elif a.cmd == "single":
        s.single(); print("SINGLE")
    elif a.cmd == "raw":
        print(s.lxi(a.scpi))


if __name__ == "__main__":
    main()

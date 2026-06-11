#!/usr/bin/env python3
"""
rigol_view.py -- live Rigol scope viewer: an auto-refreshing window so you can watch
captures as they are taken.

Two modes:
  watch (default)  display a PNG that the capture scripts overwrite each shot. Uses NO
                   scope access, so it never clashes with a running capture/sweep.
  --poll           pull a fresh screenshot from the scope yourself every --interval
                   seconds. Use only when no capture script is running (two LXI clients
                   at once can stall each other).

The watched file lives in a per-label destination folder:
<dir>/<file> (default ./rigol/scope_live.png). Point --dir at another label
("runA" -> ./runA/) or an explicit path.

Examples:
  ./rigol_view.py                              # watch ./rigol/scope_live.png
  ./rigol_view.py --poll                       # mirror the scope live (~2.5 s)
  ./rigol_view.py --dir runA                   # watch ./runA/scope_live.png
  ./rigol_view.py --file capture.png           # watch a specific capture

Leave it open in a corner of the screen; close the window to quit.
"""
import argparse
import os
import subprocess
import time
import tkinter as tk

from PIL import Image, ImageTk

from rigol_colors import ColorHelpFormatter
from rigol_pathhelper import resolve_outdir   # shared per-label output-folder helper


def pull_from_scope(scope_ip, live_path):
    """poll mode: grab a screenshot from the scope into live_path (BMP -> PNG)."""
    tmp = live_path + ".poll.bmp"
    r = subprocess.run(["lxi", "screenshot", "-a", scope_ip, "-t", "8", tmp],
                       capture_output=True, text=True)
    if r.returncode == 0:
        try:
            Image.open(tmp).save(live_path)
        except Exception:
            pass
    try:
        os.remove(tmp)
    except OSError:
        pass


class Viewer:
    def __init__(self, root, live_path, poll, scope_ip, interval):
        self.root = root
        self.live = live_path
        self.poll = poll
        self.scope_ip = scope_ip
        self.interval = interval
        self.mtime = 0
        self.last_poll = 0.0
        self.tk_img = None
        root.title("rigol scope (waiting for first capture…)")
        self.lbl = tk.Label(root, bg="black")
        self.lbl.pack(fill="both", expand=True)
        self.tick()

    def tick(self):
        now = time.time()
        if self.poll and now - self.last_poll > self.interval:
            self.last_poll = now
            pull_from_scope(self.scope_ip, self.live)
        try:
            m = os.path.getmtime(self.live)
            if m != self.mtime:
                self.mtime = m
                self.tk_img = ImageTk.PhotoImage(Image.open(self.live))
                self.lbl.configure(image=self.tk_img)
                tag = "[poll]" if self.poll else f"[watch {os.path.basename(self.live)}]"
                self.root.title(f"rigol scope — updated "
                                f"{time.strftime('%H:%M:%S', time.localtime(m))}  {tag}")
        except FileNotFoundError:
            pass
        except Exception as e:
            self.root.title(f"rigol scope — view error: {e}")
        self.root.after(400, self.tick)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=ColorHelpFormatter)
    ap.add_argument("--poll", action="store_true", help="pull screenshots from the scope yourself (no capture script running)")
    ap.add_argument("--dir", default=None, help="destination folder: a label (./<name>/) or a path (default: ./rigol/)")
    ap.add_argument("--file", default="scope_live.png", help="PNG filename to watch/update (default scope_live.png)")
    ap.add_argument("--scope-ip", default="10.0.0.10", help="Rigol scope IP (lxi, poll mode, default 10.0.0.10)")
    ap.add_argument("--interval", type=float, default=2.5, help="poll interval, s (default 2.5)")
    a = ap.parse_args()

    live = os.path.join(resolve_outdir(a.dir), a.file)
    root = tk.Tk()
    root.geometry("820x520")
    Viewer(root, live, a.poll, a.scope_ip, a.interval)
    root.mainloop()


if __name__ == "__main__":
    main()

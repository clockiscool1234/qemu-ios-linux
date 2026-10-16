#!/usr/bin/env python3
"""
tools/manageFirm.py  —  QEMU-iOS Device Manager (Linux)

Manage virtual iOS device bundles stored under a base directory (default /opt).
Device folders are named <prefix><board>_<build> (default prefix "DEV_").  The base
directory and the prefix can be changed from the Settings button (saved to
~/.config/qemu-ios/manageFirm.json) or overridden with --base / --prefix.
  •  Create devices using tools/firmwarekit.py, with optional IPSW auto-download
  •  Start / stop QEMU for a device via its generated run.sh
  •  Delete device folders

Usage:
    python3 tools/manageFirm.py [--base /opt] [--prefix DEV_] [--catalog path/to/firmware-catalog.json]

Environment:
    QEMU     Path to qemu-system-arm  (auto-detected from build/ or PATH if unset)
    BOOTROM  Path to bootrom file     (required only for m68ap / n45ap; prompted on first start)

Requirements:
    Python >= 3.8, tkinter (ships with Python on most Linux distros)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Callable, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk


# ─────────────────────────────────────────────────────────────────────────────
# Device catalog
# ─────────────────────────────────────────────────────────────────────────────

DEVICES: dict = {
    "m68ap": {
        "name":          "iPhone 2G / 1st Gen",
        "product":       "iPhone1,1",
        "qemu_machine":  "iPhone-2G",
        "soc":           "S5L8900",
        "needs_sudo":    True,
        "needs_bootrom": True,
        "builds": {
            "1A543a": "1.0",
            "4A102":  "1.1.4",
            "5A347":  "2.0",
            "7A341":  "3.0",
            "7E18":   "3.1.3",
        },
    },
    "n45ap": {
        "name":          "iPod Touch 1st Gen",
        "product":       "iPod1,1",
        "qemu_machine":  "iPod-Touch-1G",
        "soc":           "S5L8900",
        "needs_sudo":    True,
        "needs_bootrom": True,
        "builds": {
            "3A101a": "1.1",
            "4A102":  "1.1.4",
            "5A347":  "2.0",
            "7A341":  "3.0",
            "7E18":   "3.1.3",
        },
    },
    "n72ap": {
        "name":          "iPod Touch 2nd Gen",
        "product":       "iPod2,1",
        "qemu_machine":  "iPod-Touch",
        "soc":           "S5L8720",
        "needs_sudo":    False,
        "needs_bootrom": True,
        "builds": {
            "5F138": "2.1.1",
            "7A341": "3.0",
            "7E18":  "3.1.3",
            "8A293": "4.0",
            "8C148": "4.2.1",
        },
    },
    "n18ap": {
        "name":          "iPod Touch 3rd Gen",
        "product":       "iPod3,1",
        "qemu_machine":  "n18",
        "soc":           "S5L8922",
        "needs_sudo":    False,
        "needs_bootrom": False,
        "builds": {
            "7C145": "3.1.1",
            "7E18":  "3.1.3",
            "8A293": "4.0",
            "8C148": "4.2.1",
            "9B206": "5.1.1",
        },
    },
    "n88ap": {
        "name":          "iPhone 3GS",
        "product":       "iPhone2,1",
        "qemu_machine":  "n88",
        "soc":           "S5L8920",
        "needs_sudo":    False,
        "needs_bootrom": False,
        "builds": {
            "7A341": "3.0",
            "7E18":  "3.1.3",
            "8A293": "4.0",
            "8C148": "4.2.1",
            "9B206": "5.1.1",
        },
    },
    "k48ap": {
        "name":          "iPad 1st Gen",
        "product":       "iPad1,1",
        "qemu_machine":  "ipad1",
        "soc":           "S5L8930 (A4)",
        "needs_sudo":    False,
        "needs_bootrom": False,
        "builds": {
            "7B367": "3.2",
            "7B500": "3.2.2",
            "8C148": "4.2.1",
            "8J3":   "4.3.3",
            "9B206": "5.1.1",
        },
    },
    "n81ap": {
        "name":          "iPod Touch 4th Gen",
        "product":       "iPod4,1",
        "qemu_machine":  "iPod-Touch-4G",
        "soc":           "S5L8930 (A4)",
        "needs_sudo":    False,
        "needs_bootrom": False,
        "builds": {
            "8B117": "4.1",
            "8C148": "4.2.1",
            "8J2":   "4.3.3",
            "9B206": "5.1.1",
        },
    },
    "n90ap": {
        "name":          "iPhone 4 GSM",
        "product":       "iPhone3,1",
        "qemu_machine":  "iPhone-4",
        "soc":           "S5L8930 (A4)",
        "needs_sudo":    False,
        "needs_bootrom": False,
        "needs_keybag":  True,
        "builds": {
            "8A293": "4.0",
            "8A306": "4.0.1",
            "8A400": "4.0.2",
            "8B117": "4.1",
            "8C148": "4.2.1",
            "8J2":   "4.3.3",
            "9B206": "5.1.1",
        },
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Paths & constants
# ─────────────────────────────────────────────────────────────────────────────

_TOOLS_DIR  = Path(__file__).resolve().parent        # tools/
REPO_ROOT   = _TOOLS_DIR.parent
FIRMWAREKIT = _TOOLS_DIR / "firmwarekit.py"
DEFAULT_CAT = REPO_ROOT / "iphone" / "firmware-catalog.json"
IPSW_ME_API = "https://api.ipsw.me/v4/ipsw/{product}/{build}"
_UA         = "qemu-ios-manageFirm/1.0"

DEFAULT_BASE   = "/opt"
DEFAULT_PREFIX = "DEV_"
CONFIG_PATH    = (Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
                  / "qemu-ios" / "manageFirm.json")


# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────

def ipsw_filename(product: str, version: str, build: str) -> str:
    return "{}_{}_{}_Restore.ipsw".format(product, version, build)


def fetch_ipsw_download_url(product: str, build: str) -> Optional[str]:
    """Query ipsw.me for the Apple CDN URL of a specific IPSW."""
    url = IPSW_ME_API.format(product=product, build=build)
    req = urllib.request.Request(
        url, headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read()).get("url")
    except Exception:
        return None


def download_url_to_file(
    url: str,
    dest: Path,
    on_progress: Optional[Callable] = None,
) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=120) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done  = 0
        with open(str(dest), "wb") as fh:
            while True:
                chunk = resp.read(1 << 20)  # 1 MiB
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if on_progress:
                    on_progress(done, total)


def load_config() -> dict:
    """Read the saved settings (base dir, name prefix); {} if none/unreadable."""
    try:
        data = json.loads(CONFIG_PATH.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_config(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n")


def valid_prefix(prefix: str) -> bool:
    """A prefix must be non-empty and safe to use inside a directory name."""
    return bool(prefix) and not re.search(r"[/\\\0\s]", prefix)


def device_dirname(prefix: str, board: str, build: str) -> str:
    return "{}{}_{}".format(prefix, board, build)


def scan_devices(base: Path, prefix: str = DEFAULT_PREFIX) -> list:
    """Return a list of device-info dicts for every <prefix><board>_<build> dir."""
    out = []
    if not base.is_dir():
        return out
    pat = re.compile(
        r"^" + re.escape(prefix) + r"(?P<board>[A-Za-z0-9]+)_(?P<build>.+)$")
    for entry in sorted(base.iterdir()):
        if not entry.is_dir():
            continue
        m = pat.match(entry.name)
        if not m:
            continue
        board, build = m.group("board"), m.group("build")
        dev = DEVICES.get(board, {})
        identity = {}
        id_path = entry / "identity.json"
        if id_path.exists():
            try:
                identity = json.loads(id_path.read_text())
            except Exception:
                pass
        out.append({
            "path":        entry,
            "board":       board,
            "build":       build,
            "device_name": dev.get("name", board),
            "ios_version": dev.get("builds", {}).get(build, build),
            "has_run_sh":  (entry / "run.sh").exists(),
            "identity":    identity,
        })
    return out


def locate_qemu() -> Optional[str]:
    """Auto-detect qemu-system-arm from common locations."""
    candidates = [
        os.environ.get("QEMU", ""),
        str(REPO_ROOT / "build" / "qemu-system-arm"),
        shutil.which("qemu-system-arm") or "",
        "/usr/local/bin/qemu-system-arm",
        "/usr/bin/qemu-system-arm",
    ]
    for c in candidates:
        if c and Path(c).is_file():
            return c
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Create-Device dialog
# ─────────────────────────────────────────────────────────────────────────────

class CreateDeviceDialog(tk.Toplevel):
    """Wizard dialog that wraps firmwarekit.py to create a device bundle."""

    def __init__(
        self,
        parent,
        base_dir: Path,
        prefix:   str,
        catalog:  Path,
        log_fn:   Callable,
    ) -> None:
        super().__init__(parent)
        self.title("New Virtual Device")
        self.resizable(False, False)
        self.grab_set()
        self.transient(parent)

        self._base    = base_dir
        self._prefix  = prefix
        self._catalog = catalog
        self._log     = log_fn
        self._proc    = None
        self._board_keys = list(DEVICES.keys())
        self._build_keys = []

        self._build_widgets()
        self._refresh_board()
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ── widgets ──────────────────────────────────────────────────────────────

    def _build_widgets(self) -> None:
        P = {"padx": 8, "pady": 4, "sticky": "w"}
        f = ttk.Frame(self, padding=8)
        f.pack(fill="both", expand=True)
        row = 0

        # Device type
        ttk.Label(f, text="Device:").grid(row=row, column=0, **P)
        names = ["{name}  [{key}]".format(name=DEVICES[k]["name"], key=k)
                 for k in self._board_keys]
        self._board_var = tk.StringVar()
        self._board_cb  = ttk.Combobox(f, textvariable=self._board_var,
                                        values=names, state="readonly", width=42)
        self._board_cb.grid(row=row, column=1, columnspan=2, **P)
        self._board_cb.current(0)
        self._board_cb.bind("<<ComboboxSelected>>",
                            lambda _: self._refresh_board())
        row += 1

        # iOS build
        ttk.Label(f, text="iOS Build:").grid(row=row, column=0, **P)
        self._build_var = tk.StringVar()
        self._build_cb  = ttk.Combobox(f, textvariable=self._build_var,
                                        state="readonly", width=42)
        self._build_cb.grid(row=row, column=1, columnspan=2, **P)
        self._build_cb.bind("<<ComboboxSelected>>",
                            lambda _: self._refresh_out())
        row += 1

        # IPSW source radio
        ttk.Label(f, text="IPSW:").grid(row=row, column=0, **P)
        self._ipsw_mode = tk.StringVar(value="browse")
        ttk.Radiobutton(f, text="Browse file",
                         variable=self._ipsw_mode, value="browse",
                         command=self._toggle_ipsw).grid(row=row, column=1, **P)
        ttk.Radiobutton(f, text="Auto-download (ipsw.me)",
                         variable=self._ipsw_mode, value="download",
                         command=self._toggle_ipsw).grid(row=row, column=2, **P)
        row += 1

        # IPSW path entry
        self._ipsw_var   = tk.StringVar()
        self._ipsw_entry = ttk.Entry(f, textvariable=self._ipsw_var, width=36)
        self._ipsw_entry.grid(row=row, column=1, **P)
        self._ipsw_brow  = ttk.Button(f, text="Browse…",
                                       command=self._browse_ipsw)
        self._ipsw_brow.grid(row=row, column=2, **P)
        row += 1

        # Output path
        ttk.Label(f, text="Output path:").grid(row=row, column=0, **P)
        self._out_var = tk.StringVar()
        ttk.Entry(f, textvariable=self._out_var, width=36).grid(
            row=row, column=1, **P)
        ttk.Button(f, text="Browse…", command=self._browse_out).grid(
            row=row, column=2, **P)
        row += 1

        # Catalog
        ttk.Label(f, text="Catalog JSON:").grid(row=row, column=0, **P)
        self._cat_var = tk.StringVar(value=str(self._catalog))
        ttk.Entry(f, textvariable=self._cat_var, width=36).grid(
            row=row, column=1, **P)
        ttk.Button(f, text="Browse…", command=self._browse_cat).grid(
            row=row, column=2, **P)
        row += 1

        # Bootrom
        ttk.Label(f, text="Bootrom:").grid(row=row, column=0, **P)
        self._bootrom_var   = tk.StringVar()
        self._bootrom_entry = ttk.Entry(f, textvariable=self._bootrom_var, width=36)
        self._bootrom_entry.grid(row=row, column=1, **P)
        self._bootrom_brow  = ttk.Button(f, text="Browse…",
                                          command=self._browse_bootrom)
        self._bootrom_brow.grid(row=row, column=2, **P)
        row += 1

        self._bootrom_hint = ttk.Label(f, text="", foreground="gray")
        self._bootrom_hint.grid(row=row, column=1, columnspan=2, **P)
        row += 1

        # Seed
        ttk.Label(f, text="Seed (optional):").grid(row=row, column=0, **P)
        self._seed_var = tk.StringVar()
        ttk.Entry(f, textvariable=self._seed_var, width=36).grid(
            row=row, column=1, columnspan=2, **P)
        row += 1

        # Status label + progress bar
        self._status_var = tk.StringVar(value="Ready.")
        ttk.Label(f, textvariable=self._status_var,
                  foreground="gray").grid(row=row, column=0, columnspan=3, **P)
        row += 1
        self._pbar = ttk.Progressbar(f, mode="indeterminate", length=500)
        self._pbar.grid(row=row, column=0, columnspan=3, padx=8, pady=4,
                        sticky="ew")
        row += 1

        # Action buttons
        bf = ttk.Frame(f)
        bf.grid(row=row, column=0, columnspan=3, pady=8)
        self._create_btn = ttk.Button(bf, text="Create Device",
                                       command=self._on_create)
        self._create_btn.pack(side="left", padx=6)
        ttk.Button(bf, text="Cancel", command=self._close).pack(
            side="left", padx=6)

    # ── helpers ──────────────────────────────────────────────────────────────

    def _cur_board(self) -> str:
        return self._board_keys[self._board_cb.current()]

    def _cur_build(self) -> str:
        i = self._build_cb.current()
        return self._build_keys[i] if (i >= 0 and self._build_keys) else ""

    def _refresh_board(self) -> None:
        board = self._cur_board()
        dev   = DEVICES[board]
        self._build_keys = list(dev["builds"].keys())
        self._build_cb["values"] = [
            "{}  (iOS {})".format(b, v) for b, v in dev["builds"].items()
        ]
        if self._build_keys:
            self._build_cb.current(0)

        needs_br = dev.get("needs_bootrom", False)
        br_state = "normal" if needs_br else "disabled"
        self._bootrom_entry.configure(state=br_state)
        self._bootrom_brow.configure(state=br_state)
        self._bootrom_hint.configure(
            text="Required for this board" if needs_br
                 else "Not required for this board",
            foreground="red" if needs_br else "gray",
        )
        self._refresh_out()

    def _refresh_out(self) -> None:
        board = self._cur_board()
        build = self._cur_build()
        self._out_var.set(str(self._base / device_dirname(self._prefix, board, build)))

    def _toggle_ipsw(self) -> None:
        is_browse = self._ipsw_mode.get() == "browse"
        self._ipsw_entry.configure(state="normal" if is_browse else "disabled")
        self._ipsw_brow.configure(state="normal" if is_browse else "disabled")

    def _browse_ipsw(self) -> None:
        p = filedialog.askopenfilename(
            parent=self, title="Select IPSW",
            filetypes=[("IPSW files", "*.ipsw"), ("All files", "*.*")])
        if p:
            self._ipsw_var.set(p)

    def _browse_out(self) -> None:
        p = filedialog.askdirectory(parent=self, title="Select output directory")
        if p:
            self._out_var.set(p)

    def _browse_cat(self) -> None:
        p = filedialog.askopenfilename(
            parent=self, title="Select firmware-catalog.json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if p:
            self._cat_var.set(p)

    def _browse_bootrom(self) -> None:
        p = filedialog.askopenfilename(parent=self, title="Select bootrom file")
        if p:
            self._bootrom_var.set(p)

    def _ui(self, fn: Callable, delay: int = 0) -> None:
        """Run fn on the Tk thread, but only if this dialog still exists.

        The create flow runs in a worker thread and keeps reporting progress
        after the dialog was closed; touching destroyed widgets raised the
        'invalid command name ...progressbar' TclErrors.
        """
        def _run():
            try:
                if self.winfo_exists():
                    fn()
            except tk.TclError:
                pass
        try:
            self.after(delay, _run)
        except (tk.TclError, RuntimeError):
            pass

    def _set_status(self, msg: str, busy: bool = False) -> None:
        def _do():
            self._status_var.set(msg)
            if busy:
                self._pbar.start(10)
            else:
                self._pbar.stop()
        self._ui(_do)

    # ── create flow ──────────────────────────────────────────────────────────

    def _on_create(self) -> None:
        board = self._cur_board()
        build = self._cur_build()
        dev   = DEVICES[board]
        out   = self._out_var.get().strip()
        cat   = self._cat_var.get().strip()

        if not out:
            messagebox.showwarning("Missing field",
                                   "Specify an output path.", parent=self)
            return
        if not cat or not Path(cat).exists():
            messagebox.showwarning(
                "Missing catalog",
                "firmware-catalog.json not found.\n"
                "Browse for it in the Catalog JSON field.", parent=self)
            return
        if dev.get("needs_bootrom") and not self._bootrom_var.get().strip():
            messagebox.showwarning("Missing bootrom",
                                   "This board requires a bootrom file.",
                                   parent=self)
            return

        self._create_btn.configure(state="disabled")

        if self._ipsw_mode.get() == "browse":
            ipsw = self._ipsw_var.get().strip()
            if not ipsw or not Path(ipsw).exists():
                messagebox.showwarning("Missing IPSW",
                                       "Select a valid IPSW file.", parent=self)
                self._create_btn.configure(state="normal")
                return
            threading.Thread(
                target=self._run_create,
                args=(board, dev, build, ipsw, out, cat),
                daemon=True,
            ).start()
        else:
            threading.Thread(
                target=self._download_and_create,
                args=(board, dev, build, out, cat),
                daemon=True,
            ).start()

    def _download_and_create(
        self, board: str, dev: dict, build: str, out: str, cat: str
    ) -> None:
        product = dev["product"]
        version = dev["builds"][build]
        self._set_status(
            "Fetching IPSW URL for {} {}…".format(product, version), busy=True)

        dl_url = fetch_ipsw_download_url(product, build)
        if not dl_url:
            self._set_status(
                "Could not find IPSW on ipsw.me.  Try browsing for the file.")
            self._ui(lambda: self._create_btn.configure(state="normal"))
            return

        fname = ipsw_filename(product, version, build)
        dest  = Path("/tmp") / fname

        if not dest.exists():
            def _progress(done: int, total: int) -> None:
                if total:
                    pct = "{}%".format(done * 100 // total)
                else:
                    pct = "{} MiB".format(done // (1 << 20))
                self._set_status(
                    "Downloading {}… {}".format(fname, pct), busy=True)

            try:
                download_url_to_file(dl_url, dest, _progress)
            except Exception as exc:
                self._set_status("Download error: {}".format(exc))
                try:
                    dest.unlink()
                except OSError:
                    pass
                self._ui(lambda: self._create_btn.configure(state="normal"))
                return

        self._set_status("Download complete. Running firmwarekit.py…", busy=True)
        self._run_create(board, dev, build, str(dest), out, cat)

    @staticmethod
    def _as_root(cmd: list) -> list:
        """Prefix cmd so it runs as root, via pkexec (sudo if pkexec is absent).

        pkexec starts the program in a sanitised environment and in root's
        home directory, so relative paths are made absolute and the variables
        firmwarekit needs are passed explicitly through env(1).
        """
        if not shutil.which("pkexec"):
            return ["sudo", "-E"] + cmd
        fwd = ["{}={}".format(k, os.environ[k])
               for k in ("BOOTROM", "QEMU") if os.environ.get(k)]
        return ["pkexec", "env"] + fwd + cmd

    def _run_create(
        self, board: str, dev: dict, build: str,
        ipsw: str, out: str, cat: str
    ) -> None:
        ipsw, cat, out = (os.path.abspath(os.path.expanduser(x))
                          for x in (ipsw, cat, out))
        cmd = [
            sys.executable, str(FIRMWAREKIT), "create",
            "--ipsw",    ipsw,
            "--catalog", cat,
            "--id",      "{}-{}".format(board, build),
            "--out",     out,
        ]
        seed    = self._seed_var.get().strip()
        bootrom = self._bootrom_var.get().strip()
        if seed:
            cmd += ["--seed", seed]
        if bootrom:
            os.environ["BOOTROM"] = os.path.abspath(os.path.expanduser(bootrom))
        if dev.get("needs_sudo"):
            cmd = self._as_root(cmd)

        try:
            Path(out).parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass    # firmwarekit (as root) may still be able to create it

        self._set_status("Running firmwarekit.py…", busy=True)
        self._log("$ " + " ".join(str(x) for x in cmd))

        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in self._proc.stdout:
                self._log(line.rstrip())
            self._proc.wait()
            rc = self._proc.returncode
            if rc == 0:
                self._set_status("Device created successfully!")
                self._ui(self._close, 2500)
            else:
                self._set_status(
                    "firmwarekit.py exited with code {}.".format(rc))
        except Exception as exc:
            self._set_status("Error: {}".format(exc))
        finally:
            self._proc = None
            self._ui(lambda: self._create_btn.configure(state="normal"))

    # ── close ────────────────────────────────────────────────────────────────

    def _close(self) -> None:
        if self._proc and self._proc.poll() is None:
            if not messagebox.askyesno(
                "In progress",
                "firmwarekit.py is still running.  Abort?", parent=self):
                return
            self._proc.terminate()
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Settings dialog
# ─────────────────────────────────────────────────────────────────────────────

class SettingsDialog(tk.Toplevel):
    """Change where devices live and how their folders are named."""

    def __init__(self, parent, base_dir: Path, prefix: str,
                 on_save: Callable) -> None:
        super().__init__(parent)
        self.title("Settings")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self._on_save = on_save

        P = {"padx": 8, "pady": 4, "sticky": "w"}
        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)

        ttk.Label(f, text="Device folder:").grid(row=0, column=0, **P)
        self._base_var = tk.StringVar(value=str(base_dir))
        ttk.Entry(f, textvariable=self._base_var, width=44).grid(
            row=0, column=1, **P)
        ttk.Button(f, text="Browse…", command=self._browse).grid(
            row=0, column=2, **P)

        ttk.Label(f, text="Name prefix:").grid(row=1, column=0, **P)
        self._prefix_var = tk.StringVar(value=prefix)
        ttk.Entry(f, textvariable=self._prefix_var, width=20).grid(
            row=1, column=1, **P)

        self._example = ttk.Label(f, text="", foreground="gray")
        self._example.grid(row=2, column=1, columnspan=2, **P)
        ttk.Label(
            f, foreground="gray", wraplength=480, justify="left",
            text="Only folders named <prefix><board>_<build> inside the device "
                 "folder are listed, so devices created with a different "
                 "prefix or in another folder will not show up.",
        ).grid(row=3, column=0, columnspan=3, **P)

        bf = ttk.Frame(f)
        bf.grid(row=4, column=0, columnspan=3, pady=8)
        ttk.Button(bf, text="Save", command=self._save).pack(side="left", padx=6)
        ttk.Button(bf, text="Cancel", command=self.destroy).pack(
            side="left", padx=6)

        self._base_var.trace_add("write", lambda *_: self._update_example())
        self._prefix_var.trace_add("write", lambda *_: self._update_example())
        self._update_example()

    def _update_example(self) -> None:
        self._example.configure(text="Example:  {}".format(
            Path(self._base_var.get().strip() or ".")
            / device_dirname(self._prefix_var.get().strip(), "n88ap", "9B206")))

    def _browse(self) -> None:
        cur = Path(os.path.expanduser(self._base_var.get().strip() or "~"))
        while not cur.is_dir() and cur != cur.parent:
            cur = cur.parent
        p = filedialog.askdirectory(parent=self, initialdir=str(cur),
                                    title="Select device folder")
        if p:
            self._base_var.set(p)

    def _save(self) -> None:
        raw    = self._base_var.get().strip()
        prefix = self._prefix_var.get().strip()
        if not raw:
            messagebox.showwarning("Missing folder",
                                   "Specify a device folder.", parent=self)
            return
        base = Path(os.path.expanduser(raw))
        if base.exists() and not base.is_dir():
            messagebox.showwarning("Not a folder",
                                   "{} is not a folder.".format(base),
                                   parent=self)
            return
        if not valid_prefix(prefix):
            messagebox.showwarning(
                "Invalid prefix",
                "The prefix must not be empty and must not contain spaces "
                "or slashes.", parent=self)
            return
        self._on_save(base, prefix)
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Main window
# ─────────────────────────────────────────────────────────────────────────────

class App(tk.Tk):

    def __init__(self, base_dir: Path, catalog: Path,
                 prefix: str = DEFAULT_PREFIX) -> None:
        super().__init__()
        self.title("QEMU-iOS Device Manager")
        self.geometry("980x650")
        self.minsize(720, 460)

        self._base    = base_dir
        self._prefix  = prefix
        self._catalog = catalog
        self._devs: list    = []
        self._running: dict = {}   # path_str → subprocess.Popen

        self._build_ui()
        self.refresh()
        self.protocol("WM_DELETE_WINDOW", self._on_quit)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        try:
            ttk.Style(self).theme_use("clam")
        except Exception:
            pass

        # ── Toolbar ──────────────────────────────────────────────────────────
        tb = ttk.Frame(self, relief="raised", padding=(4, 2))
        tb.pack(fill="x", side="top")

        def tb_btn(label: str, cmd) -> ttk.Button:
            b = ttk.Button(tb, text=label, command=cmd)
            b.pack(side="left", padx=3, pady=2)
            return b

        tb_btn("+ New Device",  self._new_device)
        tb_btn("▶  Start",     self._start_device)
        tb_btn("■  Stop",      self._stop_device)
        tb_btn("✕  Delete",    self._delete_device)
        ttk.Separator(tb, orient="vertical").pack(
            side="left", fill="y", padx=6, pady=2)
        tb_btn("↺  Refresh",  self.refresh)
        tb_btn("⚙  Settings", self._open_settings)
        self._base_lbl = ttk.Label(tb, foreground="gray")
        self._base_lbl.pack(side="right", padx=8)
        self._update_base_label()

        # ── Vertical pane ─────────────────────────────────────────────────────
        vp = ttk.PanedWindow(self, orient="vertical")
        vp.pack(fill="both", expand=True, padx=4, pady=(2, 0))

        # Device list
        lf = ttk.Frame(vp)
        vp.add(lf, weight=4)

        cols = ("Device", "Board", "iOS", "Status", "Path")
        self._tree = ttk.Treeview(lf, columns=cols, show="headings",
                                   selectmode="browse")
        for col, width in zip(cols, (220, 90, 72, 84, 360)):
            self._tree.heading(col, text=col,
                               command=lambda c=col: self._sort_col(c))
            self._tree.column(col, width=width, minwidth=50, anchor="w")

        self._tree.tag_configure("running", foreground="#1a7a1a",
                                  font=("", 9, "bold"))
        self._tree.tag_configure("stopped", foreground="#555555")
        self._tree.tag_configure("missing",  foreground="#bb2200")

        vsb = ttk.Scrollbar(lf, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(lf, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        lf.rowconfigure(0, weight=1)
        lf.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Double-1>", lambda _: self._start_device())

        # Device detail strip
        df = ttk.LabelFrame(vp, text="Device Details", padding=4)
        vp.add(df, weight=1)
        self._detail = scrolledtext.ScrolledText(
            df, height=6, state="disabled",
            font=("Monospace", 9), wrap="none")
        self._detail.pack(fill="both", expand=True)

        # Log panel
        log_f = ttk.LabelFrame(self, text="Log", padding=4)
        log_f.pack(fill="both", expand=False, side="bottom",
                   padx=4, pady=(0, 4))
        self._log_box = scrolledtext.ScrolledText(
            log_f, height=7, state="disabled",
            font=("Monospace", 9), wrap="none")
        self._log_box.pack(fill="both", expand=True, side="left")
        ttk.Button(log_f, text="Clear",
                   command=self._clear_log).pack(
            side="right", anchor="n", padx=2, pady=2)

    # ── Data management ───────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Rescan the base directory and repopulate the device list."""
        # clean up finished processes
        for k in list(self._running.keys()):
            if self._running[k].poll() is not None:
                del self._running[k]

        self._devs = scan_devices(self._base, self._prefix)
        sel = self._sel_iid()
        self._tree.delete(*self._tree.get_children())

        for d in self._devs:
            ps      = str(d["path"])
            running = ps in self._running
            has_run = d["has_run_sh"]
            status  = ("Running" if running
                       else ("Ready" if has_run else "No run.sh"))
            tag     = ("running" if running
                       else ("stopped" if has_run else "missing"))
            self._tree.insert(
                "", "end", iid=ps,
                values=(d["device_name"], d["board"],
                        d["ios_version"], status, ps),
                tags=(tag,))

        if sel and self._tree.exists(sel):
            self._tree.selection_set(sel)

    def _dev_for(self, iid: str) -> Optional[dict]:
        return next((d for d in self._devs if str(d["path"]) == iid), None)

    def _sel_iid(self) -> Optional[str]:
        s = self._tree.selection()
        return s[0] if s else None

    def _sort_col(self, col: str) -> None:
        rows = [(self._tree.set(iid, col), iid)
                for iid in self._tree.get_children("")]
        rows.sort()
        for i, (_, iid) in enumerate(rows):
            self._tree.move(iid, "", i)

    # ── Toolbar actions ───────────────────────────────────────────────────────

    def _update_base_label(self) -> None:
        self._base_lbl.configure(text="  Base: {}   Prefix: {}".format(
            self._base, self._prefix))

    def _open_settings(self) -> None:
        dlg = SettingsDialog(self, self._base, self._prefix, self._apply_settings)
        self.wait_window(dlg)

    def _apply_settings(self, base: Path, prefix: str) -> None:
        self._base, self._prefix = base, prefix
        self._update_base_label()
        try:
            save_config({"base": str(base), "prefix": prefix})
        except OSError as exc:
            messagebox.showwarning(
                "Settings not saved",
                "Applied for this session, but could not write {}:\n{}".format(
                    CONFIG_PATH, exc))
        self.log("Device folder: {}   Prefix: {}".format(base, prefix))
        self.refresh()
        self._on_select()

    def _new_device(self) -> None:
        dlg = CreateDeviceDialog(self, self._base, self._prefix,
                                 self._catalog, self.log)
        self.wait_window(dlg)
        self.refresh()

    def _start_device(self) -> None:
        iid = self._sel_iid()
        if not iid:
            messagebox.showinfo("No selection", "Select a device to start.")
            return
        if iid in self._running:
            messagebox.showinfo("Already running",
                                "This device is already running.")
            return
        d = self._dev_for(iid)
        if not d:
            return
        if not d["has_run_sh"]:
            messagebox.showerror(
                "No run.sh",
                "run.sh not found in {}.\n"
                "Re-create the device to generate it.".format(d["path"]))
            return

        env = dict(os.environ)

        # Locate qemu-system-arm
        qemu = locate_qemu()
        if not qemu:
            qemu = filedialog.askopenfilename(
                parent=self, title="Locate qemu-system-arm binary",
                filetypes=[("qemu-system-arm", "qemu-system-arm"),
                           ("All files", "*.*")])
            if not qemu:
                return
        env["QEMU"] = qemu

        # Bootrom (m68ap / n45ap only)
        dev_meta = DEVICES.get(d["board"], {})
        if dev_meta.get("needs_bootrom"):
            bootrom = env.get("BOOTROM", "")
            if not bootrom or not Path(bootrom).exists():
                bootrom = filedialog.askopenfilename(
                    parent=self, title="Locate bootrom file")
                if not bootrom:
                    return
            env["BOOTROM"] = bootrom

        run_sh = d["path"] / "run.sh"
        label  = "{device_name}  [{board}-{build}]".format(**d)
        self.log("Starting {}  •  QEMU={}".format(label, qemu))

        try:
            proc = subprocess.Popen(
                ["bash", str(run_sh)],
                cwd=str(d["path"]),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            )
            self._running[iid] = proc
            self.refresh()
            self.log("  PID {} launched.".format(proc.pid))
            threading.Thread(
                target=self._wait_exit,
                args=(iid, proc, label),
                daemon=True,
            ).start()
        except Exception as exc:
            messagebox.showerror("Launch error", str(exc))

    def _wait_exit(
        self, iid: str, proc: subprocess.Popen, label: str
    ) -> None:
        try:
            for line in proc.stdout:        # run.sh / QEMU output -> Log panel
                self.log(line.rstrip())
        except Exception:
            pass
        proc.wait()
        self._running.pop(iid, None)
        self.after(0, self.refresh)
        self.after(0, lambda: self.log(
            "{} exited (code {}).".format(label, proc.returncode)))

    def _stop_device(self) -> None:
        iid = self._sel_iid()
        if not iid:
            messagebox.showinfo("No selection", "Select a device to stop.")
            return
        proc = self._running.get(iid)
        if not proc or proc.poll() is not None:
            messagebox.showinfo("Not running",
                                "This device is not currently running.")
            return
        proc.terminate()
        self.log("Stop signal (SIGTERM) sent.")

    def _delete_device(self) -> None:
        iid = self._sel_iid()
        if not iid:
            messagebox.showinfo("No selection", "Select a device to delete.")
            return
        if iid in self._running:
            messagebox.showwarning("Running",
                                   "Stop the device before deleting it.")
            return
        d = self._dev_for(iid)
        if not d:
            return
        if not messagebox.askyesno(
            "Confirm delete",
            "Permanently delete:\n\n"
            "  {device_name}  [{board}-{build}]\n"
            "  {path}\n\n"
            "This cannot be undone.".format(**d),
        ):
            return
        path = str(d["path"])
        try:
            shutil.rmtree(path)
        except PermissionError as exc:
            # Devices created as root (m68ap / n45ap) are root-owned.
            if not (shutil.which("pkexec") and messagebox.askyesno(
                    "Permission denied",
                    "Some files are owned by root:\n{}\n\n"
                    "Retry with administrator privileges (pkexec)?".format(exc))):
                messagebox.showerror("Delete error", str(exc))
                self.refresh()
                return
            r = subprocess.run(["pkexec", "rm", "-rf", "--", path],
                               capture_output=True, text=True)
            if r.returncode != 0:
                messagebox.showerror(
                    "Delete error", (r.stderr or "pkexec failed").strip())
                self.refresh()
                return
        except Exception as exc:
            messagebox.showerror("Delete error", str(exc))
            self.refresh()
            return
        self.log("Deleted {}.".format(path))
        self.refresh()
        self._on_select()

    # ── Detail panel ──────────────────────────────────────────────────────────

    def _on_select(self, *_) -> None:
        iid = self._sel_iid()
        d   = self._dev_for(iid) if iid else None
        self._detail.configure(state="normal")
        self._detail.delete("1.0", "end")
        if d:
            dev     = DEVICES.get(d["board"], {})
            running = iid in self._running
            proc    = self._running.get(iid)
            pid_str = ("Running  (PID {})".format(proc.pid)
                       if running and proc else "Stopped")
            lines = [
                "Device       {}".format(d["device_name"]),
                "Board ID     {}".format(d["board"]),
                "Build        {}".format(d["build"]),
                "iOS          {}".format(d["ios_version"]),
                "SoC          {}".format(dev.get("soc", "?")),
                "QEMU -M      {}".format(dev.get("qemu_machine", "?")),
                "Needs root   {}".format("Yes" if dev.get("needs_sudo") else "No"),
                "Bootrom      {}".format(
                    "Required" if dev.get("needs_bootrom") else "Not required"),
                "Status       {}".format(pid_str),
                "Path         {}".format(d["path"]),
            ]
            if d["identity"]:
                lines += ["", "── Identity ──────────────────────────────"]
                for k, v in d["identity"].items():
                    lines.append("  {:<20} {}".format(k, v))
            self._detail.insert("end", "\n".join(lines))
        self._detail.configure(state="disabled")

    # ── Log ───────────────────────────────────────────────────────────────────

    def log(self, msg: str) -> None:
        def _do() -> None:
            self._log_box.configure(state="normal")
            self._log_box.insert("end", msg + "\n")
            self._log_box.see("end")
            self._log_box.configure(state="disabled")
        self.after(0, _do)

    def _clear_log(self) -> None:
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.configure(state="disabled")

    # ── Quit ──────────────────────────────────────────────────────────────────

    def _on_quit(self) -> None:
        still_running = [iid for iid, p in self._running.items()
                         if p.poll() is None]
        if still_running:
            n = len(still_running)
            if not messagebox.askyesno(
                "Devices still running",
                "{} device{} still running.\nQuit anyway (leave them running)?".format(
                    n, "s" if n != 1 else ""),
            ):
                return
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="GUI device manager for qemu-ios-linux virtual iOS devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment
  QEMU     qemu-system-arm binary  (auto-detected from build/ or PATH if unset)
  BOOTROM  bootrom dump path       (m68ap / n45ap only; prompted on first start)

Examples
  python3 tools/manageFirm.py
  python3 tools/manageFirm.py --base ~/ios-devices --prefix MY_
  QEMU=build/qemu-system-arm python3 tools/manageFirm.py
""")
    ap.add_argument("--base", default=None,
                    help="Directory that holds the device folders  (default: saved "
                         "setting, else {})".format(DEFAULT_BASE))
    ap.add_argument("--prefix", default=None,
                    help="Device folder name prefix  (default: saved setting, "
                         "else {})".format(DEFAULT_PREFIX))
    ap.add_argument("--catalog", default=str(DEFAULT_CAT),
                    help="Path to firmware-catalog.json  (default: {})".format(
                        DEFAULT_CAT))
    args = ap.parse_args()

    cfg     = load_config()
    base    = Path(os.path.expanduser(
        args.base or cfg.get("base") or DEFAULT_BASE))
    prefix  = args.prefix or cfg.get("prefix") or DEFAULT_PREFIX
    if not valid_prefix(prefix):
        print("[warn] Invalid prefix {!r}; using {!r}.".format(
            prefix, DEFAULT_PREFIX))
        prefix = DEFAULT_PREFIX
    catalog = Path(args.catalog)

    if not base.exists():
        print("[info] Base directory {!r} does not exist yet; "
              "it will be populated when the first device is created.".format(
                  str(base)))
    if not catalog.exists():
        print("[warn] Catalog not found at {!r}; "
              "you can browse for it in the Create Device dialog.".format(
                  str(catalog)))

    App(base, catalog, prefix).mainloop()


if __name__ == "__main__":
    main()
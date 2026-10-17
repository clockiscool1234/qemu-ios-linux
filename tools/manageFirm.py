#!/usr/bin/env python3
"""
tools/manageFirm.py  —  QEMU-iOS Device Manager (Linux)

Manage virtual iOS device bundles stored under a base directory (default /opt).
Device folders are named <prefix><board>_<build> (default prefix "DEV_").  The base
directory and the prefix can be changed from the Settings button (saved to
~/.config/qemu-ios/manageFirm.json) or overridden with --base / --prefix.
  •  Create devices using tools/firmwarekit.py, with optional IPSW auto-download
     (progress bar; uses aria2c -x16 -s16 when installed) and the chosen bootrom
     copied into the device folder
  •  Optional "Jailbreak the device" checkbox on New Virtual Device (firmwarekit create
     --jailbreak: afc2 + Cydia; iPhone OS 2.0+; runs as root)
  •  Start / stop QEMU for a device via its generated run.sh
  •  Delete device folders
  •  firmwarekit's scratch (work) directory is created inside the device folder
     (removed automatically when the create finishes); downloaded IPSWs go to your
     Downloads folder, or the folder chosen in Settings / --downloads
  •  Every build in firmware-catalog.json is offered per device (final releases,
     developer / beta seeds, iOS 6 / 7 on the boards that can run them); builds the
     catalog marks "coming soon" can be shown with a checkbox
  •  Per-device preferences (name, verbose boot, boot-args, RAM, USB connection,
     baseband on/off, carrier name, window scale and rotation, sound, extra QEMU
     arguments), saved in the same config file and applied when the device is started
  •  QEMU quits by itself when the guest powers off (switched off from the iPhone's
     own UI); each device gets a private QMP socket for that

Usage:
    python3 tools/manageFirm.py [--base /opt] [--prefix DEV_] [--downloads ~/Downloads]
                                [--catalog path/to/firmware-catalog.json]

Environment:
    QEMU     Path to qemu-system-arm  (auto-detected from build/ or PATH if unset)
    BOOTROM  Path to bootrom file     (only for devices created without a bundled bootrom;
                                       m68ap / n45ap / n72ap bundle the one picked at creation)

Requirements:
    Python >= 3.8, tkinter (ships with Python on most Linux distros)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
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
        "needs_sudo":    True,       # create loop-mounts the rootfs to build the NAND
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
        "needs_sudo":    True,
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
        "needs_sudo":    True,
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
        "needs_sudo":    True,
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
TOUCH_PANEL = _TOOLS_DIR / "touchPanel.py"
DEFAULT_CAT = next((p for p in (_TOOLS_DIR / "firmware-catalog.json",
                                REPO_ROOT / "iphone" / "firmware-catalog.json")
                    if p.is_file()), _TOOLS_DIR / "firmware-catalog.json")
IPSW_ME_API = "https://api.ipsw.me/v4/ipsw/{product}/{build}"
_UA         = "qemu-ios-manageFirm/1.0"

DEFAULT_BASE   = "/opt"
DEFAULT_PREFIX = "DEV_"
CONFIG_PATH    = (Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
                  / "qemu-ios" / "manageFirm.json")


# ─────────────────────────────────────────────────────────────────────────────
# Hardware hints and firmware-catalog merge
# ─────────────────────────────────────────────────────────────────────────────

# Real-hardware RAM (MB) and native screen (px).  The guest framebuffer is fixed by the
# emulated hardware, so the "screen" preference scales the *window*, not the guest.
_HW = {
    "m68ap": (128, (320, 480)),
    "n45ap": (128, (320, 480)),
    "n72ap": (128, (320, 480)),
    "n18ap": (256, (320, 480)),
    "n88ap": (256, (320, 480)),
    "k48ap": (256, (1024, 768)),
    "n81ap": (256, (640, 960)),
    "n90ap": (512, (640, 960)),
}
for _b, (_ram, _scr) in _HW.items():
    DEVICES[_b]["ram_mb"] = _ram
    DEVICES[_b]["screen"] = _scr

_BASE_BUILDS = {b: dict(d["builds"]) for b, d in DEVICES.items()}
CATALOG_ENTRIES: dict = {}          # (board, build) -> catalog entry


def apply_catalog(path) -> int:
    """Merge firmware-catalog.json into DEVICES[*]["builds"].

    Every catalog entry for a known board becomes a selectable build (final releases,
    developer / beta seeds, iOS 6 / 7 where the board supports them); the built-in list
    is kept for builds the catalog lacks.  Returns the number of entries merged (0 if
    the catalog is missing or unreadable, in which case the built-in list is used).
    """
    CATALOG_ENTRIES.clear()
    for board, dev in DEVICES.items():
        dev["builds"] = dict(_BASE_BUILDS[board])
    try:
        data = json.loads(Path(path).read_text())
        entries = data.get("entries", [])
    except Exception:
        return 0
    per: dict = {}
    for e in entries:
        board = e.get("board")
        if board in DEVICES and e.get("build") and e.get("version"):
            per.setdefault(board, []).append(e)
    for board, ents in per.items():
        builds = {}
        for e in ents:
            builds[e["build"]] = e["version"]
            CATALOG_ENTRIES[(board, e["build"])] = e
        for b, v in _BASE_BUILDS[board].items():
            builds.setdefault(b, v)
        DEVICES[board]["builds"] = builds
    return len(CATALOG_ENTRIES)


def build_info(board: str, build: str) -> dict:
    """The catalog entry for a build ({} when the build is only in the built-in list)."""
    return CATALOG_ENTRIES.get((board, build), {})


def is_prerelease(board: str, build: str) -> bool:
    return bool(build_info(board, build).get("prerelease"))


def build_label(board: str, build: str, version: str) -> str:
    """'8C5091e  (iOS 4.2)  [beta 1, experimental]' for the build drop-down."""
    info = build_info(board, build)
    tags = []
    if info.get("prerelease"):
        n = info.get("prerelease_number")
        tags.append("{}{}".format(info["prerelease"], " {}".format(n) if n else ""))
    st = info.get("status")
    if st and st != "available":
        tags.append(st.replace("_", " "))
    return "{}  (iOS {}){}".format(
        build, version, "  [" + ", ".join(tags) + "]" if tags else "")


def list_builds(board: str, include_beta: bool = True,
                include_unsupported: bool = False) -> list:
    """Build ids for a board, filtered; catalog order (oldest first)."""
    out = []
    for build in DEVICES[board]["builds"]:
        info = build_info(board, build)
        if not include_beta and info.get("prerelease"):
            continue
        if not include_unsupported and info.get("status") == "coming_soon":
            continue
        out.append(build)
    return out


def catalog_sources(board: str, build: str) -> list:
    """Download candidates for a build from the catalog: the primary source, then mirrors.

    Each item: {"url", "kind" ("ipsw" | "rar"), "member", "sha1"}.  For kind "rar" the URL is
    an archive and "member" is the IPSW inside it.
    """
    src = build_info(board, build).get("source") or {}
    out = []
    if src.get("url"):
        out.append({"url": src["url"], "kind": src.get("kind", "ipsw"),
                    "member": src.get("member"), "sha1": src.get("sha1")})
    for m in src.get("mirrors", []) or []:
        if m.get("url"):
            out.append({"url": m["url"], "kind": "ipsw", "member": None,
                        "sha1": m.get("sha1") or src.get("sha1")})
    return out


def default_download_dir() -> Path:
    """The user's Downloads folder (XDG user-dirs.dirs), else ~/Downloads."""
    cfg_home = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    try:
        for line in (cfg_home / "user-dirs.dirs").read_text().splitlines():
            m = re.match(r'\s*XDG_DOWNLOAD_DIR\s*=\s*"(.*)"\s*$', line)
            if m:
                p = Path(m.group(1).replace("$HOME", str(Path.home())))
                if p != Path.home():        # "$HOME/" means "no Downloads folder"
                    return p
    except OSError:
        pass
    return Path.home() / "Downloads"


def sha1_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha1()
    with open(str(path), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_rar_member(archive: Path, member: str, dest: Path) -> None:
    """Pull one file out of a .rar with whichever of 7z / 7zz / unrar / bsdtar is installed."""
    tmp = Path(tempfile.mkdtemp(prefix="qemu-ios-rar-", dir=str(dest.parent)))
    try:
        tried = []
        for tool, cmd in (
            ("7z",     ["7z", "e", "-y", "-o" + str(tmp), str(archive), member]),
            ("7zz",    ["7zz", "e", "-y", "-o" + str(tmp), str(archive), member]),
            ("unrar",  ["unrar", "e", "-o+", str(archive), member, str(tmp) + "/"]),
            ("bsdtar", ["bsdtar", "-xf", str(archive), "-C", str(tmp), member]),
        ):
            if not shutil.which(tool):
                continue
            tried.append(tool)
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, errors="replace")
            hits = list(tmp.rglob(Path(member).name))
            if r.returncode == 0 and hits:
                os.replace(str(hits[0]), str(dest))
                return
        if not tried:
            raise RuntimeError("this build is shipped as a .rar; install 7z (p7zip-full), "
                               "unrar or bsdtar to unpack it")
        raise RuntimeError("could not extract {} from {} ({})".format(
            member, archive.name, ", ".join(tried)))
    finally:
        shutil.rmtree(str(tmp), ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Per-device preferences
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_PREFS = {
    "name":       "",       # display name (device list, window title)
    "verbose":    False,    # iOS verbose boot ("-v" in the kernel command line)
    "boot_args":  "",       # extra kernel boot-args (replaces iBoot's command line!)
    "ram_mb":     0,        # 0 = the machine's own RAM size; else QEMU -m <n>M
    "usb_addr":   "",       # USB-over-TCP host bridge (usbmuxd): port, host:port or socket path
    "baseband":   "default",  # cellular modem: "default" (machine's own), "on" or "off"
    "carrier":    "",       # carrier name shown by the phone ("" = leave the modem's own)
    "mcc_mnc":    "",       # carrier MCC+MNC (5-6 digits), optional, goes with the name
    "scale":      "fit",    # touch-panel window scale: "fit" or a factor
    "rotate":     0,        # touch-panel rotation: 0 / 90 / 180 / 270
    "sound":      "off",    # host audio: "off" (muted), "auto" (QEMU's own pick) or a driver name
    "extra_args": "",       # raw extra QEMU arguments
}
SCALE_CHOICES    = ["fit", "0.5", "0.75", "1", "1.5", "2"]
RAM_CHOICES      = ["Default", "64", "128", "256", "512", "1024"]
ROTATE_CHOICES   = ["0", "90", "180", "270"]
BASEBAND_CHOICES = ["Default", "On", "Off"]
CARRIERS = (                    # name, MCC+MNC (same presets as touchPanel.py's Network tab)
    ("Test Network", "00101"), ("AT&T", "310410"), ("T-Mobile", "310260"),
    ("Verizon", "311480"), ("Vodafone UK", "23415"), ("Globe", "51502"),
    ("Smart", "51503"),
)
MODEM_PATH = "/machine/baseband-modem"      # QOM path of the fake modem (hw/misc/ios_baseband.c)


# "off" keeps run.sh's `-audio driver=none`; "auto" lets QEMU use the first host driver it
# was built with; the rest name a driver (checked against `qemu -audio help` at start).
SOUND_CHOICES    = ["off", "auto", "pipewire", "pa", "alsa", "sdl", "jack", "oss", "coreaudio"]
SOUND_DRIVER_RE  = re.compile(r"^[a-z][a-z0-9]*$")


def valid_carrier(s: str) -> bool:
    """The modem's carrier-name rule: 1-32 printable characters, no double quote."""
    return 1 <= len(s) <= 32 and s.isprintable() and '"' not in s


def valid_plmn(s: str) -> bool:
    """MCC+MNC: 5 or 6 digits."""
    return s.isdigit() and len(s) in (5, 6)


def get_prefs(dirname: str, cfg: Optional[dict] = None) -> dict:
    """Saved preferences for a device folder name, filled in with defaults."""
    cfg = load_config() if cfg is None else cfg
    saved = (cfg.get("device_prefs") or {}).get(dirname) or {}
    prefs = dict(DEFAULT_PREFS)
    prefs.update({k: v for k, v in saved.items() if k in DEFAULT_PREFS})
    return prefs


def save_prefs(dirname: str, prefs: dict) -> None:
    """Persist only the non-default values (an all-default device has no entry)."""
    cfg = load_config()
    dp = cfg.get("device_prefs")
    dp = dp if isinstance(dp, dict) else {}
    changed = {k: v for k, v in prefs.items()
               if k in DEFAULT_PREFS and v != DEFAULT_PREFS[k]}
    if changed:
        dp[dirname] = changed
    else:
        dp.pop(dirname, None)
    cfg["device_prefs"] = dp
    save_config(cfg)


UNIX_SOCKET_PATH_MAX = 103      # sun_path is 104 bytes on macOS / 108 on Linux, with the NUL


def normalize_usb_addr(text: str) -> tuple:
    """Check a USB connection setting -> (normalized value, error or "").

    Accepts what QEMU's `usb-tcp-addr` takes, plus a bare port:
        ""                  no link (the machine's own default)
        1235 / :1235        -> 127.0.0.1:1235
        host:port           a TCP bridge (usbmuxd's USBMUXD_QEMU_ADDR)
        /path/to/socket     the bridge's Unix socket
    QEMU is the client, so the bridge (usbmuxd) must be the one listening.
    """
    t = (text or "").strip()
    if not t:
        return "", ""
    if re.search(r"[\r\n\0]", t):
        return t, "USB connection must be a single line."
    if t.startswith("/"):
        if len(t.encode()) > UNIX_SOCKET_PATH_MAX:
            return t, ("USB socket path is too long for a Unix socket "
                       "(at most {} bytes).".format(UNIX_SOCKET_PATH_MAX))
        return t, ""
    if t.startswith("~"):
        return t, "USB socket path must be absolute (a leading ~ is not expanded)."
    host, sep, port = t.rpartition(":")
    if not sep:                      # a bare port
        host, port = "", t
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return t, ("USB connection must be a port (1-65535), host:port, or an "
                   "absolute path to a Unix socket.")
    if re.search(r"[\s,=]", host):
        return t, "USB host must not contain spaces, commas or '='."
    return "{}:{}".format(host or "127.0.0.1", int(port)), ""


def validate_prefs(prefs: dict) -> list:
    """Problems with a preferences dict, as human-readable strings ([] when fine)."""
    errs = []
    ram = prefs.get("ram_mb", 0)
    if not isinstance(ram, int) or not (ram == 0 or 16 <= ram <= 8192):
        errs.append("RAM must be Default or between 16 and 8192 MB.")
    sc = prefs.get("scale", "fit")
    if sc != "fit":
        try:
            if not 0.05 <= float(sc) <= 8:
                raise ValueError
        except (TypeError, ValueError):
            errs.append("Window scale must be 'fit' or a number between 0.05 and 8.")
    if prefs.get("rotate", 0) not in (0, 90, 180, 270):
        errs.append("Rotation must be 0, 90, 180 or 270.")
    snd = prefs.get("sound", "off")
    if snd in ("none", "wav"):
        errs.append("Sound: '{}' is not a host output; use Off (muted) or a real "
                    "driver.".format(snd))
    elif not isinstance(snd, str) or not (snd in ("off", "auto")
                                          or SOUND_DRIVER_RE.match(snd)):
        errs.append("Sound must be off, auto or an audio driver name (e.g. pipewire, pa, "
                    "alsa, sdl, coreaudio).")
    usb_err = normalize_usb_addr(prefs.get("usb_addr", ""))[1]
    if usb_err:
        errs.append(usb_err)
    if prefs.get("baseband", "default") not in ("default", "on", "off"):
        errs.append("Baseband must be Default, On or Off.")
    carrier = prefs.get("carrier", "")
    if carrier and not valid_carrier(carrier):
        errs.append("Carrier name must be 1-32 printable characters, no double quotes.")
    plmn = prefs.get("mcc_mnc", "")
    if plmn and not valid_plmn(plmn):
        errs.append("MCC-MNC must be 5 or 6 digits (MCC + MNC).")
    ba = prefs.get("boot_args", "")
    if "\n" in ba or len(ba.encode()) + ba.count("%") > 250:
        errs.append("Boot-args must be one line of at most ~250 bytes (each % counts twice).")
    try:
        shlex.split(prefs.get("extra_args", ""))
    except ValueError as exc:
        errs.append("Extra QEMU arguments: {}".format(exc))
    return errs


_PROP_CACHE: dict = {}


def machine_has_property(qemu: str, machine: str, prop: str) -> bool:
    """True if `qemu -M <machine>,help` lists the property (cached per binary + machine)."""
    key = (qemu, machine)
    if key not in _PROP_CACHE:
        try:
            r = subprocess.run([qemu, "-M", machine + ",help"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, errors="replace",
                               timeout=15)
            _PROP_CACHE[key] = r.stdout
        except Exception:
            _PROP_CACHE[key] = ""
    return re.search(r"(^|\s)" + re.escape(prop) + r"=", _PROP_CACHE[key]) is not None


_AUDIO_CACHE: dict = {}


def qemu_audio_drivers(qemu: str) -> Optional[set]:
    """Host audio drivers this QEMU binary was built with (`qemu -audio help`, cached).

    None when the list could not be read (the caller then skips the check)."""
    if qemu not in _AUDIO_CACHE:
        found = None
        try:
            r = subprocess.run([qemu, "-audio", "help"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, errors="replace",
                               timeout=15)
            lines = r.stdout.splitlines()
            if any(l.startswith("Available audio drivers") for l in lines):
                found = {l.strip() for l in lines
                         if SOUND_DRIVER_RE.match(l.strip())}
        except Exception:
            pass
        _AUDIO_CACHE[qemu] = found
    return _AUDIO_CACHE[qemu]


def _sound_value(prefs: dict) -> str:
    """The Sound preference as off / auto / a driver name; anything invalid counts as off."""
    snd = prefs.get("sound", "off")
    if snd in ("off", "auto"):
        return snd
    if isinstance(snd, str) and SOUND_DRIVER_RE.match(snd) and snd not in ("none", "wav"):
        return snd
    return "off"


def _extra_sets_audio(prefs: dict) -> bool:
    try:
        toks = shlex.split(prefs.get("extra_args", ""))
    except ValueError:
        return False
    return any(t in ("-audio", "--audio") for t in toks)


def pref_replaces_audio(prefs: dict) -> bool:
    """True when run.sh's `-audio driver=none` has to go: QEMU keeps the first -audio it is
    given, so an appended one would never be heard.  (Sound off keeps the muted default
    unless the extra QEMU arguments bring their own -audio.)"""
    return _sound_value(prefs) != "off" or _extra_sets_audio(prefs)


def build_pref_args(qemu: str, board: str, prefs: dict) -> tuple:
    """QEMU arguments for a device's preferences -> (args, notes).

    The arguments are appended after run.sh's own (QEMU merges repeated -M options), so
    run.sh itself is never rewritten.  `notes` are warnings for the log (settings that
    could not be applied).  Panel-only settings (scale, rotate) are handled elsewhere.
    """
    machine = DEVICES.get(board, {}).get("qemu_machine")
    args, notes = [], []
    if prefs.get("name"):
        args += ["-name", prefs["name"].replace(",", ",,")]
    if prefs.get("ram_mb"):
        args += ["-m", "{}M".format(int(prefs["ram_mb"]))]
    parts = (["-v"] if prefs.get("verbose") else []) + (
        [prefs["boot_args"].strip()] if prefs.get("boot_args", "").strip() else [])
    if parts and machine:
        if machine_has_property(qemu, machine, "boot-args"):
            args += ["-M", "{},boot-args={}".format(
                machine, " ".join(parts).replace(",", ",,"))]
        else:
            notes.append("machine {} has no boot-args property in this QEMU build; "
                         "verbose / boot-args ignored.".format(machine))
    usb, usb_err = normalize_usb_addr(prefs.get("usb_addr", ""))
    if usb and not usb_err and machine:
        if machine_has_property(qemu, machine, "usb-tcp-addr"):
            opts = "{},usb-tcp-addr={}".format(machine, usb.replace(",", ",,"))
            # The A4 machines default the cable to attached; the others need it said.
            if machine_has_property(qemu, machine, "usb-attached"):
                opts += ",usb-attached=on"
            args += ["-M", opts]
        else:
            notes.append("machine {} has no usb-tcp-addr property in this QEMU build; "
                         "USB connection ignored.".format(machine))
    bb = prefs.get("baseband", "default")
    if bb in ("on", "off") and machine:
        if machine_has_property(qemu, machine, "baseband"):
            args += ["-M", "{},baseband={}".format(machine, bb)]
        else:
            notes.append("machine {} has no baseband property in this QEMU build; "
                         "baseband setting ignored.".format(machine))
    if prefs.get("carrier", "").strip() and bb == "off":
        notes.append("carrier name is set but the baseband is Off; the carrier is not applied.")
    snd = _sound_value(prefs)
    if snd != "off":
        if _extra_sets_audio(prefs):
            notes.append("the extra QEMU arguments already set -audio; the Sound "
                         "preference is ignored.")
        elif snd == "auto":
            notes.append("sound: auto (QEMU picks the first host audio driver it was "
                         "built with).")
        else:
            avail = qemu_audio_drivers(qemu)
            if avail is not None and snd not in avail:
                notes.append("audio driver '{}' is not built into this QEMU (have: {}); "
                             "using auto instead.".format(
                                 snd, ", ".join(sorted(avail - {"none"})) or "none"))
            else:
                args += ["-audio", "driver={}".format(snd)]
                notes.append("sound: host audio driver {}.".format(snd))
    if prefs.get("extra_args", "").strip():
        args += shlex.split(prefs["extra_args"])
    return args, notes


# Drops run.sh's `-audio driver=none` (and any other `-audio none`) from the argument list, so
# the -audio from the preferences, or QEMU's own default choice, is the one in effect.
_DROP_NULL_AUDIO_SH = """\
n=$#
pend=0
while [ "$n" -gt 0 ]; do
  a=$1; shift; n=$((n-1))
  if [ "$pend" = 1 ]; then
    pend=0
    case $a in
      driver=none|driver=none,*|none|none,*) ;;
      *) set -- "$@" -audio "$a" ;;
    esac
    continue
  fi
  if [ "$a" = -audio ]; then pend=1; continue; fi
  set -- "$@" "$a"
done
"""


def write_args_wrapper(real_qemu: str, extra: list, qmp_name: str = "",
                       drop_null_audio: bool = False) -> dict:
    """A one-line sh wrapper that runs `real_qemu "$@" <extra>`; run.sh uses it as $QEMU.

    With `qmp_name`, the wrapper also adds `-qmp unix:<dir>/<qmp_name>,server,nowait`:
    a QMP socket that belongs to the manager alone (QEMU takes any number of -qmp
    monitors, and each accepts one client, so it never competes with the touch
    panel's socket).  The socket path is returned as "sock".

    With `drop_null_audio` it first removes run.sh's muted `-audio driver=none`.
    """
    tmp = tempfile.mkdtemp(prefix="qemu-ios-args-")     # short path: unix sockets cap at ~107 bytes
    args = list(extra)
    sock = ""
    if qmp_name:
        sock = str(Path(tmp) / qmp_name)
        args += ["-qmp", "unix:{},server,nowait".format(sock.replace(",", ",,"))]
    w = Path(tmp) / "qemu-args.sh"
    body = "#!/bin/sh\n" + (_DROP_NULL_AUDIO_SH if drop_null_audio else "")
    body += "exec {} \"$@\" {}\n".format(
        shlex.quote(real_qemu), " ".join(shlex.quote(a) for a in args))
    w.write_text(body)
    w.chmod(0o755)
    return {"dir": tmp, "path": str(w), "sock": sock}


class QmpAgent:
    """Watches one running device over its own QMP socket.

    * Guest power-off: when the iPhone is switched off from its own UI, QEMU reports a
      SHUTDOWN event (or sits in the "shutdown" run state, as with -no-shutdown) but a
      machine started this way does not always exit by itself.  The agent sends QMP
      `quit` so the QEMU process ends, which also closes the touch panel and frees the
      device in the list.  If QEMU has not exited a few seconds after `quit`, the
      process is terminated.
    * Carrier: once the fake modem (/machine/baseband-modem) exists, the saved carrier
      name (and MCC-MNC) are applied with `qom-set`, the way the touch panel's Network
      tab does it.

    Everything runs on daemon threads; `log` must be thread-safe (App.log is).
    """

    CONNECT_TIMEOUT = 120.0     # QEMU may take a while to open its monitor
    MODEM_TIMEOUT   = 15.0      # how long to wait for the modem object to show up
    QUIT_GRACE      = 5.0       # after `quit`: wait, then SIGTERM, then SIGKILL

    HOLD_MAX_AGE    = 600.0     # a hold file older than this is stale (the panel crashed mid-reboot)

    def __init__(self, sock: str, proc: subprocess.Popen, log: Callable,
                 carrier: str = "", mcc_mnc: str = "", auto_quit: bool = True,
                 hold_file: str = "") -> None:
        self.sock, self.proc, self.log = sock, proc, log
        self.carrier, self.mcc_mnc, self.auto_quit = carrier, mcc_mnc, auto_quit
        self.hold_file = hold_file
        self._sk = None
        self._rf = None
        self._wlock = threading.Lock()
        self._plock = threading.Lock()
        self._pending: dict = {}
        self._next = 1
        self._quit_started = False
        self._seen: set = set()

    def start(self) -> None:
        threading.Thread(target=self._run, name="qmp-agent", daemon=True).start()

    # ── connection ────────────────────────────────────────────────────────────

    def _connect(self) -> bool:
        deadline = time.monotonic() + self.CONNECT_TIMEOUT
        while self.proc.poll() is None and time.monotonic() < deadline:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2.0)
            try:
                s.connect(self.sock)
            except OSError:
                s.close()
                time.sleep(0.25)
                continue
            try:
                s.settimeout(30.0)
                rf = s.makefile("rb")
                greeting = json.loads(rf.readline().decode("utf-8", "replace") or "{}")
                if "QMP" not in greeting:
                    raise ValueError("not a QMP greeting")
                s.sendall(b'{"execute":"qmp_capabilities"}\r\n')
                while True:                  # events may arrive before the reply
                    msg = json.loads(rf.readline().decode("utf-8", "replace") or "{}")
                    if "return" in msg:
                        break
                    if "error" in msg or not msg:
                        raise ValueError("qmp_capabilities failed")
                s.settimeout(None)
            except (OSError, ValueError):
                s.close()
                time.sleep(0.5)
                continue
            self._sk, self._rf = s, rf
            return True
        return False

    def _send(self, obj: dict) -> None:
        with self._wlock:
            self._sk.sendall((json.dumps(obj) + "\r\n").encode())

    def _cmd(self, name: str, args: Optional[dict] = None, timeout: float = 5.0):
        """Run a QMP command from a worker thread (never from the reader) -> its return value."""
        with self._plock:
            rid = self._next
            self._next += 1
            slot = {"ev": threading.Event(), "msg": None}
            self._pending[rid] = slot
        msg = {"execute": name, "id": rid}
        if args:
            msg["arguments"] = args
        try:
            self._send(msg)
        except OSError as exc:
            with self._plock:
                self._pending.pop(rid, None)
            raise RuntimeError("send failed: {}".format(exc))
        if not slot["ev"].wait(timeout):
            with self._plock:
                self._pending.pop(rid, None)
            raise RuntimeError("{} timed out".format(name))
        reply = slot["msg"]
        if reply is None:
            raise RuntimeError("connection closed")
        if "error" in reply:
            raise RuntimeError(reply["error"].get("desc", str(reply["error"])))
        return reply.get("return")

    # ── main loop ─────────────────────────────────────────────────────────────

    def _run(self) -> None:
        try:
            if not self._connect():
                if self.proc.poll() is None:
                    self.log("  qmp: could not connect to QEMU's manager socket; the "
                             "device will not quit by itself when the guest powers off.")
                return
            if self.carrier or self.mcc_mnc:
                threading.Thread(target=self._apply_carrier, daemon=True).start()
            for line in self._rf:
                try:
                    msg = json.loads(line.decode("utf-8", "replace"))
                except ValueError:
                    continue
                if "event" in msg:
                    self._on_event(msg["event"], msg.get("data") or {})
                    continue
                with self._plock:
                    slot = self._pending.pop(msg.get("id"), None)
                if slot is not None:
                    slot["msg"] = msg
                    slot["ev"].set()
        except (OSError, ValueError):
            pass
        finally:
            with self._plock:                       # wake anything still waiting
                waiting = list(self._pending.values())
                self._pending.clear()
            for slot in waiting:
                slot["ev"].set()
            try:
                if self._sk:
                    self._sk.close()
            except OSError:
                pass

    def _on_event(self, name: str, data: dict) -> None:
        if name == "SHUTDOWN":
            why = data.get("reason")
            self.log("  qmp: guest powered off (SHUTDOWN{}).".format(
                ", reason " + str(why) if why else ""))
            self.quit()
        elif name == "STOP":
            threading.Thread(target=self._check_stopped, daemon=True).start()
        elif name not in self._seen:
            self._seen.add(name)        # each other event is logged once, to see what the machine reports
            if name not in ("RTC_CHANGE", "NIC_RX_FILTER_CHANGED", "VNC_CONNECTED"):
                self.log("  qmp: event {}".format(name))

    def _check_stopped(self) -> None:
        """QEMU left running in the 'shutdown' state (-no-shutdown) still counts as powered off."""
        try:
            status = (self._cmd("query-status") or {}).get("status")
        except RuntimeError:
            return
        if status == "shutdown":
            self.log("  qmp: guest powered off (run state 'shutdown').")
            self.quit()

    def _held(self) -> bool:
        """The touch panel's "Reboot safely" is under way: it lets the guest shut down cleanly, then resets the
        same QEMU, so the guest's SHUTDOWN must not end it.  The panel marks that with a file next to its QMP
        socket (touchPanel.reboot_hold_path) and removes it when done; a stale one is ignored."""
        try:
            return bool(self.hold_file) and time.time() - os.path.getmtime(self.hold_file) < self.HOLD_MAX_AGE
        except OSError:
            return False

    def quit(self) -> None:
        """End QEMU: QMP quit, then SIGTERM, then SIGKILL if it lingers."""
        if not self.auto_quit:
            self.log("  qmp: -no-shutdown is in the extra QEMU arguments; "
                     "leaving QEMU running.")
            return
        if self._held():
            self.log("  qmp: the touch panel is rebooting the device; leaving QEMU running.")
            return
        if self._quit_started:
            return
        self._quit_started = True

        def work() -> None:
            try:
                self._send({"execute": "quit"})
            except (OSError, AttributeError):
                pass
            for sig_name in ("terminate", "kill"):
                try:
                    self.proc.wait(self.QUIT_GRACE)
                    return
                except subprocess.TimeoutExpired:
                    self.log("  qmp: QEMU did not exit; sending {}.".format(
                        "SIGTERM" if sig_name == "terminate" else "SIGKILL"))
                    try:
                        getattr(self.proc, sig_name)()
                    except OSError:
                        return
        threading.Thread(target=work, daemon=True).start()

    # ── carrier ───────────────────────────────────────────────────────────────

    def _apply_carrier(self) -> None:
        """qom-set mcc-mnc, then carrier (the name change re-announces the operator)."""
        deadline = time.monotonic() + self.MODEM_TIMEOUT
        while True:
            try:
                self._cmd("qom-list", {"path": MODEM_PATH})
                break
            except RuntimeError as exc:
                if "not found" not in str(exc).lower() or time.monotonic() > deadline:
                    self.log("  qmp: no baseband modem on this machine ({}); carrier "
                             "not applied. Set Baseband to On in Device Preferences."
                             .format(exc))
                    return
                time.sleep(0.5)
        try:
            if self.mcc_mnc:
                self._cmd("qom-set", {"path": MODEM_PATH, "property": "mcc-mnc",
                                      "value": self.mcc_mnc})
            if self.carrier:
                self._cmd("qom-set", {"path": MODEM_PATH, "property": "carrier",
                                      "value": self.carrier})
            self.log("  qmp: carrier set to {}{}.".format(
                self.carrier or "(unchanged)",
                " ({})".format(self.mcc_mnc) if self.mcc_mnc else ""))
        except RuntimeError as exc:
            self.log("  qmp: carrier not applied: {}".format(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────

def ipsw_filename(product: str, version: str, build: str) -> str:
    return "{}_{}_{}_Restore.ipsw".format(product, version, build)


_IPSW_PRODUCT_RE = re.compile(r"(?<![A-Za-z])(iPhone|iPod|iPad)(\d+),(\d+)")
_IPSW_BUILD_RE   = re.compile(r"(?<![A-Za-z0-9])(\d{1,2}[A-Z]\d{1,4}[a-z]?)(?![A-Za-z0-9])")
_IPSW_VERSION_RE = re.compile(r"(?<![\d.])(\d{1,2}\.\d+(?:\.\d+)?)(?![\d.])")


def parse_ipsw_filename(path: str) -> dict:
    """What an IPSW's file name says about it: Apple's 'iPod2,1_3.1.3_7E18_Restore.ipsw'.

    Returns {"board", "build", "version"} for what could be recognised (keys are missing otherwise):
    the board from the product ID (falling back to the build ID when only one device has that build),
    the build from the build ID (falling back to the version when only one build of the board has it).
    The result only names boards and builds this tool knows (DEVICES, with the catalog merged in)."""
    name = Path(path).name
    if name.lower().endswith(".ipsw"):
        name = name[:-5]
    out: dict = {}
    m = _IPSW_PRODUCT_RE.search(name)
    bm = _IPSW_BUILD_RE.search(name)
    vm = _IPSW_VERSION_RE.search(name)
    build = bm.group(1) if bm else ""
    version = vm.group(1) if vm else ""
    board = ""
    if m:
        product = "{}{},{}".format(m.group(1), m.group(2), m.group(3))
        board = next((k for k, d in DEVICES.items() if d["product"] == product), "")
    elif build:
        owners = [k for k, d in DEVICES.items() if build in d["builds"]]
        board = owners[0] if len(owners) == 1 else ""
    if not board:
        return out
    out["board"] = board
    builds = DEVICES[board]["builds"]
    if build in builds:
        out["build"] = build
        out["version"] = builds[build]
    elif version:
        same = [b for b, v in builds.items() if v == version]
        if len(same) == 1:
            out["build"], out["version"] = same[0], version
    return out


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


class DownloadCancelled(Exception):
    pass


# aria2c's console readout:  [#a1b2c3 1.2MiB/100MiB(1%) CN:16 DL:2.3MiB ETA:42s]
_ARIA_PCT = re.compile(r"\((\d+)%\)")
_ARIA_DL  = re.compile(r"DL:(\S+?)[\s\]]")
_ARIA_ETA = re.compile(r"ETA:(\S+?)[\s\]]")


def _download_aria2(aria2: str, url: str, part: Path,
                    on_progress, should_stop, on_proc) -> bool:
    """Download with aria2c (16 connections, 16 splits).  True on success."""
    cmd = [aria2, "-x16", "-s16", "-k1M", "-c",
           "--file-allocation=none", "--auto-file-renaming=false",
           "--allow-overwrite=true", "--summary-interval=0",
           "--console-log-level=warn", "--download-result=hide",
           "--user-agent=" + _UA,
           "-d", str(part.parent), "-o", part.name, url]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors="replace")
    if on_proc:
        on_proc(proc)
    tail: list = []
    for line in proc.stdout:            # aria2c redraws one line with \r
        if should_stop and should_stop():
            proc.terminate()
            break
        m = _ARIA_PCT.search(line)
        if m:
            if on_progress:
                note = []
                dl, eta = _ARIA_DL.search(line), _ARIA_ETA.search(line)
                if dl:
                    note.append(dl.group(1) + "/s")
                if eta:
                    note.append("ETA " + eta.group(1))
                on_progress(int(m.group(1)), 100, "  ".join(note))
        elif line.strip():
            tail = (tail + [line.strip()])[-5:]
    proc.wait()
    if on_proc:
        on_proc(None)
    if should_stop and should_stop():
        raise DownloadCancelled()
    if proc.returncode != 0:
        if on_progress:
            on_progress(None, None, "aria2c failed (exit {}): {}".format(
                proc.returncode, " | ".join(tail) or "no output"))
        return False
    if on_progress and part.exists():
        on_progress(100, 100, "")
    return part.exists()


def _download_urllib(url: str, part: Path, on_progress, should_stop) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=120) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done  = 0
        last  = 0.0
        with open(str(part), "wb") as fh:
            while True:
                if should_stop and should_stop():
                    raise DownloadCancelled()
                chunk = resp.read(1 << 20)  # 1 MiB
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                now = time.monotonic()
                if on_progress and now - last >= 0.1:
                    last = now
                    on_progress(done, total, "")
        if on_progress:
            on_progress(done, total, "")        # final value (not throttled)


def download_url_to_file(
    url: str,
    dest: Path,
    on_progress: Optional[Callable] = None,
    should_stop: Optional[Callable] = None,
    on_proc: Optional[Callable] = None,
) -> str:
    """Download url to dest (written as dest.part, renamed when complete).

    Uses ``aria2c -x16 -s16`` when it is installed (falling back to urllib if
    it fails), else urllib.  on_progress(done, total, note) is called as the
    download advances: bytes for urllib; a percentage out of 100 for aria2c;
    (None, None, message) reports a non-fatal problem.  Returns the tool used.
    """
    part = dest.with_name(dest.name + ".part")
    aria2 = shutil.which("aria2c")
    tool = "urllib"
    if aria2 and _download_aria2(aria2, url, part, on_progress, should_stop, on_proc):
        tool = "aria2c"
    else:
        for leftover in (part, part.with_name(part.name + ".aria2")):
            try:
                leftover.unlink()
            except OSError:
                pass
        _download_urllib(url, part, on_progress, should_stop)
    os.replace(str(part), str(dest))
    return tool


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
        info = build_info(board, build)
        ver  = dev.get("builds", {}).get(build, build)
        if info.get("prerelease"):
            ver += " " + str(info["prerelease"])
        out.append({
            "path":        entry,
            "dirname":     entry.name,
            "board":       board,
            "build":       build,
            "device_name": dev.get("name", board),
            "ios_version": ver,
            "status":      info.get("status", ""),
            "has_run_sh":  (entry / "run.sh").exists(),
            "identity":    identity,
        })
    return out


def prepare_touch_panel(env: dict, qemu: str) -> Optional[dict]:
    """Make run.sh start QEMU with a QMP socket and without the SDL window.

    run.sh ends in `exec ${QEMU:-qemu-system-arm} ... -display sdl,...`, so QEMU is
    pointed at a one-line wrapper that runs `touchPanel.py --exec-qemu`; that adds
    `-qmp unix:SOCK,server,nowait`, swaps the display for `-display none` and execs
    the real binary (passed in LT_REAL_QEMU).  The wrapper also turns run.sh's
    `-serial mon:stdio` into a chardev that logs to LT_SERIAL_LOG, which the panel
    shows in its serial pane.  Updates `env` in place and returns
    {"dir", "sock", "serial"} (the caller removes "dir" when QEMU exits), or None if
    the panel script is missing.
    """
    if not TOUCH_PANEL.is_file():
        return None
    tmp = tempfile.mkdtemp(prefix="qemu-ios-panel-")       # short path: unix sockets cap at ~107 bytes
    wrapper = Path(tmp) / "qemu-wrapper.sh"
    wrapper.write_text("#!/bin/sh\nexec {} {} --exec-qemu \"$@\"\n".format(
        shlex.quote(sys.executable), shlex.quote(str(TOUCH_PANEL))))
    wrapper.chmod(0o755)
    sock = str(Path(tmp) / "qmp.sock")
    serial = str(Path(tmp) / "serial.log")
    env["LT_REAL_QEMU"]    = qemu
    env["LT_QMP_SOCK"]     = sock
    env["LT_SERIAL_LOG"]   = serial
    env["LT_HIDE_DISPLAY"] = "1"
    env["QEMU"]            = str(wrapper)
    return {"dir": tmp, "sock": sock, "serial": serial}


def spawn_touch_panel(sock: str, title: str, scale: str = "fit",
                      rotate: int = 0, serial: str = "") -> subprocess.Popen:
    """Open the touch panel window for the QEMU listening on QMP socket `sock`.
    `serial` is the file QEMU logs the guest's serial output to (shown in the panel's side pane)."""
    cmd = [sys.executable, str(TOUCH_PANEL), "--qmp", sock, "--title", title]
    if serial:
        cmd += ["--serial-log", serial]
    if scale and scale != "fit":
        cmd += ["--scale", str(scale)]
    if rotate:
        cmd += ["--rotate", str(int(rotate))]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        errors="replace")


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

class ScrollableFrame(ttk.Frame):
    """A frame whose content scrolls vertically when it is taller than ~70% of the screen.

    Put the widgets in ``.body``.  The scrollbar only shows when needed, and the mouse wheel
    scrolls while the pointer is anywhere in the dialog (the dialog's own bindings, not global
    ones).  Keep buttons that must stay reachable outside it, packed with side="bottom".
    """

    def __init__(self, parent, padding=0) -> None:
        super().__init__(parent)
        bg = ttk.Style(parent).lookup("TFrame", "background") or self.winfo_toplevel().cget("bg")
        self._canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0, bg=bg)
        self._vsb = ttk.Scrollbar(self, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._vsb.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        self.body = ttk.Frame(self._canvas, padding=padding)
        self._win = self._canvas.create_window((0, 0), window=self.body, anchor="nw")
        self._scrolls = False
        self.body.bind("<Configure>", self._on_body)
        self._canvas.bind("<Configure>",
                          lambda e: self._canvas.itemconfigure(self._win, width=e.width))
        top = self.winfo_toplevel()
        for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            top.bind(ev, self._on_wheel, add="+")

    def _on_body(self, _e=None) -> None:
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        want = self.body.winfo_reqheight()
        cap = int(self.winfo_screenheight() * 0.7)
        self._canvas.configure(width=self.body.winfo_reqwidth(), height=min(want, cap))
        self._scrolls = want > cap
        if self._scrolls:
            self._vsb.pack(side="right", fill="y")
        else:
            self._vsb.pack_forget()
            self._canvas.yview_moveto(0)

    def _on_wheel(self, e) -> None:
        if not self._scrolls or not str(e.widget).startswith(str(self)):
            return
        if getattr(e, "num", 0) == 4:
            step = -1
        elif getattr(e, "num", 0) == 5:
            step = 1
        else:
            step = -1 if e.delta > 0 else 1
        self._canvas.yview_scroll(step * 2, "units")


class CreateProgressWindow(tk.Toplevel):
    """Shown while a device is being created (the New Virtual Device dialog is hidden meanwhile):
    the current stage, a percentage bar on the left, firmwarekit's log on the right."""

    MAX_LOG_LINES = 6000

    def __init__(self, parent, title: str, on_cancel: Callable, on_back: Callable,
                 on_close: Callable) -> None:
        super().__init__(parent)
        self.title("Creating {}".format(title))
        self.geometry("920x460")
        self.minsize(640, 320)
        try:
            self.transient(parent)
        except tk.TclError:
            pass
        self._on_cancel, self._on_back, self._on_close = on_cancel, on_back, on_close
        self._pct = 0.0
        self._done = False
        self.protocol("WM_DELETE_WINDOW", self._x_pressed)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        left = ttk.Frame(self, padding=12)
        left.grid(row=0, column=0, sticky="ns")
        ttk.Label(left, text="Stage", foreground="gray").pack(anchor="w")
        self._stage_var = tk.StringVar(value="Starting\u2026")
        ttk.Label(left, textvariable=self._stage_var, wraplength=250, justify="left",
                  font=("TkDefaultFont", 11, "bold")).pack(anchor="w", pady=(2, 14))
        self._pbar = ttk.Progressbar(left, mode="determinate", maximum=100, length=250)
        self._pbar.pack(fill="x")
        self._pct_var = tk.StringVar(value="0%")
        ttk.Label(left, textvariable=self._pct_var).pack(anchor="e", pady=(2, 0))
        self._detail_var = tk.StringVar(value="")
        ttk.Label(left, textvariable=self._detail_var, foreground="gray",
                  wraplength=250, justify="left").pack(anchor="w", pady=(10, 0))
        self._btns = ttk.Frame(left)
        self._btns.pack(side="bottom", anchor="w", pady=(16, 0))
        self._cancel_btn = ttk.Button(self._btns, text="Cancel", command=self._cancel)
        self._cancel_btn.pack(side="left")
        self._back_btn = ttk.Button(self._btns, text="Back", command=self._back)
        self._close_btn = ttk.Button(self._btns, text="Close", command=self._close)

        right = ttk.Frame(self, padding=(0, 12, 12, 12))
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        ttk.Label(right, text="Log", foreground="gray").grid(row=0, column=0, sticky="w")
        self._text = tk.Text(right, wrap="none", state="disabled", height=10,
                             font="TkFixedFont", background="#101010", foreground="#d8d8d8")
        ysb = ttk.Scrollbar(right, orient="vertical", command=self._text.yview)
        xsb = ttk.Scrollbar(right, orient="horizontal", command=self._text.xview)
        self._text.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self._text.grid(row=1, column=0, sticky="nsew")
        ysb.grid(row=1, column=1, sticky="ns")
        xsb.grid(row=2, column=0, sticky="ew")

    # thread-safe entry points (the create flow runs in a worker thread)
    def _ui(self, fn: Callable) -> None:
        def _run():
            try:
                if self.winfo_exists():
                    fn()
            except tk.TclError:
                pass
        try:
            self.after(0, _run)
        except (tk.TclError, RuntimeError):
            pass

    def set_stage(self, label: str, pct: Optional[float] = None, detail: str = "") -> None:
        """Stage text; pct only moves the bar forward (stages are reported in the order they happen)."""
        def _do():
            self._stage_var.set(label)
            self._detail_var.set(detail)
            if pct is not None:
                self._set_pct(max(self._pct, pct))
        self._ui(_do)

    def set_status(self, msg: str, busy: bool = False, pct: Optional[float] = None) -> None:
        """A download / generic status: pct sets the bar exactly, busy spins it."""
        def _do():
            self._stage_var.set(msg)
            self._pbar.stop()
            if pct is not None:
                self._pct = pct
                self._set_pct(pct, force=True)
            elif busy:
                self._pbar.configure(mode="indeterminate")
                self._pbar.start(10)
                self._pct_var.set("\u2026")
        self._ui(_do)

    def _set_pct(self, pct: float, force: bool = False) -> None:
        pct = max(0.0, min(100.0, pct))
        if not force and str(self._pbar.cget("mode")) != "determinate":
            self._pbar.stop()
        self._pbar.configure(mode="determinate", maximum=100)
        self._pbar["value"] = pct
        self._pct = pct
        self._pct_var.set("{:.0f}%".format(pct))

    def reset_progress(self) -> None:
        """A new phase starts (the download ends, firmwarekit begins): the bar starts over."""
        def _do():
            self._pbar.stop()
            self._set_pct(0.0, force=True)
            self._pct = 0.0
        self._ui(_do)

    def append_log(self, line: str) -> None:
        def _do():
            t = self._text
            at_end = t.yview()[1] >= 0.999
            t.configure(state="normal")
            t.insert("end", line + "\n")
            n = int(t.index("end-1c").split(".")[0])
            if n > self.MAX_LOG_LINES:
                t.delete("1.0", "{}.0".format(n - self.MAX_LOG_LINES + 1000))
            t.configure(state="disabled")
            if at_end:
                t.see("end")
        self._ui(_do)

    def finish(self, ok: bool, msg: str) -> None:
        def _do():
            self._done = True
            self._pbar.stop()
            if ok:
                self._set_pct(100.0, force=True)
            else:
                self._pbar.configure(mode="determinate")
            self._stage_var.set(msg)
            self._cancel_btn.pack_forget()
            if ok:
                self._back_btn.pack_forget()
            else:
                self._back_btn.pack(side="left", padx=(0, 6))
            self._close_btn.pack(side="left")
        self._ui(_do)

    # buttons
    def _cancel(self) -> None:
        self._on_cancel()

    def _back(self) -> None:
        self._on_back()

    def _close(self) -> None:
        self._on_close()

    def _x_pressed(self) -> None:
        (self._close if self._done else self._cancel)()


class CreateDeviceDialog(tk.Toplevel):
    """Wizard dialog that wraps firmwarekit.py to create a device bundle."""

    def __init__(
        self,
        parent,
        base_dir: Path,
        prefix:   str,
        catalog:  Path,
        log_fn:   Callable,
        download_dir: Optional[Path] = None,
    ) -> None:
        super().__init__(parent)
        self.title("New Virtual Device")
        self.resizable(False, True)
        self.grab_set()
        self.transient(parent)

        self._base    = base_dir
        self._prefix  = prefix
        self._catalog = catalog
        self._main_log = log_fn
        self._log     = self._tee_log     # the main window's log, and the progress window's
        self._prog: Optional["CreateProgressWindow"] = None
        self._stage_pct = 0.0
        self._gen = 0                     # bumped when a running create is aborted
        self._downloads = Path(download_dir) if download_dir else default_download_dir()
        self._proc    = None
        self._dl_proc = None      # aria2c, while downloading
        self._closed  = False
        self._board_keys = list(DEVICES.keys())
        self._build_keys = []
        self._show_beta  = tk.BooleanVar(value=True)
        self._show_unsup = tk.BooleanVar(value=False)

        self._build_widgets()
        self._refresh_board()
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ── widgets ──────────────────────────────────────────────────────────────

    def _build_widgets(self) -> None:
        P = {"padx": 8, "pady": 4, "sticky": "w"}
        # status, progress bar and buttons stay at the bottom; the form above them scrolls
        fixed = ttk.Frame(self, padding=(8, 0, 8, 8))
        fixed.pack(side="bottom", fill="x")
        sf = ScrollableFrame(self, padding=8)
        sf.pack(side="top", fill="both", expand=True)
        f = sf.body
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
                            lambda _: (self._refresh_out(), self._refresh_hint()))
        row += 1

        # Build filters + catalog note for the selected build
        ff = ttk.Frame(f)
        ff.grid(row=row, column=1, columnspan=2, **P)
        ttk.Checkbutton(ff, text="Developer / beta builds", variable=self._show_beta,
                        command=self._refresh_builds).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(ff, text="Coming soon (unsupported)", variable=self._show_unsup,
                        command=self._refresh_builds).pack(side="left")
        row += 1
        self._build_hint = ttk.Label(f, text="", foreground="gray",
                                      wraplength=420, justify="left")
        self._build_hint.grid(row=row, column=1, columnspan=2, **P)
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
        cat_entry = ttk.Entry(f, textvariable=self._cat_var, width=36)
        cat_entry.grid(row=row, column=1, **P)
        cat_entry.bind("<FocusOut>", lambda _: self._reload_catalog())
        cat_entry.bind("<Return>",   lambda _: self._reload_catalog())
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

        # Jailbreak
        self._jailbreak = tk.BooleanVar(value=False)
        self._jb_cb = ttk.Checkbutton(
            f, text="Jailbreak the device (afc2 + Cydia)", variable=self._jailbreak)
        self._jb_cb.grid(row=row, column=1, columnspan=2, **P)
        row += 1
        self._jb_hint = ttk.Label(f, text="", foreground="gray",
                                  wraplength=420, justify="left")
        self._jb_hint.grid(row=row, column=1, columnspan=2, **P)
        row += 1

        # Guest package + No GLES
        ttk.Label(f, text="Guest package:").grid(row=row, column=0, **P)
        self._gp_var = tk.StringVar()
        ttk.Entry(f, textvariable=self._gp_var, width=36).grid(row=row, column=1, **P)
        ttk.Button(f, text="Browse\u2026", command=self._browse_gp).grid(row=row, column=2, **P)
        row += 1
        self._no_gles = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            f, text="No GLES (leave the GL hooks out of the guest package)",
            variable=self._no_gles).grid(row=row, column=1, columnspan=2, **P)
        row += 1
        ttk.Label(f, text="Optional .itpack (contrib/guest-package/build.sh) baked into the rootfs; needs root and the "
                          "hfsplus module. Not used by the iPod touch 2G. With No GLES the OpenGLES front end and "
                          "the MBX shim stay out (firmwarekit --no-gles).",
                  foreground="gray", wraplength=420, justify="left").grid(
            row=row, column=1, columnspan=2, **P)
        row += 1

        # Status label + progress bar
        self._status_var = tk.StringVar(value="Ready.")
        ttk.Label(fixed, textvariable=self._status_var,
                  foreground="gray").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        self._pbar = ttk.Progressbar(fixed, mode="indeterminate", length=500)
        self._pbar.grid(row=1, column=0, padx=8, pady=4, sticky="ew")
        fixed.columnconfigure(0, weight=1)

        # Action buttons
        bf = ttk.Frame(fixed)
        bf.grid(row=2, column=0, pady=8)
        self._create_btn = ttk.Button(bf, text="Create Device",
                                       command=self._on_create)
        self._create_btn.pack(side="left", padx=6)
        ttk.Button(bf, text="Cancel", command=self._close).pack(
            side="left", padx=6)

        # Picking (or pasting) an IPSW selects its device and iOS build from the file name.
        # Registered last so the first refresh above never triggers it.
        self._ipsw_detected = None
        self._ipsw_var.trace_add("write", self._ipsw_path_changed)

    # ── helpers ──────────────────────────────────────────────────────────────

    def _cur_board(self) -> str:
        return self._board_keys[self._board_cb.current()]

    def _cur_build(self) -> str:
        i = self._build_cb.current()
        return self._build_keys[i] if (i >= 0 and self._build_keys) else ""

    def _refresh_builds(self, keep: bool = True) -> None:
        """Fill the build drop-down for the current board and filters."""
        board = self._cur_board()
        dev   = DEVICES[board]
        prev  = self._cur_build() if keep else ""
        self._build_keys = list_builds(board, self._show_beta.get(),
                                       self._show_unsup.get())
        self._build_cb["values"] = [
            build_label(board, b, dev["builds"][b]) for b in self._build_keys]
        if self._build_keys:
            self._build_cb.current(
                self._build_keys.index(prev) if prev in self._build_keys else 0)
        else:
            self._build_cb.set("")
        self._refresh_out()
        self._refresh_hint()

    def _refresh_hint(self) -> None:
        board, build = self._cur_board(), self._cur_build()
        info = build_info(board, build)
        bits = []
        if info.get("released"):
            bits.append("released " + info["released"])
        if info.get("status"):
            bits.append(info["status"].replace("_", " "))
        text = ", ".join(bits)
        if info.get("status_note"):
            text += ("\n" if text else "") + info["status_note"]
        self._build_hint.configure(text=text)
        if hasattr(self, "_jb_cb"):
            self._refresh_jailbreak()

    @staticmethod
    def _jailbreak_problem(board: str, version: str) -> str:
        """Why this board/build can't be jailbroken by firmwarekit create ('' = it can)."""
        m = re.match(r"\d+", version or "")
        if m and int(m.group()) < 2:
            return "Needs iPhone OS 2.0 or later."
        return ""

    def _refresh_jailbreak(self) -> None:
        board, build = self._cur_board(), self._cur_build()
        version = DEVICES[board]["builds"].get(build, "") if build else ""
        why = self._jailbreak_problem(board, version)
        if why:
            self._jailbreak.set(False)
        self._jb_cb.configure(state="disabled" if why else "normal")
        self._jb_hint.configure(
            text=why or "Installs afc2 and Cydia (with Substrate on iOS 3-6). Needs root; "
                        "downloads the Cydia bootstrap once; the first boot takes longer.")

    def _reload_catalog(self) -> None:
        cat = self._cat_var.get().strip()
        if cat and Path(cat).is_file():
            n = apply_catalog(cat)
            self._log("Catalog {}: {} builds.".format(cat, n))
            self._refresh_builds()

    def _refresh_board(self) -> None:
        board = self._cur_board()
        dev   = DEVICES[board]
        self._refresh_builds(keep=False)

        needs_br = dev.get("needs_bootrom", False)
        br_state = "normal" if needs_br else "disabled"
        self._bootrom_entry.configure(state=br_state)
        self._bootrom_brow.configure(state=br_state)
        self._bootrom_hint.configure(
            text="Required for this board (copied into the device folder)"
                 if needs_br else "Not required for this board",
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

    def _ipsw_path_changed(self, *_args) -> None:
        """Select the Device and iOS Build the IPSW's file name names (iPod2,1_3.1.3_7E18_Restore.ipsw).
        Acts once per distinct result, so the person can still change the choice afterwards."""
        p = self._ipsw_var.get().strip()
        det = parse_ipsw_filename(p) if p.lower().endswith(".ipsw") else {}
        if not det or det == self._ipsw_detected:
            return
        self._ipsw_detected = det
        board, build = det["board"], det.get("build", "")
        if board not in self._board_keys:
            return
        if board != self._cur_board():
            self._board_cb.current(self._board_keys.index(board))
            self._refresh_board()
        if build and build not in self._build_keys:      # hidden by the beta / coming-soon filters
            info = build_info(board, build)
            if info.get("prerelease"):
                self._show_beta.set(True)
            if info.get("status") == "coming_soon":
                self._show_unsup.set(True)
            self._refresh_builds()
        if build and build in self._build_keys:
            self._build_cb.current(self._build_keys.index(build))
            self._refresh_out()
            self._refresh_hint()
        name = DEVICES[board]["name"]
        if build:
            self._log("IPSW file name: {} / iOS {} ({}).".format(name, det["version"], build))
        else:
            self._log("IPSW file name: {}; its iOS build is not in the list, pick it above.".format(name))

    def _browse_gp(self) -> None:
        p = filedialog.askopenfilename(parent=self, title="Select a guest package",
                                       filetypes=[("Guest package", "*.itpack"), ("All files", "*")])
        if p:
            self._gp_var.set(p)

    def _browse_ipsw(self) -> None:
        p = filedialog.askopenfilename(
            parent=self, title="Select IPSW",
            initialdir=str(self._downloads) if self._downloads.is_dir() else None,
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
            self._reload_catalog()

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

    def _set_status(self, msg: str, busy: bool = False,
                    pct: Optional[float] = None) -> None:
        """busy -> spinning bar; pct (0-100) -> filled bar; neither -> idle."""
        def _do():
            self._status_var.set(msg)
            self._pbar.stop()
            if pct is not None:
                self._pbar.configure(mode="determinate", maximum=100)
                self._pbar["value"] = pct
            elif busy:
                self._pbar.configure(mode="indeterminate")
                self._pbar.start(10)
            else:
                self._pbar.configure(mode="determinate", maximum=100)
                self._pbar["value"] = 0
        self._ui(_do)
        if self._prog is not None:
            self._prog.set_status(msg, busy=busy, pct=pct)

    def _tee_log(self, msg: str) -> None:
        self._main_log(msg)
        if self._prog is not None:
            self._prog.append_log(msg)

    # (pattern, stage label, overall % reached) for firmwarekit's own progress lines
    _STAGES = [
        (r"^IPSW ok|^skipping IPSW SHA-1", "Verifying the IPSW", 4),
        (r"^building nor\.bin", "Building the NOR image", 10),
        (r"^decrypting firmware components", "Decrypting firmware components", 22),
        (r"^building kboot\.bin", "Building the kernel boot image", 26),
        (r"^bootrom ", "Installing the bootrom", 30),
        (r"^\[nand 1/5\]", "NAND 1/5: decrypting the root filesystem", 34),
        (r"^extracting HFS\+ volume|^\[nand 2/5\]", "Extracting the root filesystem", 44),
        (r"^\[nand 3/5\]", "NAND 3/5: growing the volume", 52),
        (r"^\[nand 4/5\] fstab|mounting|^editing", "Editing the system volume", 58),
        (r"activating lockdownd", "Activating lockdownd", 66),
        (r"installing the jailbreak", "Installing the jailbreak", 72),
        (r"seeding the guest package", "Seeding the guest package", 76),
        (r"^\[nand 5/5\]|^writing the NAND page|^building NAND store",
         "Writing the NAND page store (the longest step)", 82),
        (r"^done:", "Finishing", 98),
    ]

    def _create_line(self, line: str) -> None:
        """One line of firmwarekit output: into the logs, and the stage / percentage if it names one."""
        self._log(line)
        for pat, label, pct in self._STAGES:
            if re.search(pat, line):
                self._stage_pct = max(self._stage_pct, pct)
                if self._prog is not None:
                    self._prog.set_stage(label, self._stage_pct)
                break

    # ── hide the form, show the progress window ──────────────────────────────

    def _open_progress(self, board: str) -> None:
        self._stage_pct = 0.0
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.withdraw()
        self._prog = CreateProgressWindow(
            self.master, DEVICES[board]["name"],
            on_cancel=self._progress_cancel, on_back=self._progress_back,
            on_close=self._progress_close)
        self._prog.set_stage("Starting\u2026", 0)

    def _progress_cancel(self) -> None:
        """Cancel pressed while running: abort (after confirming), and put the form back."""
        if not self._abort_running(self._prog or self):
            return
        self._progress_back()

    def _progress_back(self) -> None:
        """Back to the form, e.g. to fix something after a failure."""
        prog, self._prog = self._prog, None
        if prog is not None:
            prog.destroy()
        self._create_btn.configure(state="normal")
        self.deiconify()
        try:
            self.grab_set()
        except tk.TclError:
            pass

    def _progress_close(self) -> None:
        """Close the progress window and the form with it."""
        prog, self._prog = self._prog, None
        if prog is not None:
            prog.destroy()
        self.destroy()

    def _fail(self, msg: str) -> None:
        """The create stopped with an error: say so on the form and in the progress window."""
        self._set_status(msg)
        if self._prog is not None:
            self._prog.finish(False, msg)
        self._ui(lambda: self._create_btn.configure(state="normal"))

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
        if dev.get("needs_bootrom"):
            br = self._bootrom_var.get().strip()
            if not br:
                messagebox.showwarning("Missing bootrom",
                                       "This board requires a bootrom file.",
                                       parent=self)
                return
            if not Path(os.path.expanduser(br)).is_file():
                messagebox.showwarning("Missing bootrom",
                                       "Bootrom file not found:\n{}".format(br),
                                       parent=self)
                return

        info = build_info(board, build)
        if info.get("status") == "coming_soon" and not messagebox.askyesno(
                "Not supported yet",
                "{}\n\nThis build is marked \"coming soon\": it will probably not "
                "boot.  Create it anyway?".format(info.get("status_note", "")),
                parent=self):
            return

        self._create_btn.configure(state="disabled")
        self._jb_requested = bool(self._jailbreak.get())    # read here: Tk vars belong to this thread
        self._no_gles_requested = bool(self._no_gles.get())
        self._gp_requested = self._gp_var.get().strip()

        if self._ipsw_mode.get() == "browse":
            ipsw = self._ipsw_var.get().strip()
            if not ipsw or not Path(ipsw).exists():
                messagebox.showwarning("Missing IPSW",
                                       "Select a valid IPSW file.", parent=self)
                self._create_btn.configure(state="normal")
                return
            self._open_progress(board)
            threading.Thread(
                target=self._run_create,
                args=(board, dev, build, ipsw, out, cat),
                daemon=True,
            ).start()
        else:
            self._open_progress(board)
            threading.Thread(
                target=self._download_and_create,
                args=(board, dev, build, out, cat),
                daemon=True,
            ).start()

    def _download_and_create(
        self, board: str, dev: dict, build: str, out: str, cat: str
    ) -> None:
        gen = self._gen
        product = dev["product"]
        version = dev["builds"][build]
        self._set_status(
            "Looking up IPSW for {} {}…".format(product, version), busy=True)

        fname = ipsw_filename(product, version, build)
        dl_dir = self._downloads
        dest   = dl_dir / fname

        if not dest.exists():
            try:
                dl_dir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                self._fail("Cannot create download folder {}: {}".format(dl_dir, exc))
                return
            # Catalog sources first (they cover beta seeds and RAR-packed builds, with
            # mirrors); ipsw.me last, for final releases only.
            cands = catalog_sources(board, build)
            if not is_prerelease(board, build):
                api = fetch_ipsw_download_url(product, build)
                if api and all(api != c["url"] for c in cands):
                    cands.append({"url": api, "kind": "ipsw",
                                  "member": None, "sha1": None})
            if not cands:
                self._fail("No download source for this build.  Try browsing for the file.")
                return

            def _set_dl_proc(p) -> None:
                self._dl_proc = p

            ok = False
            for cand in cands:
                is_rar = cand["kind"] == "rar" and cand.get("member")
                target = (dl_dir / "{}-{}.rar".format(board, build)
                          if is_rar else dest)
                label  = target.name

                def _progress(done, total, note="", label=label) -> None:
                    if done is None:        # non-fatal problem (aria2c failed)
                        self._log(note + " -- falling back to urllib")
                        return
                    if total:
                        pct = done * 100 / total
                        msg = "Downloading {}…  {:.0f}%".format(label, pct)
                        if total != 100:    # urllib: byte counts
                            msg += "  ({} / {} MiB)".format(
                                done >> 20, total >> 20)
                        if note:
                            msg += "  " + note
                        self._set_status(msg, pct=pct)
                    else:                   # size unknown
                        self._set_status(
                            "Downloading {}… {} MiB".format(label, done >> 20),
                            busy=True)

                tool = "aria2c -x16 -s16" if shutil.which("aria2c") else "urllib"
                self._log("Downloading {} with {}  ({})".format(
                    label, tool, cand["url"]))
                self._set_status("Downloading {}…  0%".format(label), pct=0)
                try:
                    download_url_to_file(cand["url"], target, _progress,
                                         should_stop=lambda: self._closed or gen != self._gen,
                                         on_proc=_set_dl_proc)
                    if is_rar:
                        self._set_status("Unpacking {}…".format(cand["member"]),
                                         busy=True)
                        extract_rar_member(target, cand["member"], dest)
                        target.unlink()
                    if cand.get("sha1") and dest.exists():
                        if sha1_file(dest) != cand["sha1"]:
                            self._log("  WARNING: sha1 of {} does not match the "
                                      "catalog.".format(fname))
                    ok = dest.exists()
                except DownloadCancelled:
                    self._log("Download cancelled.")
                    return
                except Exception as exc:
                    self._log("  source failed: {}".format(exc))
                    for left in (target, dest):
                        try:
                            left.unlink()
                        except OSError:
                            pass
                if ok:
                    break
            if not ok:
                self._fail("Download failed (see the log).  Try browsing for the file.")
                return

        self._set_status("Download complete. Running firmwarekit.py…", busy=True)
        self._run_create(board, dev, build, str(dest), out, cat)

    @staticmethod
    def _as_root(cmd: list) -> list:
        """Prefix cmd so it runs as root through pkexec (never sudo: a GUI has no terminal to answer it).

        pkexec starts the program in a sanitised environment and in root's
        home directory, so relative paths are made absolute and the variables
        firmwarekit needs are passed explicitly through env(1).
        """
        fwd = ["{}={}".format(k, os.environ[k])
               for k in ("BOOTROM", "QEMU", "IT_KEYBAG") if os.environ.get(k)]
        return ["pkexec", "env"] + fwd + cmd

    def _run_create(
        self, board: str, dev: dict, build: str,
        ipsw: str, out: str, cat: str
    ) -> None:
        gen = self._gen
        ipsw, cat, out = (os.path.abspath(os.path.expanduser(x))
                          for x in (ipsw, cat, out))
        cmd = [
            # -u: unbuffered.  Piped, Python block-buffers stdout (8 KB), so the progress window would show nothing
            # until firmwarekit exits.  As an argument (not PYTHONUNBUFFERED) it also survives pkexec's clean environment.
            sys.executable, "-u", str(FIRMWAREKIT), "create",
            "--ipsw",    ipsw,
            "--catalog", cat,
            "--id",      "{}-{}".format(board, build),
            "--out",     out,
            # scratch space next to the device folder (firmwarekit removes it itself)
            "--tmpdir",  str(Path(out).parent),
        ]
        seed    = self._seed_var.get().strip()
        bootrom = self._bootrom_var.get().strip()
        if seed:
            cmd += ["--seed", seed]
        if bootrom and dev.get("needs_bootrom"):
            # firmwarekit copies it into the device folder; run.sh uses that copy
            cmd += ["--bootrom", os.path.abspath(os.path.expanduser(bootrom))]
        gp = getattr(self, "_gp_requested", "")
        if gp and board != "n72ap":
            cmd += ["--guest-package", os.path.abspath(os.path.expanduser(gp))]
            if getattr(self, "_no_gles_requested", False):
                cmd += ["--no-gles"]
        jailbreak = bool(getattr(self, "_jb_requested", False))
        if jailbreak:
            cmd += ["--jailbreak"]
        if dev.get("needs_sudo") or jailbreak or (gp and board != "n72ap"):      # the jailbreak edits the loop-mounted rootfs
            if not shutil.which("pkexec"):
                self._fail("This device needs root and pkexec (polkit) is not installed.")
                return
            cmd = self._as_root(cmd)

        try:
            Path(out).parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass    # firmwarekit (as root) may still be able to create it

        self._set_status("Running firmwarekit.py…", busy=True)
        if self._prog is not None:
            self._prog.reset_progress()
            self._prog.set_stage("Starting firmwarekit\u2026", 2)
        self._stage_pct = 2.0
        self._log("$ " + " ".join(str(x) for x in cmd))

        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in self._proc.stdout:
                self._create_line(line.rstrip())
            self._proc.wait()
            rc = self._proc.returncode
            if gen != self._gen or self._closed:
                pass                    # cancelled: the progress window is already gone
            elif rc == 0:
                self._set_status("Device created successfully!")
                if self._prog is not None:
                    self._prog.finish(True, "Device created successfully!")
                self._ui(self.destroy)  # the form is done; the progress window stays until Close
            else:
                self._fail("firmwarekit.py exited with code {} (see the log).".format(rc))
        except Exception as exc:
            self._fail("Error: {}".format(exc))
        finally:
            self._proc = None
            self._ui(lambda: self._create_btn.configure(state="normal"))

    # ── close ────────────────────────────────────────────────────────────────

    def _abort_running(self, parent) -> bool:
        """Stop a running download / firmwarekit after confirming; False when the user declined."""
        dl = self._dl_proc
        if dl and dl.poll() is None:
            if not messagebox.askyesno(
                "Download in progress",
                "The IPSW is still downloading.  Cancel it?", parent=parent):
                return False
        if self._proc and self._proc.poll() is None:
            if not messagebox.askyesno(
                "In progress",
                "firmwarekit.py is still running.  Abort?", parent=parent):
                return False
            self._proc.terminate()
        self._gen += 1                 # stops the download / create threads (they hold the old number)
        if dl and dl.poll() is None:
            dl.terminate()
        return True

    def _close(self) -> None:
        if not self._abort_running(self):
            return
        if self._prog is not None:
            self._prog.destroy()
            self._prog = None
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Settings dialog
# ─────────────────────────────────────────────────────────────────────────────

class SettingsDialog(tk.Toplevel):
    """Change where devices live and how their folders are named."""

    def __init__(self, parent, base_dir: Path, prefix: str,
                 on_save: Callable, download_dir: Optional[Path] = None) -> None:
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

        ttk.Label(f, text="IPSW downloads:").grid(row=4, column=0, **P)
        self._dl_var = tk.StringVar(
            value=str(download_dir or default_download_dir()))
        ttk.Entry(f, textvariable=self._dl_var, width=44).grid(
            row=4, column=1, **P)
        ttk.Button(f, text="Browse…", command=self._browse_dl).grid(
            row=4, column=2, **P)
        ttk.Label(
            f, foreground="gray", wraplength=480, justify="left",
            text="Auto-downloaded IPSWs are saved here (default: your Downloads "
                 "folder) and reused next time.  firmwarekit's scratch folder is "
                 "created inside the device folder and deleted when it finishes.",
        ).grid(row=5, column=0, columnspan=3, **P)

        bf = ttk.Frame(f)
        bf.grid(row=6, column=0, columnspan=3, pady=8)
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

    def _browse_dl(self) -> None:
        cur = Path(os.path.expanduser(self._dl_var.get().strip() or "~"))
        while not cur.is_dir() and cur != cur.parent:
            cur = cur.parent
        p = filedialog.askdirectory(parent=self, initialdir=str(cur),
                                    title="Select IPSW download folder")
        if p:
            self._dl_var.set(p)

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
        dl_raw = self._dl_var.get().strip()
        dl = Path(os.path.expanduser(dl_raw)) if dl_raw else default_download_dir()
        if dl.exists() and not dl.is_dir():
            messagebox.showwarning("Not a folder",
                                   "{} is not a folder.".format(dl), parent=self)
            return
        self._on_save(base, prefix, dl)
        self.destroy()


class DevicePrefsDialog(tk.Toplevel):
    """Per-device preferences: name, verbose boot, boot-args, RAM, window scale, ..."""

    def __init__(self, parent, title: str, board: str, prefs: dict,
                 boot_args_ok: bool, on_save: Callable) -> None:
        super().__init__(parent)
        self.title("Device Preferences")
        self.resizable(False, True)
        self.transient(parent)
        self.grab_set()
        self._on_save = on_save

        dev = DEVICES.get(board, {})
        P = {"padx": 8, "pady": 4, "sticky": "w"}
        # Save / Reset / Cancel stay at the bottom; the preferences above them scroll
        bf = ttk.Frame(self, padding=(10, 0, 10, 8))
        bf.pack(side="bottom")
        sf = ScrollableFrame(self, padding=10)
        sf.pack(side="top", fill="both", expand=True)
        f = sf.body
        row = 0

        ttk.Label(f, text=title, font=("", 10, "bold")).grid(
            row=row, column=0, columnspan=3, **P)
        row += 1

        self._pv_name = tk.StringVar(value=prefs["name"])
        ttk.Label(f, text="Name:").grid(row=row, column=0, **P)
        ttk.Entry(f, textvariable=self._pv_name, width=34).grid(
            row=row, column=1, columnspan=2, **P)
        row += 1
        ttk.Label(f, text="Shown in the device list and used as the window title.",
                  foreground="gray").grid(row=row, column=1, columnspan=2, **P)
        row += 1

        self._pv_verbose = tk.BooleanVar(value=bool(prefs["verbose"]))
        ttk.Checkbutton(f, text="Verbose boot (-v)", variable=self._pv_verbose).grid(
            row=row, column=1, columnspan=2, **P)
        row += 1

        self._pv_boot_args = tk.StringVar(value=prefs["boot_args"])
        ttk.Label(f, text="Boot-args:").grid(row=row, column=0, **P)
        ttk.Entry(f, textvariable=self._pv_boot_args, width=34).grid(
            row=row, column=1, columnspan=2, **P)
        row += 1
        ttk.Label(
            f, foreground="gray", wraplength=380, justify="left",
            text=("Replaces iBoot's whole kernel command line (it is not appended). "
                  "Only machines with a boot-args property support this "
                  "(checked when the device starts)."
                  if boot_args_ok else
                  "This board's machine model may not have a boot-args property; "
                  "it is checked when the device starts and ignored if missing."),
        ).grid(row=row, column=1, columnspan=2, **P)
        row += 1

        ram = prefs["ram_mb"]
        self._pv_ram = tk.StringVar(value="Default" if not ram else str(ram))
        ttk.Label(f, text="RAM (MB):").grid(row=row, column=0, **P)
        ttk.Combobox(f, textvariable=self._pv_ram, values=RAM_CHOICES, width=10).grid(
            row=row, column=1, **P)
        ttk.Label(f, foreground="gray",
                  text="Real hardware: {} MB (QEMU -m)".format(
                      dev.get("ram_mb", "?"))).grid(row=row, column=2, **P)
        row += 1

        self._pv_usb = tk.StringVar(value=prefs["usb_addr"])
        ttk.Label(f, text="USB connection:").grid(row=row, column=0, **P)
        uf = ttk.Frame(f)
        uf.grid(row=row, column=1, columnspan=2, **P)
        ttk.Entry(uf, textvariable=self._pv_usb, width=26).pack(side="left")
        ttk.Button(uf, text="Browse\u2026", command=self._browse_usb).pack(
            side="left", padx=(6, 0))
        row += 1
        ttk.Label(
            f, foreground="gray", wraplength=380, justify="left",
            text="Where the device's USB goes: a port (1235), host:port, or the path "
                 "of a Unix socket. A usbmuxd with USBMUXD_QEMU_ADDR set to the same "
                 "value must be listening (QEMU dials out). Empty = the machine's "
                 "default.").grid(row=row, column=1, columnspan=2, **P)
        row += 1

        self._pv_baseband = tk.StringVar(
            value=BASEBAND_CHOICES[("default", "on", "off").index(prefs["baseband"])]
            if prefs["baseband"] in ("default", "on", "off") else "Default")
        ttk.Label(f, text="Baseband:").grid(row=row, column=0, **P)
        ttk.Combobox(f, textvariable=self._pv_baseband, values=BASEBAND_CHOICES,
                     width=10, state="readonly").grid(row=row, column=1, **P)
        ttk.Label(f, foreground="gray",
                  text="Cellular modem (QEMU baseband=on/off)").grid(
            row=row, column=2, **P)
        row += 1
        ttk.Label(
            f, foreground="gray", wraplength=380, justify="left",
            text="Default keeps the machine's own setting (the iPhone 2G has a modem, "
                 "the iPhone 4 needs it switched On). Call / SMS / carrier need it On."
        ).grid(row=row, column=1, columnspan=2, **P)
        row += 1

        self._pv_carrier = tk.StringVar(value=prefs["carrier"])
        self._pv_plmn = tk.StringVar(value=prefs["mcc_mnc"])
        ttk.Label(f, text="Carrier name:").grid(row=row, column=0, **P)
        cb = ttk.Combobox(f, textvariable=self._pv_carrier,
                          values=[c[0] for c in CARRIERS], width=31)
        cb.grid(row=row, column=1, columnspan=2, **P)
        cb.bind("<<ComboboxSelected>>", self._carrier_picked)
        row += 1
        ttk.Label(f, text="MCC-MNC:").grid(row=row, column=0, **P)
        ttk.Entry(f, textvariable=self._pv_plmn, width=12).grid(
            row=row, column=1, **P)
        ttk.Label(f, foreground="gray", text="optional, 5-6 digits").grid(
            row=row, column=2, **P)
        row += 1
        ttk.Label(
            f, foreground="gray", wraplength=380, justify="left",
            text="Name the phone shows for its network (empty = the modem's own). "
                 "Applied over QMP a moment after the device starts; needs the "
                 "baseband On."
        ).grid(row=row, column=1, columnspan=2, **P)
        row += 1

        w, h = dev.get("screen", (0, 0))
        self._pv_scale = tk.StringVar(value=str(prefs["scale"]))
        ttk.Label(f, text="Window scale:").grid(row=row, column=0, **P)
        ttk.Combobox(f, textvariable=self._pv_scale, values=SCALE_CHOICES, width=10).grid(
            row=row, column=1, **P)
        ttk.Label(f, foreground="gray",
                  text="Native screen: {}×{}".format(w, h)).grid(
            row=row, column=2, **P)
        row += 1

        self._pv_rotate = tk.StringVar(value=str(prefs["rotate"]))
        ttk.Label(f, text="Rotation:").grid(row=row, column=0, **P)
        ttk.Combobox(f, textvariable=self._pv_rotate, values=ROTATE_CHOICES,
                     width=10, state="readonly").grid(row=row, column=1, **P)
        row += 1
        ttk.Label(
            f, foreground="gray", wraplength=380, justify="left",
            text="The guest's screen resolution is fixed by the emulated hardware; "
                 "scale and rotation apply to the touch-panel window (not the SDL "
                 "window).").grid(row=row, column=1, columnspan=2, **P)
        row += 1

        self._pv_sound = tk.StringVar(value=str(prefs["sound"]))
        ttk.Label(f, text="Sound:").grid(row=row, column=0, **P)
        ttk.Combobox(f, textvariable=self._pv_sound, values=SOUND_CHOICES,
                     width=10).grid(row=row, column=1, **P)
        row += 1
        ttk.Label(
            f, foreground="gray", wraplength=380, justify="left",
            text="off = muted (the default). auto = the first host audio driver this QEMU "
                 "was built with. Or type a driver name (pipewire, pa, alsa, sdl, "
                 "coreaudio...). Applies to every board; the iPod touch 1G only "
                 "plays its buzzer clicks. Checked when the device starts."
        ).grid(row=row, column=1, columnspan=2, **P)
        row += 1

        self._pv_extra = tk.StringVar(value=prefs["extra_args"])
        ttk.Label(f, text="Extra QEMU args:").grid(row=row, column=0, **P)
        ttk.Entry(f, textvariable=self._pv_extra, width=34).grid(
            row=row, column=1, columnspan=2, **P)
        row += 1

        ttk.Button(bf, text="Save", command=self._save).pack(side="left", padx=6)
        ttk.Button(bf, text="Reset", command=self._reset).pack(side="left", padx=6)
        ttk.Button(bf, text="Cancel", command=self.destroy).pack(side="left", padx=6)

    def _reset(self) -> None:
        d = DEFAULT_PREFS
        self._pv_name.set(d["name"])
        self._pv_verbose.set(d["verbose"])
        self._pv_boot_args.set(d["boot_args"])
        self._pv_ram.set("Default")
        self._pv_usb.set(d["usb_addr"])
        self._pv_baseband.set("Default")
        self._pv_carrier.set(d["carrier"])
        self._pv_plmn.set(d["mcc_mnc"])
        self._pv_scale.set(d["scale"])
        self._pv_rotate.set(str(d["rotate"]))
        self._pv_sound.set(d["sound"])
        self._pv_extra.set(d["extra_args"])

    def _carrier_picked(self, _e=None) -> None:
        for name, plmn in CARRIERS:
            if name == self._pv_carrier.get():
                self._pv_plmn.set(plmn)

    def _browse_usb(self) -> None:
        cur = self._pv_usb.get().strip()
        start = Path(cur).parent if cur.startswith("/") and Path(cur).parent.is_dir() \
            else Path.home()
        p = filedialog.askopenfilename(parent=self, initialdir=str(start),
                                       title="Select the bridge's Unix socket")
        if p:
            self._pv_usb.set(p)

    def _save(self) -> None:
        ram_txt = self._pv_ram.get().strip()
        try:
            ram = 0 if ram_txt.lower() in ("", "default") else int(ram_txt)
        except ValueError:
            messagebox.showwarning("Invalid RAM", "RAM must be Default or a "
                                   "number of MB.", parent=self)
            return
        try:
            rotate = int(self._pv_rotate.get())
        except ValueError:
            rotate = -1
        prefs = {
            "name":       self._pv_name.get().strip(),
            "verbose":    bool(self._pv_verbose.get()),
            "boot_args":  self._pv_boot_args.get().strip(),
            "ram_mb":     ram,
            "usb_addr":   normalize_usb_addr(self._pv_usb.get())[0],
            "baseband":   self._pv_baseband.get().strip().lower() or "default",
            "carrier":    self._pv_carrier.get().strip(),
            "mcc_mnc":    self._pv_plmn.get().strip(),
            "scale":      self._pv_scale.get().strip() or "fit",
            "rotate":     rotate,
            "sound":      self._pv_sound.get().strip().lower() or "off",
            "extra_args": self._pv_extra.get().strip(),
        }
        errs = validate_prefs(prefs)
        if errs:
            messagebox.showwarning("Invalid preferences", "\n".join(errs),
                                   parent=self)
            return
        self._on_save(prefs)
        self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Main window
# ─────────────────────────────────────────────────────────────────────────────

class App(tk.Tk):

    def __init__(self, base_dir: Path, catalog: Path,
                 prefix: str = DEFAULT_PREFIX,
                 download_dir: Optional[Path] = None) -> None:
        super().__init__()
        self.title("QEMU-iOS Device Manager")
        self.geometry("980x650")
        self.minsize(720, 460)

        self._base    = base_dir
        self._prefix  = prefix
        self._download = Path(download_dir) if download_dir else default_download_dir()
        self._catalog = catalog
        self._devs: list    = []
        self._running: dict = {}   # path_str → subprocess.Popen
        self._panels: dict  = {}   # path_str → {"dir", "sock", "title", "proc"}
        self._argdirs: dict = {}   # path_str → temp dir of the preferences wrapper
        self._panel_var = tk.BooleanVar(
            value=bool(load_config().get("touch_panel", True)))

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
        tb_btn("☰  Prefs",     self._edit_prefs)
        ttk.Separator(tb, orient="vertical").pack(
            side="left", fill="y", padx=6, pady=2)
        ttk.Checkbutton(
            tb, text="Touch panel", variable=self._panel_var,
            command=self._panel_pref_changed).pack(side="left", padx=3)
        tb_btn("☝  Panel", self._reopen_panel)
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
        for col, width in zip(cols, (220, 90, 110, 84, 340)):
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
        saved = load_config()
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
            custom = get_prefs(d["dirname"], saved)["name"]
            self._tree.insert(
                "", "end", iid=ps,
                values=(custom or d["device_name"], d["board"],
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
        dlg = SettingsDialog(self, self._base, self._prefix, self._apply_settings,
                             self._download)
        self.wait_window(dlg)

    def _apply_settings(self, base: Path, prefix: str,
                        download: Optional[Path] = None) -> None:
        self._base, self._prefix = base, prefix
        if download is not None:
            self._download = download
        self._update_base_label()
        try:
            cfg = load_config()
            cfg.update({"base": str(base), "prefix": prefix,
                        "download_dir": str(self._download)})
            save_config(cfg)
        except OSError as exc:
            messagebox.showwarning(
                "Settings not saved",
                "Applied for this session, but could not write {}:\n{}".format(
                    CONFIG_PATH, exc))
        self.log("Device folder: {}   Prefix: {}   IPSW downloads: {}".format(
            base, prefix, self._download))
        self.refresh()
        self._on_select()

    def _new_device(self) -> None:
        dlg = CreateDeviceDialog(self, self._base, self._prefix,
                                 self._catalog, self.log, self._download)
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
        bundled = sorted(d["path"].glob("bootrom_*"))
        if dev_meta.get("needs_bootrom") and bundled:
            env.pop("BOOTROM", None)    # run.sh uses the copy in the device folder
            self.log("  bootrom: {}".format(bundled[0].name))
        elif dev_meta.get("needs_bootrom"):
            bootrom = env.get("BOOTROM", "")
            if not bootrom or not Path(bootrom).exists():
                bootrom = filedialog.askopenfilename(
                    parent=self, title="Locate bootrom file")
                if not bootrom:
                    return
            env["BOOTROM"] = bootrom

        run_sh = d["path"] / "run.sh"
        prefs  = get_prefs(d["dirname"])
        label  = "{device_name}  [{board}-{build}]".format(**d)
        if prefs["name"]:
            label = "{}  [{}-{}]".format(prefs["name"], d["board"], d["build"])
        self.log("Starting {}  •  QEMU={}".format(label, qemu))

        # Touch panel: QMP socket + no SDL window (see prepare_touch_panel)
        panel = None
        if self._panel_var.get():
            panel = prepare_touch_panel(env, qemu)
            if panel is None:
                self.log("  touch panel: {} not found; using the SDL window."
                         .format(TOUCH_PANEL))

        # Preferences: extra QEMU arguments go through a wrapper that wraps whatever
        # $QEMU is now (the real binary, or the touch-panel wrapper).
        for msg in validate_prefs(prefs):
            self.log("  preferences: {}".format(msg))
        extra, notes = build_pref_args(qemu, d["board"], prefs)
        for n in notes:
            self.log("  preferences: {}".format(n))
        # The wrapper is always used: it also gives the manager its own QMP socket, which
        # the QmpAgent below uses to quit QEMU on guest power-off and to apply the carrier.
        drop_audio = pref_replaces_audio(prefs)
        aw = write_args_wrapper(env["QEMU"], extra, "mgr.sock", drop_null_audio=drop_audio)
        env["QEMU"] = aw["path"]
        self._argdirs[iid] = aw["dir"]
        if extra:
            self.log("  preferences: QEMU extra args: {}".format(
                " ".join(shlex.quote(a) for a in extra)))
        if drop_audio:
            self.log("  preferences: run.sh's muted audio (-audio driver=none) "
                     "is replaced.")
        if not panel and (prefs["scale"] != "fit" or prefs["rotate"]):
            self.log("  preferences: window scale / rotation only apply to the "
                     "touch panel; it is off, so they are ignored.")

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
            try:
                extra_tokens = shlex.split(prefs.get("extra_args", ""))
            except ValueError:
                extra_tokens = []
            QmpAgent(aw["sock"], proc, self.log,
                     carrier=prefs.get("carrier", "").strip(),
                     mcc_mnc=prefs.get("mcc_mnc", "").strip(),
                     auto_quit="-no-shutdown" not in extra_tokens,
                     # same name as touchPanel.reboot_hold_path(): QMP socket + ".reboot-pending"
                     hold_file=(panel["sock"] + ".reboot-pending") if panel else "").start()
            if panel:
                panel["title"] = label
                panel["scale"] = prefs["scale"]
                panel["rotate"] = prefs["rotate"]
                self._panels[iid] = panel
                self._open_panel(iid)
            threading.Thread(
                target=self._wait_exit,
                args=(iid, proc, label),
                daemon=True,
            ).start()
        except Exception as exc:
            if panel:
                shutil.rmtree(panel["dir"], ignore_errors=True)
            shutil.rmtree(self._argdirs.pop(iid, ""), ignore_errors=True)
            messagebox.showerror("Launch error", str(exc))

    # ── Device preferences ────────────────────────────────────────────────────

    def _edit_prefs(self) -> None:
        iid = self._sel_iid()
        d = self._dev_for(iid) if iid else None
        if not d:
            messagebox.showinfo("No selection", "Select a device first.")
            return
        prefs = get_prefs(d["dirname"])
        title = "{}  [{}-{}]".format(d["device_name"], d["board"], d["build"])

        def _saved(new: dict) -> None:
            try:
                save_prefs(d["dirname"], new)
            except OSError as exc:
                messagebox.showwarning(
                    "Preferences not saved",
                    "Could not write {}:\n{}".format(CONFIG_PATH, exc))
                return
            self.log("Preferences saved for {}.".format(d["dirname"]))
            if iid in self._running:
                self.log("They apply the next time this device starts.")
            self.refresh()
            self._on_select()

        dlg = DevicePrefsDialog(self, title, d["board"], prefs, True, _saved)
        self.wait_window(dlg)

    # ── Touch panel ───────────────────────────────────────────────────────────

    def _panel_pref_changed(self) -> None:
        try:
            cfg = load_config()
            cfg["touch_panel"] = bool(self._panel_var.get())
            save_config(cfg)
        except OSError:
            pass
        if self._running:
            self.log("Touch panel setting applies the next time a device starts.")

    def _open_panel(self, iid: str) -> None:
        """Start the touch-panel window for a running device that has a QMP socket."""
        info = self._panels.get(iid)
        if not info:
            return
        old = info.get("proc")
        if old is not None and old.poll() is None:
            return                              # already open
        try:
            info["proc"] = spawn_touch_panel(
                info["sock"], info["title"],
                info.get("scale", "fit"), info.get("rotate", 0),
                info.get("serial", ""))
        except Exception as exc:
            self.log("  touch panel failed to start: {}".format(exc))
            return
        self.log("  touch panel opened (PID {}).".format(info["proc"].pid))
        threading.Thread(target=self._panel_exit,
                         args=(info["proc"],), daemon=True).start()

    def _panel_exit(self, proc: subprocess.Popen) -> None:
        err = proc.stderr.read() if proc.stderr else ""
        proc.wait()
        if proc.returncode not in (0, None) and err.strip():
            self.after(0, lambda: self.log(
                "touch panel exited ({}): {}".format(
                    proc.returncode, err.strip().splitlines()[-1])))

    def _reopen_panel(self) -> None:
        iid = self._sel_iid()
        if not iid or iid not in self._running:
            messagebox.showinfo(
                "Touch panel",
                "Select a running device that was started with the touch panel "
                "enabled.")
            return
        if iid not in self._panels:
            messagebox.showinfo(
                "Touch panel",
                "This device was started without the touch panel (it uses the "
                "SDL window).\nTick \"Touch panel\" and start it again.")
            return
        self._open_panel(iid)

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
        shutil.rmtree(self._argdirs.pop(iid, ""), ignore_errors=True)
        panel = self._panels.pop(iid, None)
        if panel:
            pp = panel.get("proc")
            if pp is not None and pp.poll() is None:
                pp.terminate()                  # QEMU is gone; close its panel
            shutil.rmtree(panel["dir"], ignore_errors=True)
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
            prefs = get_prefs(d["dirname"])
            info  = build_info(d["board"], d["build"])
            lines = [
                "Name         {}".format(prefs["name"] or "(none)"),
                "Device       {}".format(d["device_name"]),
                "Board ID     {}".format(d["board"]),
                "Build        {}".format(d["build"]),
                "iOS          {}".format(d["ios_version"]),
                "Catalog      {}".format(
                    (info.get("status", "?").replace("_", " ")
                     + (", released " + info["released"] if info.get("released") else ""))
                    if info else "not in catalog"),
                "Screen       {}x{} native   RAM {} MB (hardware)".format(
                    *dev.get("screen", ("?", "?")), dev.get("ram_mb", "?")),
                "SoC          {}".format(dev.get("soc", "?")),
                "QEMU -M      {}".format(dev.get("qemu_machine", "?")),
                "Needs root   {}".format("Yes" if dev.get("needs_sudo") else "No"),
                "Bootrom      {}".format(
                    ("Bundled (" + next(iter(sorted(d["path"].glob("bootrom_*")))).name + ")")
                    if dev.get("needs_bootrom") and any(d["path"].glob("bootrom_*"))
                    else "Required (not bundled; set BOOTROM)" if dev.get("needs_bootrom")
                    else "Not required"),
                "Status       {}".format(pid_str),
                "Path         {}".format(d["path"]),
            ]
            changed = {k: v for k, v in prefs.items()
                       if k != "name" and v != DEFAULT_PREFS[k]}
            if changed:
                lines += ["", "── Preferences ───────────────────────────"]
                for k, v in changed.items():
                    lines.append("  {:<20} {}".format(k, v))
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
  BOOTROM  bootrom dump path       (only for devices without a bundled bootrom)

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
    ap.add_argument("--downloads", default=None,
                    help="Folder for auto-downloaded IPSWs  (default: saved setting, "
                         "else your Downloads folder)")
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
    n_builds = apply_catalog(catalog)
    if n_builds:
        print("[info] {} builds loaded from {}".format(n_builds, catalog))

    if not base.exists():
        print("[info] Base directory {!r} does not exist yet; "
              "it will be populated when the first device is created.".format(
                  str(base)))
    if not catalog.exists():
        print("[warn] Catalog not found at {!r}; using the built-in build list "
              "(browse for the catalog in the Create Device dialog to get every "
              "build).".format(str(catalog)))

    download = Path(os.path.expanduser(
        args.downloads or cfg.get("download_dir") or str(default_download_dir())))
    App(base, catalog, prefix, download).mainloop()


if __name__ == "__main__":
    main()
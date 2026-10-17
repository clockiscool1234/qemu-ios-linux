#!/usr/bin/env python3
"""
touchPanel.py -- on-screen device panel for the qemu-ios machines.

A small Tk window with the device's hardware buttons (Power, Home, Volume +/-) and a screen you can touch.
It talks to a running QEMU over QMP (the machine-readable monitor), so it replaces the SDL window's single
mouse pointer with real multi-touch events:

  * the screen is polled with QMP `screendump` (PPM) and drawn in the window;
  * a mouse drag becomes a finger (`input-send-event` "mtt" begin/update/end, the same multi-touch path
    the machines use for host touch), Ctrl+drag adds a mirrored second finger (pinch about the centre),
    Shift+drag a second finger beside the first (two-finger scroll);
  * the buttons send the same key events as the SDL window's P / H / - / = keys.  Press and hold are
    real: hold Power for slide-to-power-off, tap it to lock or wake.

Usage (QEMU started with `-qmp unix:/tmp/dev.sock,server,nowait`; manageFirm.py does this for you):
    python3 tools/touchPanel.py --qmp /tmp/dev.sock
    python3 tools/touchPanel.py --selftest            # headless checks, no QEMU or display needed

Closing the panel does not stop QEMU; buttons held at that moment are released.

The pane beside the screen ("View > Serial log") shows the guest's serial output, the verbose kernel / boot log.
manageFirm.py has the --exec-qemu wrapper tee the serial port into a file (LT_SERIAL_LOG) and passes it here as
--serial-log; the panel tails the file and fixes the line breaks (iOS's \r\n / \n\r\n / \r\r\n all become one),
strips escape sequences, keeps the last 5000 lines, and can Clear or Save them.  Without --serial-log the pane
is off.

The "Phone..." button opens a second window that drives the fake cellular modem and the battery over QMP
`qom-set` (no guest software involved, the guest just sees a baseband / PMU that changed):

  * Call     fake incoming call from any number, then answer-from-the-far-end / hang up;
  * SMS      fake incoming text message from any number;
  * Network  carrier name + MCC-MNC, signal strength (dBm), "No service" (registered off), SIM removed;
  * Battery  charge level 0-100 %, charging auto/on/off and the USB cable.

The modem only exists where the machine has one: /machine/baseband-modem (an iPhone machine started with
baseband=on, e.g. `-M iPhone-4,baseband=on`; the iPhone 2G has it by default).  Without it the Call / SMS /
Network tabs are greyed out and say so; the Battery tab only needs the machine's battery-level property.

Optional: Pillow (with ImageTk) gives smooth fit-to-window scaling and 90-degree view rotation (an iPad's
landscape panel shows the portrait UI sideways).  Without it the screen is shown at 1:1, 1:2, 1:3 ... or 2:1.

Also: `--exec-qemu` is the launcher hook manageFirm.py uses to add a QMP socket (and optionally drop the SDL
window) to a bundle's run.sh without editing it; see exec_qemu().
"""
from __future__ import annotations

import argparse
import codecs
import json
import os
import queue
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import zlib

ABS_MAX = 0x7FFF                      # QEMU's absolute input range
PINCH_OFFSET_PX = 48                  # Shift+drag: second finger this far to the right of the first
KEYS = {                              # button -> QEMU qcode; the machines' own key map (P H - =)
    "power": "p", "home": "h", "voldown": "minus", "volup": "equal",
}


# ---------------------------------------------------------------------------------------------
# pure helpers (covered by --selftest)
# ---------------------------------------------------------------------------------------------

def key_event(qcode, down):
    return {"type": "key", "data": {"down": bool(down), "key": {"type": "qcode", "data": qcode}}}


def mtt_event(kind, slot, tracking_id, axis, value):
    return {"type": "mtt", "data": {"type": kind, "slot": int(slot), "tracking-id": int(tracking_id),
                                    "axis": axis, "value": int(value)}}


def touch_events(phase, fingers):
    """One input-send-event batch for every finger at once: each finger's position is latched with two
    `data` events, then the phase (begin / update / end / cancel) commits them.
    fingers: [(slot, tracking_id, x, y)] in QEMU absolute 0..0x7fff."""
    events = []
    for slot, tid, x, y in fingers:
        events.append(mtt_event("data", slot, tid, "x", x))
        events.append(mtt_event("data", slot, tid, "y", y))
    for slot, tid, x, y in fingers:
        events.append(mtt_event(phase, slot, tid, "x", x))
    return events


def view_to_source(u, v, rot):
    """A point of the displayed picture (0..1, y down), shown rotated `rot` degrees clockwise, -> the
    same point of the guest's screen.  The machines' touch is in the screen's own coordinates."""
    if rot == 90:
        return v, 1.0 - u
    if rot == 180:
        return 1.0 - u, 1.0 - v
    if rot == 270:
        return 1.0 - v, u
    return u, v


def frac_to_abs(f):
    return max(0, min(ABS_MAX, int(round(f * ABS_MAX))))


def clamp01(f):
    return 0.0 if f < 0 else 1.0 if f > 1 else f


def gesture_fingers(mode, u, v, disp_w):
    """The fingers (displayed-picture fractions) one pointer position stands for."""
    if mode == "pinch":
        return [(u, v), (1.0 - u, 1.0 - v)]
    if mode == "pan2":
        return [(u, v), (clamp01(u + PINCH_OFFSET_PX / max(1, disp_w)), v)]
    return [(u, v)]


def parse_ppm(data):
    """-> (width, height, pixel offset) of a binary P6 PPM (QEMU's screendump).  ValueError if it is not one."""
    n, pos, toks = len(data), 0, []
    if data[:2] != b"P6":
        raise ValueError("not a P6 PPM")
    pos = 2
    while len(toks) < 3:
        while pos < n and data[pos] in b" \t\r\n":
            pos += 1
        if pos < n and data[pos:pos + 1] == b"#":
            while pos < n and data[pos] not in b"\r\n":
                pos += 1
            continue
        start = pos
        while pos < n and data[pos] not in b" \t\r\n":
            pos += 1
        if start == pos:
            raise ValueError("truncated PPM header")
        toks.append(int(data[start:pos]))
    w, h, maxval = toks
    pos += 1  # the single whitespace after maxval
    if w <= 0 or h <= 0 or maxval != 255 or n - pos < w * h * 3:
        raise ValueError("unsupported or truncated PPM")
    return w, h, pos


def scale_to_ratio(s):
    """Tk-only scaling: the nearest integer ratio not larger than s -> (zoom, subsample)."""
    if s >= 1:
        return int(s), 1
    sub = 1
    while 1.0 / sub > s and sub < 16:
        sub += 1
    return 1, sub


def build_qemu_args(args, qmp_sock=None, hide_display=False, serial_log=None):
    """The launcher hook's argument edit: add our own QMP socket, and optionally replace the display with
    `-display none` (the panel is the screen).  Existing monitors and sockets are left alone.

    With `serial_log`, the usual `-serial mon:stdio` is rebuilt as the same thing spelled out (a muxed stdio
    chardev carrying the serial port and the monitor) plus `logfile=PATH`, so everything the guest writes to its
    serial port is also appended to that file; the panel's serial pane tails it.  Anything else on the
    command line (another -serial, no -serial at all) is left alone and the pane just stays empty."""
    out = list(args)
    if hide_display:
        kept, i = [], 0
        while i < len(out):
            if out[i] in ("-display", "--display"):
                i += 2
                continue
            kept.append(out[i])
            i += 1
        out = kept + ["-display", "none"]
    if serial_log:
        kept, i = [], 0
        while i < len(out):
            if out[i] in ("-serial", "--serial") and i + 1 < len(out) and out[i + 1] == "mon:stdio":
                kept += ["-chardev", "stdio,id=ltserial,mux=on,logfile=%s" % serial_log.replace(",", ",,"),
                         "-serial", "chardev:ltserial", "-mon", "chardev=ltserial,mode=readline"]
                i += 2
                continue
            kept.append(out[i])
            i += 1
        out = kept
    if qmp_sock:
        out += ["-qmp", "unix:%s,server,nowait" % qmp_sock.replace(",", ",,")]
    return out


def exec_qemu(argv):
    """`--exec-qemu ARGS...`: replace this process with the real QEMU (LT_REAL_QEMU), same arguments plus the
    edits above (LT_QMP_SOCK, LT_HIDE_DISPLAY=1, LT_SERIAL_LOG).  A bundle's run.sh runs `$QEMU -M ...`;
    manageFirm.py points QEMU at a one-line shell wrapper that runs this."""
    real = os.environ.get("LT_REAL_QEMU")
    if not real:
        sys.exit("touchPanel: --exec-qemu needs LT_REAL_QEMU")
    args = build_qemu_args(argv, os.environ.get("LT_QMP_SOCK"), os.environ.get("LT_HIDE_DISPLAY") == "1",
                           os.environ.get("LT_SERIAL_LOG"))
    os.execv(real, [real] + args)


# ---- serial log (the pane beside the screen) ---------------------------------------------------------
SERIAL_MAX_LINES = 5000                                   # lines kept in the pane
SERIAL_PARTIAL_FLUSH_S = 0.4                              # show an unfinished line (a prompt) after this long
_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_]|\][^\x07\x1b]*(?:\x07|\x1b\\)?)")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")        # control characters except tab (\n and \r are split on)
_EOL_RE = re.compile(r"[\r\n]+")


class SerialCleaner:
    """Turns the raw bytes of a guest's serial port into clean text lines.

    iOS writes \\r\\n, \\n\\r\\n or a bare \\r depending on the code path, and a terminal that converts each of
    those separately shows doubled newlines.  Here every run of \\r and \\n is one line break, escape sequences
    and other control characters are dropped, and invalid UTF-8 is replaced instead of raising.  Bytes may arrive
    in any chunking: feed() returns only the lines completed so far, flush() hands back the unfinished one."""

    def __init__(self):
        self._dec = codecs.getincrementaldecoder("utf-8")("replace")
        self._buf = ""

    @staticmethod
    def clean(text):
        return _CTRL_RE.sub("", _ANSI_RE.sub("", text)).rstrip()

    def feed(self, data):
        self._buf += self._dec.decode(data)
        parts = _EOL_RE.split(self._buf)
        self._buf = parts.pop()                           # "" when the chunk ended on a line break
        out = []
        for p in parts:
            p = self.clean(p)
            if p:
                out.append(p)
        return out

    def flush(self):
        line, self._buf = self.clean(self._buf), ""
        return [line] if line else []


class SerialTail(threading.Thread):
    """Follows the serial log file QEMU writes (see build_qemu_args) and calls on_lines(list_of_str) with each
    batch of cleaned lines.  The file may not exist yet when the panel starts; it is waited for."""

    def __init__(self, path, on_lines):
        super().__init__(name="serial-tail", daemon=True)
        self.path, self.on_lines = path, on_lines
        self.stop_ev = threading.Event()

    def run(self):
        cleaner = SerialCleaner()
        f = None
        idle_since = None
        try:
            while not self.stop_ev.is_set():
                if f is None:
                    try:
                        f = open(self.path, "rb")
                    except OSError:
                        self.stop_ev.wait(0.2)
                        continue
                data = f.read(65536)
                if data:
                    idle_since = None
                    lines = cleaner.feed(data)
                    if lines:
                        self.on_lines(lines)
                    continue
                if idle_since is None:
                    idle_since = time.monotonic()
                elif time.monotonic() - idle_since >= SERIAL_PARTIAL_FLUSH_S:
                    lines = cleaner.flush()
                    if lines:
                        self.on_lines(lines)
                    idle_since = None
                self.stop_ev.wait(0.1)
        finally:
            if f is not None:
                f.close()


# ---- phone controls (QOM paths and value rules mirror hw/misc/ios_baseband.c) ----------------------
MACHINE_PATH = "/machine"
MODEM_PATH = "/machine/baseband-modem"
SIGNAL_MIN_DBM, SIGNAL_MAX_DBM = -113, -51
SIGNAL_PRESETS = (("5 bars", -59), ("3 bars", -95), ("1 bar", -109))      # 5 and 3 bars verified on N90 4.2.1
CARRIERS = (                                                                 # name, MCC+MNC (typical values)
    ("Test Network", "00101"), ("AT&T", "310410"), ("T-Mobile", "310260"), ("Verizon", "311480"),
    ("Vodafone UK", "23415"), ("Globe", "51502"), ("Smart", "51503"),
)


def valid_phone_number(n):
    """The modem's sender rule: 1-20 digits, optionally after a leading '+'."""
    digits = n[1:] if n.startswith("+") else n
    return 1 <= len(digits) <= 20 and digits.isdigit() and len(n) <= 31


def sms_value(number, text):
    """The incoming-sms property's value, "<number>|<text>".  ValueError says what is wrong."""
    number = number.strip()
    if not valid_phone_number(number):
        raise ValueError("number must be 1-20 digits, optionally starting with +")
    if not text.strip():
        raise ValueError("the message is empty")
    return "%s|%s" % (number, text)


def valid_plmn(s):
    return s.isdigit() and len(s) in (5, 6)


def valid_carrier(s):
    return 1 <= len(s) <= 32 and s.isprintable() and '"' not in s


def qom_set_args(path, prop, value):
    return {"path": path, "property": prop, "value": value}


def charging_args(machine_props, mode):
    """(property, value) that sets 'auto' / 'on' / 'off' charging on this machine: the iPod and iPhone machines
    have battery-charging (a string); the A4 machines only usb-charger (a bool, "off" takes a replug)."""
    if "battery-charging" in machine_props:
        return "battery-charging", mode
    if "usb-charger" in machine_props:
        return "usb-charger", mode != "off"
    return None


def phone_caps(machine_props):
    """What this machine offers the Phone window, from the names qom-list shows under /machine."""
    names = set(machine_props)
    return {"modem": "baseband-modem" in names, "battery": "battery-level" in names,
            "charging": charging_args(names, "auto") is not None, "usb": "usb-attached" in names,
            "machine_props": names}


# ---------------------------------------------------------------------------------------------
# QMP client
# ---------------------------------------------------------------------------------------------

class QMPError(Exception):
    pass


class _Pending:
    __slots__ = ("ev", "msg")

    def __init__(self):
        self.ev = threading.Event()
        self.msg = None


class QMPClient:
    """Minimal threaded QMP client: execute() waits for its reply, send_nowait() does not.  Events are
    handed to on_event(name); on_close() runs once when the socket ends; on_error(cmd, text) reports the
    failure of a send_nowait() command."""

    def __init__(self, path, on_event=None, on_close=None, on_error=None):
        self.path = path
        self.on_event, self.on_close, self.on_error = on_event, on_close, on_error
        self._sock = None
        self._wlock = threading.Lock()
        self._plock = threading.Lock()
        self._pending = {}
        self._async = {}
        self._next = 1
        self.closed = False
        self._close_called = False

    def connect(self, timeout=60.0, stop=None):
        """Wait for the socket (QEMU may still be starting), negotiate capabilities, start the reader."""
        deadline = time.monotonic() + timeout
        last = None
        while True:
            if stop is not None and stop.is_set():
                raise QMPError("cancelled")
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2.0)
            try:
                s.connect(self.path)
                break
            except OSError as e:
                last = e
                s.close()
                if time.monotonic() > deadline:
                    raise QMPError("cannot connect to %s: %s" % (self.path, last))
                time.sleep(0.25)
        self._sock = s
        self._rfile = s.makefile("rb")
        try:
            greeting = self._read_msg()
            if "QMP" not in greeting:
                raise QMPError("not a QMP socket (greeting: %r)" % (greeting,))
            self._write({"execute": "qmp_capabilities"})
            while True:
                msg = self._read_msg()
                if "return" in msg:
                    break
                if "error" in msg:
                    raise QMPError(msg["error"].get("desc", "qmp_capabilities failed"))
        except (OSError, ValueError) as e:
            s.close()
            raise QMPError("QMP handshake failed: %s" % e)
        s.settimeout(None)
        threading.Thread(target=self._reader, name="qmp-reader", daemon=True).start()

    def _read_msg(self):
        line = self._rfile.readline()
        if not line:
            raise QMPError("connection closed")
        return json.loads(line.decode("utf-8", "replace"))

    def _write(self, obj):
        data = (json.dumps(obj) + "\r\n").encode()
        with self._wlock:
            self._sock.sendall(data)

    def _reader(self):
        try:
            while True:
                line = self._rfile.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode("utf-8", "replace"))
                except ValueError:
                    continue
                if "event" in msg:
                    if self.on_event:
                        self.on_event(msg["event"])
                    continue
                rid = msg.get("id")
                with self._plock:
                    p = self._pending.pop(rid, None)
                    cmd = self._async.pop(rid, None)
                if p is not None:
                    p.msg = msg
                    p.ev.set()
                elif cmd is not None and "error" in msg and self.on_error:
                    self.on_error(cmd, msg["error"].get("desc", str(msg["error"])))
        except (OSError, ValueError):
            pass
        self._shutdown()

    def _shutdown(self):
        self.closed = True
        with self._plock:
            waiting = list(self._pending.values())
            self._pending.clear()
        for p in waiting:
            p.ev.set()  # msg stays None: "connection closed"
        if not self._close_called:
            self._close_called = True
            if self.on_close:
                self.on_close()

    def _request(self, cmd, args):
        if self.closed or self._sock is None:
            raise QMPError("not connected")
        with self._plock:
            rid = self._next
            self._next += 1
        msg = {"execute": cmd, "id": rid}
        if args:
            msg["arguments"] = args
        return rid, msg

    def execute(self, cmd, args=None, timeout=5.0):
        rid, msg = self._request(cmd, args)
        p = _Pending()
        with self._plock:
            self._pending[rid] = p
        try:
            self._write(msg)
        except OSError as e:
            with self._plock:
                self._pending.pop(rid, None)
            raise QMPError("send failed: %s" % e)
        if not p.ev.wait(timeout):
            with self._plock:
                self._pending.pop(rid, None)
            raise QMPError("%s timed out" % cmd)
        if p.msg is None:
            raise QMPError("connection closed")
        if "error" in p.msg:
            raise QMPError(p.msg["error"].get("desc", str(p.msg["error"])))
        return p.msg.get("return")

    def send_nowait(self, cmd, args=None):
        rid, msg = self._request(cmd, args)
        with self._plock:
            self._async[rid] = cmd
        try:
            self._write(msg)
        except OSError as e:
            with self._plock:
                self._async.pop(rid, None)
            raise QMPError("send failed: %s" % e)

    def input_events(self, events):
        self.send_nowait("input-send-event", {"events": events})

    def qom_set(self, path, prop, value, timeout=5.0):
        return self.execute("qom-set", qom_set_args(path, prop, value), timeout=timeout)

    def qom_get(self, path, prop, timeout=5.0):
        return self.execute("qom-get", {"path": path, "property": prop}, timeout=timeout)

    def qom_names(self, path, timeout=5.0):
        """Property and child names under a QOM path (empty when the path does not exist)."""
        try:
            return [e["name"] for e in self.execute("qom-list", {"path": path}, timeout=timeout) or []]
        except QMPError as e:
            if "not found" in str(e).lower():       # QEMU: "Device '...' not found" / "Property ... not found"
                return []
            raise

    def close(self):
        self.closed = True
        try:
            if self._sock:
                self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------------------------
# frame grabber
# ---------------------------------------------------------------------------------------------

class FrameGrabber(threading.Thread):
    """Polls `screendump` and hands every *changed* frame to on_frame(w, h, data, pixel_offset).  Polls at
    `fps` while the picture is changing or you are touching it, and at 4 Hz when it has been still."""

    def __init__(self, qmp, on_frame, fps=15.0, on_error=None):
        super().__init__(name="frame-grabber", daemon=True)
        self.qmp, self.on_frame, self.on_error = qmp, on_frame, on_error
        self.fps = max(1.0, float(fps))
        self.stop_ev = threading.Event()
        self._active_until = 0.0
        self.frames = 0

    def kick(self, seconds=1.5):
        self._active_until = max(self._active_until, time.monotonic() + seconds)

    def run(self):
        shm = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
        tmp = tempfile.mkdtemp(prefix="lt-panel-", dir=shm)
        path = os.path.join(tmp, "frame.ppm")
        last_crc, errors = None, 0
        try:
            while not self.stop_ev.is_set() and not self.qmp.closed:
                t0 = time.monotonic()
                try:
                    self.qmp.execute("screendump", {"filename": path, "format": "ppm"}, timeout=5.0)
                    with open(path, "rb") as f:
                        data = f.read()
                    w, h, off = parse_ppm(data)
                    crc = zlib.crc32(data[off:])
                    errors = 0
                    if crc != last_crc:
                        last_crc = crc
                        self.kick(1.0)
                        self.frames += 1
                        self.on_frame(w, h, data, off)
                except (QMPError, OSError, ValueError) as e:
                    if self.qmp.closed:
                        break
                    errors += 1
                    if errors in (1, 10) and self.on_error:
                        self.on_error("screen: %s" % e)
                    time.sleep(min(2.0, 0.2 * errors))
                    continue
                active = time.monotonic() < self._active_until
                period = 1.0 / self.fps if active else 0.25
                self.stop_ev.wait(max(0.0, period - (time.monotonic() - t0)))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------------------------
# the window
# ---------------------------------------------------------------------------------------------

def _gui_main(args, run=True):
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    try:
        if os.environ.get("TOUCHPANEL_NO_PIL"):
            raise ImportError("Pillow disabled by TOUCHPANEL_NO_PIL")
        from PIL import Image, ImageTk
        resample = getattr(getattr(Image, "Resampling", Image), "BILINEAR")
        transpose = getattr(Image, "Transpose", Image)
        have_pil = True
    except Exception:
        Image = ImageTk = None
        have_pil = False

    class Panel(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(args.title or "Device panel")
            self.resizable(True, True)
            self.protocol("WM_DELETE_WINDOW", self._quit)
            self._rot = args.rotate
            self._scale_mode = args.scale            # "fit" or a float
            self._frame = None                       # latest (w, h, data, off) from the grabber
            self._frame_lock = threading.Lock()
            self._frame_serial = 0
            self._shown_serial = 0
            self._status_q = queue.Queue()
            self._connected = False
            self._first_frame = True
            self._photo = None
            self._img_item = None
            self._rect = (0, 0, 1, 1)                # displayed picture: x0, y0, w, h in canvas pixels
            self._held = {}                          # qcode -> True while a button is down
            self._release_after = {}                 # qcode -> after id (X auto-repeat debounce)
            self._fingers = []                       # active (slot, tracking_id)
            self._mode = "single"
            self._last_uv = (0.5, 0.5)
            self._motion_after = None
            self._tid = 1
            self._fps_n, self._fps_t, self._fps = 0, time.monotonic(), 0.0
            self._closing = False
            self._phone_win = None                   # the Phone... window (Toplevel) while open
            self._phone = None                       # phone_caps() of this machine, once probed
            self._phone_ui = {}
            self._callstate_busy = False
            self._serial_q = queue.Queue()           # cleaned serial lines from the tail thread
            self._serial_tail = None
            self._serial_visible = False
            self.qmp = QMPClient(args.qmp, on_event=self._on_event, on_close=self._on_qmp_close,
                                 on_error=lambda c, t: self._status_q.put(("warn", "%s: %s" % (c, t))))
            self.grabber = None
            self._build()
            self._set_status("Waiting for QEMU…")
            threading.Thread(target=self._connect, daemon=True).start()
            self.after(15, self._pump)

        # -- layout ---------------------------------------------------------
        def _build(self):
            try:
                ttk.Style(self).theme_use("clam")
            except Exception:
                pass
            menubar = tk.Menu(self)
            view = tk.Menu(menubar, tearoff=0)
            self._scale_var = tk.StringVar(value="fit" if self._scale_mode == "fit" else str(self._scale_mode))
            sm = tk.Menu(view, tearoff=0)
            for label, val in (("Fit window", "fit"), ("100%", "1.0"), ("75%", "0.75"), ("50%", "0.5"),
                               ("33%", "0.3333")):
                sm.add_radiobutton(label=label, value=val, variable=self._scale_var, command=self._scale_changed)
            view.add_cascade(label="Scale", menu=sm)
            self._rot_var = tk.IntVar(value=self._rot)
            rm = tk.Menu(view, tearoff=0)
            for label, val in (("0°", 0), ("90° clockwise", 90), ("180°", 180), ("90° counter-clockwise", 270)):
                rm.add_radiobutton(label=label, value=val, variable=self._rot_var, command=self._rot_changed,
                                   state="normal" if have_pil else "disabled")
            view.add_cascade(label="Rotate view" + ("" if have_pil else " (needs Pillow)"), menu=rm)
            self._top_var = tk.BooleanVar(value=False)
            view.add_checkbutton(label="Always on top", variable=self._top_var,
                                 command=lambda: self.attributes("-topmost", self._top_var.get()))
            self._serial_var = tk.BooleanVar(value=bool(args.serial_log))
            view.add_checkbutton(label="Serial log", variable=self._serial_var, command=self._serial_toggle,
                                 state="normal" if args.serial_log else "disabled")
            menubar.add_cascade(label="View", menu=view)
            self.config(menu=menubar)

            body = ttk.Frame(self, padding=4)
            body.pack(fill="both", expand=True)
            self._body = body
            side = ttk.Frame(body)
            side.pack(side="right", fill="y", padx=(6, 0))
            self._serial_frame = ttk.Frame(body)     # packed beside the screen by _serial_toggle()
            self._build_serial(self._serial_frame)
            self.canvas = tk.Canvas(body, width=360, height=480, bg="#101010", highlightthickness=0,
                                    cursor="circle")
            self.canvas.pack(side="left", fill="both", expand=True)
            if args.serial_log:
                self._serial_toggle()
            self._msg_item = self.canvas.create_text(180, 240, fill="#888888", text="", font=("", 11),
                                                     justify="center")

            def hw_button(text, name, tip):
                b = ttk.Button(side, text=text, width=8)
                b.pack(fill="x", pady=3)
                b.bind("<ButtonPress-1>", lambda e, n=name: self._button(n, True))
                b.bind("<ButtonRelease-1>", lambda e, n=name: self._button(n, False))
                return b
            hw_button("Power", "power", "")
            hw_button("Home", "home", "")
            ttk.Separator(side).pack(fill="x", pady=6)
            hw_button("Vol +", "volup", "")
            hw_button("Vol −", "voldown", "")
            ttk.Separator(side).pack(fill="x", pady=6)
            ttk.Button(side, text="Screenshot", width=8, command=self._screenshot).pack(fill="x", pady=3)
            ttk.Button(side, text="Phone…", width=8, command=self._open_phone).pack(fill="x", pady=3)
            self._status = ttk.Label(self, text="", anchor="w", padding=(6, 2), foreground="#555555")
            self._status.pack(fill="x", side="bottom")

            self.canvas.bind("<Configure>", lambda e: self._redraw())
            self.canvas.bind("<ButtonPress-1>", self._touch_down)
            self.canvas.bind("<B1-Motion>", self._touch_move)
            self.canvas.bind("<ButtonRelease-1>", self._touch_up)
            # keyboard: the SDL window's keys, with X auto-repeat (release+press pairs) debounced
            for keysym, name in (("p", "power"), ("h", "home"), ("minus", "voldown"), ("equal", "volup"),
                                 ("plus", "volup"), ("KP_Subtract", "voldown"), ("KP_Add", "volup")):
                self.bind("<KeyPress-%s>" % keysym, lambda e, n=name: self._key(n, True))
                self.bind("<KeyRelease-%s>" % keysym, lambda e, n=name: self._key(n, False))

        # -- serial log pane ---------------------------------------------------
        def _build_serial(self, frame):
            bar = ttk.Frame(frame)
            bar.pack(fill="x", side="top")
            ttk.Label(bar, text="Serial log").pack(side="left")
            ttk.Button(bar, text="Save…", width=6, command=self._serial_save).pack(side="right")
            ttk.Button(bar, text="Clear", width=6, command=self._serial_clear).pack(side="right", padx=(0, 4))
            self._serial_follow = tk.BooleanVar(value=True)
            ttk.Checkbutton(bar, text="Follow", variable=self._serial_follow).pack(side="right", padx=(0, 6))
            inner = ttk.Frame(frame)
            inner.pack(fill="both", expand=True, pady=(4, 0))
            import tkinter.font as tkfont
            self._serial_font = tkfont.nametofont("TkFixedFont").copy()
            self._serial_font.configure(size=9)
            self._serial_text = tk.Text(inner, width=56, height=10, wrap="none", state="disabled",
                                        bg="#101010", fg="#d0d0d0", insertbackground="#d0d0d0",
                                        font=self._serial_font, highlightthickness=0, takefocus=0, undo=False)
            ys = ttk.Scrollbar(inner, orient="vertical", command=self._serial_text.yview)
            xs = ttk.Scrollbar(inner, orient="horizontal", command=self._serial_text.xview)
            self._serial_text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
            ys.pack(side="right", fill="y")
            xs.pack(side="bottom", fill="x")
            self._serial_text.pack(side="left", fill="both", expand=True)
            # The panel's P / H / - / = keys are bound on the window; do not fire them (a power press!) while
            # the log has the focus.  Ctrl combinations (copy, select all) still work.
            nav = ("Up", "Down", "Left", "Right", "Prior", "Next", "Home", "End")
            self._serial_text.bind("<Key>", lambda e: None if (e.state & 0x4 or e.keysym in nav) else "break")
            self._serial_text.bind("<Button-1>", lambda e: self._serial_text.focus_set())

        def _serial_toggle(self):
            want = self._serial_var.get()
            if want and not self._serial_visible:
                self._serial_frame.pack(side="right", fill="both", padx=(6, 0), before=self.canvas)
                self._serial_visible = True
                if self._serial_tail is None and args.serial_log:
                    self._serial_tail = SerialTail(args.serial_log, self._serial_q.put)
                    self._serial_tail.start()
            elif not want and self._serial_visible:
                self._serial_frame.pack_forget()
                self._serial_visible = False

        def _serial_append(self, lines):
            t = self._serial_text
            t.configure(state="normal")
            t.insert("end", "\n".join(lines) + "\n")
            over = int(t.index("end-1c").split(".")[0]) - 1 - SERIAL_MAX_LINES
            if over > 0:
                t.delete("1.0", "%d.0" % (over + 1))
            t.configure(state="disabled")
            if self._serial_follow.get():
                t.see("end")

        def _serial_clear(self):
            self._serial_text.configure(state="normal")
            self._serial_text.delete("1.0", "end")
            self._serial_text.configure(state="disabled")

        def _serial_save(self):
            path = filedialog.asksaveasfilename(parent=self, title="Save serial log", defaultextension=".log",
                                                filetypes=[("Log", "*.log"), ("Text", "*.txt"), ("All", "*.*")])
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._serial_text.get("1.0", "end-1c") + "\n")
                self._set_status("Serial log saved to %s" % path)
            except OSError as ex:
                messagebox.showerror("Save serial log", str(ex), parent=self)

        # -- status / lifecycle ----------------------------------------------
        def _set_status(self, text):
            self._status_text = text
            self._refresh_status()
            note = self._phone_ui.get("note")
            if note is not None and self._phone_win is not None:
                note.configure(text=text)

        def _refresh_status(self):
            extra = ""
            if self._frame is not None:
                w, h = self._frame[0], self._frame[1]
                extra = "  ·  %dx%d  ·  %.0f fps" % (w, h, self._fps)
            self._status.configure(text=self._status_text + extra)

        def _on_event(self, name):
            if name in ("SHUTDOWN", "POWERDOWN"):
                self._status_q.put(("info", "Guest %s" % name.lower()))

        def _on_qmp_close(self):
            self._status_q.put(("closed", "QEMU exited"))

        def _connect(self):
            try:
                self.qmp.connect(timeout=args.connect_timeout, stop=None)
            except QMPError as e:
                self._status_q.put(("fatal", str(e)))
                return
            self._status_q.put(("connected", "Connected"))
            self.grabber = FrameGrabber(self.qmp, self._on_frame, fps=args.fps,
                                        on_error=lambda t: self._status_q.put(("warn", t)))
            self.grabber.start()

        def _on_frame(self, w, h, data, off):
            with self._frame_lock:
                self._frame = (w, h, data, off)
                self._frame_serial += 1

        def _pump(self):
            """Main-thread poll: status messages and the newest frame from the worker threads."""
            if self._closing:
                return
            try:
                while True:
                    kind, text = self._status_q.get_nowait()
                    if kind == "connected":
                        self._connected = True
                        self._set_status(text)
                        self.canvas.itemconfigure(self._msg_item, text="Waiting for the first frame…")
                    elif kind == "closed":
                        self._connected = False
                        self._set_status(text)
                        if not args.keep_open:
                            self.after(1500, self._quit)
                    elif kind == "fatal":
                        self._set_status(text)
                        self.canvas.itemconfigure(self._msg_item, text=text)
                    elif kind == "probe":
                        self._apply_probe(text)           # `text` is the payload here
                    elif kind == "callstate":
                        lab = self._phone_ui.get("callstate")
                        if lab is not None and self._phone_win is not None:
                            lab.configure(text="Call state: %s" % text)
                    else:
                        self._set_status(text)
            except queue.Empty:
                pass
            lines, n = [], 0
            try:
                while n < 20:                                  # batches; keeps one pump tick short
                    lines += self._serial_q.get_nowait()
                    n += 1
            except queue.Empty:
                pass
            if lines:
                self._serial_append(lines)
            with self._frame_lock:
                serial = self._frame_serial
            if serial != self._shown_serial:
                self._shown_serial = serial
                self._redraw()
                self._fps_n += 1
            now = time.monotonic()
            if now - self._fps_t >= 1.0:
                self._fps = self._fps_n / (now - self._fps_t)
                self._fps_n, self._fps_t = 0, now
                if self._connected:
                    self._refresh_status()
            self.after(15, self._pump)

        # -- drawing ---------------------------------------------------------
        def _src_size(self, fw, fh):
            return (fh, fw) if self._rot in (90, 270) else (fw, fh)

        def _target_scale(self, rw, rh, cw, ch):
            if self._scale_mode == "fit":
                s = min(cw / rw, ch / rh)
                return max(0.05, min(s, 4.0))
            return float(self._scale_mode)

        def _redraw(self):
            with self._frame_lock:
                fr = self._frame
            if fr is None:
                return
            w, h, data, off = fr
            rw, rh = self._src_size(w, h)
            cw, ch = max(1, self.canvas.winfo_width()), max(1, self.canvas.winfo_height())
            if self._first_frame:
                self._first_frame = False
                sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
                extra = self._serial_frame.winfo_reqwidth() + 6 if self._serial_visible else 0
                s0 = min(1.0, 0.85 * sh / rh, 0.85 * (sw - 140 - extra) / rw)
                if not have_pil:
                    z, sub = scale_to_ratio(s0)
                    s0 = z / sub
                if self._scale_mode != "fit":
                    s0 = float(self._scale_mode)
                cw, ch = max(120, int(rw * s0)), max(120, int(rh * s0))
                self.canvas.configure(width=cw, height=ch)
                self.canvas.itemconfigure(self._msg_item, text="")
                self.update_idletasks()
                cw, ch = max(1, self.canvas.winfo_width()), max(1, self.canvas.winfo_height())
            s = self._target_scale(rw, rh, cw, ch)
            if have_pil:
                im = Image.frombuffer("RGB", (w, h), data[off:off + w * h * 3], "raw", "RGB", 0, 1)
                if self._rot:
                    im = im.transpose({90: transpose.ROTATE_270, 180: transpose.ROTATE_180,
                                       270: transpose.ROTATE_90}[self._rot])
                dw, dh = max(1, int(round(rw * s))), max(1, int(round(rh * s)))
                if (dw, dh) != (rw, rh):
                    im = im.resize((dw, dh), resample)
                photo = ImageTk.PhotoImage(im)
            else:
                photo = tk.PhotoImage(data=data, format="ppm")
                z, sub = scale_to_ratio(s)
                if sub > 1:
                    photo = photo.subsample(sub)
                elif z > 1:
                    photo = photo.zoom(z)
                dw, dh = photo.width(), photo.height()
            x0, y0 = (cw - dw) // 2, (ch - dh) // 2
            self._photo = photo  # keep a reference: Tk does not
            if self._img_item is None:
                self._img_item = self.canvas.create_image(x0, y0, image=photo, anchor="nw")
                self.canvas.tag_lower(self._img_item)
            else:
                self.canvas.itemconfigure(self._img_item, image=photo)
                self.canvas.coords(self._img_item, x0, y0)
            self._rect = (x0, y0, dw, dh)

        def _scale_changed(self):
            v = self._scale_var.get()
            self._scale_mode = "fit" if v == "fit" else float(v)
            self._redraw()

        def _rot_changed(self):
            self._rot = self._rot_var.get()
            self._first_frame = False
            self._redraw()

        # -- hardware buttons ------------------------------------------------
        def _send_key(self, qcode, down):
            try:
                self.qmp.input_events([key_event(qcode, down)])
                if self.grabber:
                    self.grabber.kick()
            except QMPError as e:
                self._set_status("Not sent: %s" % e)

        def _button(self, name, down):
            qcode = KEYS[name]
            if down == bool(self._held.get(qcode)):
                return
            self._held[qcode] = down
            if not down:
                self._held.pop(qcode, None)
            self._send_key(qcode, down)

        def _key(self, name, down):
            qcode = KEYS[name]
            pending = self._release_after.pop(qcode, None)
            if pending is not None:
                self.after_cancel(pending)
            if down:
                if not self._held.get(qcode):
                    self._button(name, True)
            elif self._held.get(qcode):
                self._release_after[qcode] = self.after(30, lambda: (self._release_after.pop(qcode, None),
                                                                     self._button(name, False)))

        # -- touch -----------------------------------------------------------
        def _uv(self, cx, cy):
            x0, y0, dw, dh = self._rect
            return clamp01((cx - x0) / max(1, dw)), clamp01((cy - y0) / max(1, dh))

        def _finger_abs(self, u, v):
            fx, fy = view_to_source(u, v, self._rot)
            return frac_to_abs(fx), frac_to_abs(fy)

        def _fingers_now(self):
            u, v = self._last_uv
            pts = gesture_fingers(self._mode, u, v, self._rect[2])
            return [(slot, tid, *self._finger_abs(pu, pv))
                    for (slot, tid), (pu, pv) in zip(self._fingers, pts)]

        def _draw_fingers(self):
            self.canvas.delete("finger")
            x0, y0, dw, dh = self._rect
            u, v = self._last_uv
            for pu, pv in gesture_fingers(self._mode, u, v, dw)[:len(self._fingers)]:
                cx, cy = x0 + pu * dw, y0 + pv * dh
                self.canvas.create_oval(cx - 14, cy - 14, cx + 14, cy + 14, outline="#ffffff", width=2,
                                        tags="finger")
                self.canvas.create_oval(cx - 3, cy - 3, cx + 3, cy + 3, fill="#ffffff", outline="", tags="finger")

        def _touch_down(self, e):
            x0, y0, dw, dh = self._rect
            if self._frame is None or not self._connected or not (x0 <= e.x < x0 + dw and y0 <= e.y < y0 + dh):
                return
            self.canvas.focus_set()
            self._mode = "pinch" if e.state & 0x4 else "pan2" if e.state & 0x1 else "single"
            self._last_uv = self._uv(e.x, e.y)
            n = 1 if self._mode == "single" else 2
            self._fingers = [(i, self._tid + i) for i in range(n)]
            self._tid += n
            self._send_touch("begin")
            self._draw_fingers()

        def _touch_move(self, e):
            if not self._fingers:
                return
            self._last_uv = self._uv(e.x, e.y)
            self._draw_fingers()
            if self._motion_after is None:      # coalesce to ~60 events/s
                self._motion_after = self.after(16, self._flush_motion)

        def _flush_motion(self):
            self._motion_after = None
            if self._fingers:
                self._send_touch("update")

        def _touch_up(self, e):
            if not self._fingers:
                return
            if self._motion_after is not None:
                self.after_cancel(self._motion_after)
                self._motion_after = None
            self._last_uv = self._uv(e.x, e.y)
            self._send_touch("end")
            self._fingers = []
            self.canvas.delete("finger")

        def _send_touch(self, phase):
            try:
                self.qmp.input_events(touch_events(phase, self._fingers_now()))
                if self.grabber:
                    self.grabber.kick()
            except QMPError as ex:
                self._set_status("Not sent: %s" % ex)

        # -- phone window: fake call / SMS, carrier, battery ---------------------
        def _qom_async(self, path, prop, value, ok=None):
            """qom-set on a worker thread; the outcome goes to the status line."""
            def work():
                try:
                    self.qmp.qom_set(path, prop, value)
                    self._status_q.put(("info", ok or "%s set" % prop))
                except QMPError as ex:
                    self._status_q.put(("warn", "%s: %s" % (prop, ex)))
            threading.Thread(target=work, daemon=True).start()

        def _modem(self, prop, value, ok=None):
            self._qom_async(MODEM_PATH, prop, value, ok)

        def _machine(self, prop, value, ok=None):
            self._qom_async(MACHINE_PATH, prop, value, ok)

        def _open_phone(self):
            if self._phone_win is not None:
                self._phone_win.lift()
                return
            if not self._connected:
                self._set_status("Phone: not connected to QEMU yet")
                return
            win = tk.Toplevel(self)
            self._phone_win = win
            win.title("Phone controls")
            win.resizable(False, False)
            win.protocol("WM_DELETE_WINDOW", self._close_phone)
            ui = self._phone_ui = {}
            self._modem_widgets, self._battery_widgets = [], []

            def widget(kind, parent, group, **kw):
                w = kind(parent, **kw)
                group.append(w)
                return w

            nb = ttk.Notebook(win)
            nb.pack(fill="both", expand=True, padx=6, pady=6)
            tabs = {}
            for name in ("Call", "SMS", "Network", "Battery"):
                f = ttk.Frame(nb, padding=10)
                nb.add(f, text=name)
                tabs[name] = f
            ui["nb"] = nb
            ui["nomodem"] = ttk.Label(
                win, wraplength=330, foreground="#a33", justify="left",
                text="This machine has no baseband (the Call, SMS and Network tabs need one). Start an iPhone "
                     "machine with baseband=on, e.g. -M iPhone-4,baseband=on.")

            # Call
            f = tabs["Call"]
            ui["call_num"] = tk.StringVar(value="+15551234567")
            ttk.Label(f, text="From number").grid(row=0, column=0, sticky="w")
            widget(ttk.Entry, f, self._modem_widgets, textvariable=ui["call_num"], width=24).grid(
                row=0, column=1, columnspan=2, sticky="we", pady=2)
            widget(ttk.Button, f, self._modem_widgets, text="Ring (incoming call)", command=self._do_call).grid(
                row=1, column=0, columnspan=3, sticky="we", pady=(8, 2))
            widget(ttk.Button, f, self._modem_widgets, text="Caller answers (outgoing call)",
                   command=lambda: self._modem("remote-answer", "1", "Far end answered")).grid(
                row=2, column=0, columnspan=3, sticky="we", pady=2)
            widget(ttk.Button, f, self._modem_widgets, text="Caller hangs up",
                   command=lambda: self._modem("remote-hangup", "1", "Far end hung up")).grid(
                row=3, column=0, columnspan=3, sticky="we", pady=2)
            ui["callstate"] = ttk.Label(f, text="Call state: -", foreground="#555555")
            ui["callstate"].grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))
            ttk.Label(f, text="To take the call on the guest, tap Accept on its screen.", foreground="#555555",
                      wraplength=320).grid(row=5, column=0, columnspan=3, sticky="w", pady=(4, 0))

            # SMS
            f = tabs["SMS"]
            ui["sms_num"] = tk.StringVar(value="+15551234567")
            ttk.Label(f, text="From number").grid(row=0, column=0, sticky="w")
            widget(ttk.Entry, f, self._modem_widgets, textvariable=ui["sms_num"], width=26).grid(
                row=0, column=1, sticky="we", pady=2)
            ttk.Label(f, text="Message").grid(row=1, column=0, sticky="nw", pady=(6, 0))
            ui["sms_text"] = widget(tk.Text, f, self._modem_widgets, width=30, height=5, wrap="word")
            ui["sms_text"].grid(row=1, column=1, sticky="we", pady=(6, 2))
            ui["sms_text"].insert("1.0", "Hello from the host!")
            widget(ttk.Button, f, self._modem_widgets, text="Receive SMS", command=self._do_sms).grid(
                row=2, column=0, columnspan=2, sticky="we", pady=(8, 0))

            # Network
            f = tabs["Network"]
            ui["carrier"] = tk.StringVar(value=CARRIERS[0][0])
            ui["plmn"] = tk.StringVar(value=CARRIERS[0][1])
            ttk.Label(f, text="Carrier").grid(row=0, column=0, sticky="w")
            cb = widget(ttk.Combobox, f, self._modem_widgets, textvariable=ui["carrier"], width=22,
                        values=[c[0] for c in CARRIERS])
            cb.grid(row=0, column=1, sticky="we", pady=2)
            cb.bind("<<ComboboxSelected>>", self._carrier_picked)
            ttk.Label(f, text="MCC-MNC").grid(row=1, column=0, sticky="w")
            widget(ttk.Entry, f, self._modem_widgets, textvariable=ui["plmn"], width=10).grid(
                row=1, column=1, sticky="w", pady=2)
            widget(ttk.Button, f, self._modem_widgets, text="Apply carrier", command=self._do_carrier).grid(
                row=2, column=0, columnspan=2, sticky="we", pady=(4, 8))
            ttk.Separator(f).grid(row=3, column=0, columnspan=2, sticky="we", pady=4)
            ui["dbm"] = tk.IntVar(value=-59)
            ui["dbm_label"] = ttk.Label(f, text="Signal: -59 dBm")
            ui["dbm_label"].grid(row=4, column=0, columnspan=2, sticky="w")
            sc = widget(ttk.Scale, f, self._modem_widgets, from_=SIGNAL_MIN_DBM, to=SIGNAL_MAX_DBM,
                        orient="horizontal", length=260,
                        command=lambda v: ui["dbm_label"].configure(text="Signal: %d dBm" % round(float(v))))
            sc.grid(row=5, column=0, columnspan=2, sticky="we")
            sc.set(-59)
            sc.bind("<ButtonRelease-1>", lambda e: self._modem("signal-dbm", round(float(sc.get())),
                                                               "Signal %d dBm" % round(float(sc.get()))))
            ui["dbm_scale"] = sc
            pr = ttk.Frame(f)
            pr.grid(row=6, column=0, columnspan=2, sticky="w", pady=2)
            for label, dbm in SIGNAL_PRESETS:
                widget(ttk.Button, pr, self._modem_widgets, text=label, width=7,
                       command=lambda d=dbm: self._set_signal(d)).pack(side="left", padx=(0, 4))
            ui["registered"] = tk.BooleanVar(value=False)       # True = "No service"
            ui["nosim"] = tk.BooleanVar(value=False)
            widget(ttk.Checkbutton, f, self._modem_widgets, text="No service (deregister)",
                   variable=ui["registered"], command=lambda: self._modem(
                       "registered", not ui["registered"].get(),
                       "No service" if ui["registered"].get() else "Registered again")).grid(
                row=7, column=0, columnspan=2, sticky="w", pady=(8, 0))
            widget(ttk.Checkbutton, f, self._modem_widgets, text="No SIM card", variable=ui["nosim"],
                   command=lambda: self._modem("sim-present", not ui["nosim"].get(),
                                               "SIM removed" if ui["nosim"].get() else "SIM inserted")).grid(
                row=8, column=0, columnspan=2, sticky="w")

            # Battery
            f = tabs["Battery"]
            ui["batt_label"] = ttk.Label(f, text="Level: 100 %")
            ui["batt_label"].grid(row=0, column=0, columnspan=4, sticky="w")
            bs = widget(ttk.Scale, f, self._battery_widgets, from_=0, to=100, orient="horizontal", length=260,
                        command=lambda v: ui["batt_label"].configure(text="Level: %d %%" % round(float(v))))
            bs.grid(row=1, column=0, columnspan=4, sticky="we")
            bs.set(100)
            bs.bind("<ButtonRelease-1>", lambda e: self._set_battery(round(float(bs.get()))))
            ui["batt_scale"] = bs
            for i, pct in enumerate((100, 50, 20, 5)):
                widget(ttk.Button, f, self._battery_widgets, text="%d%%" % pct, width=5,
                       command=lambda v=pct: self._set_battery(v)).grid(row=2, column=i, pady=4, padx=(0, 4))
            ui["charging"] = tk.StringVar(value="auto")
            ttk.Label(f, text="Charging").grid(row=3, column=0, sticky="w", pady=(8, 0))
            cf = ttk.Frame(f)
            cf.grid(row=4, column=0, columnspan=4, sticky="w")
            ui["charging_buttons"] = []
            for label, val in (("Auto", "auto"), ("Charging", "on"), ("Not charging", "off")):
                rb = ttk.Radiobutton(cf, text=label, value=val, variable=ui["charging"],
                                     command=self._do_charging)
                rb.pack(side="left", padx=(0, 8))
                ui["charging_buttons"].append(rb)
            ui["usb"] = tk.BooleanVar(value=True)
            ui["usb_check"] = ttk.Checkbutton(
                f, text="USB cable plugged in", variable=ui["usb"],
                command=lambda: self._machine("usb-attached", ui["usb"].get(),
                                              "USB cable in" if ui["usb"].get() else "USB cable out"))
            ui["usb_check"].grid(row=5, column=0, columnspan=4, sticky="w", pady=(8, 0))

            ui["note"] = ttk.Label(win, text=self._status_text, anchor="w", foreground="#555555", padding=(8, 2))
            ui["note"].pack(fill="x", side="bottom")
            self._set_group_state(self._modem_widgets, False)
            self._set_group_state(self._battery_widgets, False)
            threading.Thread(target=self._probe_phone, daemon=True).start()
            self.after(2000, self._poll_callstate)

        def _close_phone(self):
            win, self._phone_win = self._phone_win, None
            self._phone_ui = {}
            if win is not None:
                win.destroy()

        @staticmethod
        def _set_group_state(group, enabled):
            for w in group:
                try:
                    w.state(["!disabled"] if enabled else ["disabled"])
                except (AttributeError, tk.TclError):
                    w.configure(state="normal" if enabled else "disabled")

        def _probe_phone(self):
            """Worker thread: which phone controls does this machine have, and what are the current values?"""
            try:
                caps = phone_caps(self.qmp.qom_names(MACHINE_PATH))
                caps["values"] = {}
                for prop, path in (("battery-level", MACHINE_PATH), ("usb-attached", MACHINE_PATH),
                                   ("signal-dbm", MODEM_PATH), ("carrier", MODEM_PATH),
                                   ("mcc-mnc", MODEM_PATH), ("registered", MODEM_PATH),
                                   ("sim-present", MODEM_PATH)):
                    if (path == MODEM_PATH and not caps["modem"]) or \
                            (path == MACHINE_PATH and prop not in caps["machine_props"]):
                        continue
                    try:
                        caps["values"][prop] = self.qmp.qom_get(path, prop)
                    except QMPError:
                        pass
                self._status_q.put(("probe", caps))
            except QMPError as ex:
                self._status_q.put(("warn", "Phone: %s" % ex))

        def _apply_probe(self, caps):
            self._phone = caps
            ui = self._phone_ui
            if self._phone_win is None or not ui:
                return
            vals = caps["values"]
            self._set_group_state(self._modem_widgets, caps["modem"])
            if not caps["modem"]:
                ui["nomodem"].pack(fill="x", padx=8, before=ui["note"])
                ui["nb"].select(3)
            self._set_group_state(self._battery_widgets, caps["battery"])
            if not caps["charging"]:
                for rb in ui["charging_buttons"]:
                    rb.state(["disabled"])
            if not caps["usb"]:
                ui["usb_check"].state(["disabled"])
            if isinstance(vals.get("battery-level"), int):
                ui["batt_scale"].set(vals["battery-level"])
            if isinstance(vals.get("usb-attached"), bool):
                ui["usb"].set(vals["usb-attached"])
            if isinstance(vals.get("signal-dbm"), int):
                ui["dbm_scale"].set(vals["signal-dbm"])
            if isinstance(vals.get("carrier"), str):
                ui["carrier"].set(vals["carrier"])
            if isinstance(vals.get("mcc-mnc"), str):
                ui["plmn"].set(vals["mcc-mnc"])
            if isinstance(vals.get("registered"), bool):
                ui["registered"].set(not vals["registered"])
            if isinstance(vals.get("sim-present"), bool):
                ui["nosim"].set(not vals["sim-present"])

        def _poll_callstate(self):
            if self._phone_win is None or self._closing:
                return
            if self._phone and self._phone["modem"] and not self._callstate_busy and self._connected:
                self._callstate_busy = True

                def work():
                    try:
                        self._status_q.put(("callstate", str(self.qmp.qom_get(MODEM_PATH, "call-state"))))
                    except QMPError:
                        pass
                    finally:
                        self._callstate_busy = False
                threading.Thread(target=work, daemon=True).start()
            self.after(2000, self._poll_callstate)

        def _do_call(self):
            num = self._phone_ui["call_num"].get().strip()
            if not valid_phone_number(num):
                self._set_status("Call: number must be 1-20 digits, optionally starting with +")
                return
            self._modem("incoming-call", num, "Ringing from %s" % num)

        def _do_sms(self):
            try:
                value = sms_value(self._phone_ui["sms_num"].get(), self._phone_ui["sms_text"].get("1.0", "end-1c"))
            except ValueError as ex:
                self._set_status("SMS: %s" % ex)
                return
            self._modem("incoming-sms", value, "SMS delivered")

        def _carrier_picked(self, _e=None):
            ui = self._phone_ui
            for name, plmn in CARRIERS:
                if name == ui["carrier"].get():
                    ui["plmn"].set(plmn)

        def _do_carrier(self):
            ui = self._phone_ui
            name, plmn = ui["carrier"].get().strip(), ui["plmn"].get().strip()
            if not valid_carrier(name):
                self._set_status("Carrier: 1-32 printable characters, no double quotes")
                return
            if not valid_plmn(plmn):
                self._set_status("MCC-MNC: 5 or 6 digits (MCC + MNC)")
                return

            def work():                      # plmn first, then the name: the name change re-announces the operator
                try:
                    self.qmp.qom_set(MODEM_PATH, "mcc-mnc", plmn)
                    self.qmp.qom_set(MODEM_PATH, "carrier", name)
                    self._status_q.put(("info", "Carrier is now %s (%s)" % (name, plmn)))
                except QMPError as ex:
                    self._status_q.put(("warn", "carrier: %s" % ex))
            threading.Thread(target=work, daemon=True).start()

        def _set_signal(self, dbm):
            self._phone_ui["dbm_scale"].set(dbm)
            self._modem("signal-dbm", dbm, "Signal %d dBm" % dbm)

        def _set_battery(self, pct):
            self._phone_ui["batt_scale"].set(pct)
            self._machine("battery-level", int(pct), "Battery %d %%" % pct)

        def _do_charging(self):
            mode = self._phone_ui["charging"].get()
            args = charging_args(self._phone["machine_props"] if self._phone else (), mode)
            if args is None:
                self._set_status("This machine has no charging control")
                return
            self._machine(args[0], args[1], "Charging: %s" % mode)

        # -- screenshot ------------------------------------------------------
        def _screenshot(self):
            if not self._connected:
                return
            path = filedialog.asksaveasfilename(
                parent=self, title="Save screenshot", defaultextension=".png",
                initialfile=time.strftime("screenshot-%Y%m%d-%H%M%S.png"),
                filetypes=[("PNG image", "*.png"), ("PPM image", "*.ppm")])
            if not path:
                return
            fmt = "ppm" if path.lower().endswith(".ppm") else "png"

            def work():
                try:
                    self.qmp.execute("screendump", {"filename": path, "format": fmt}, timeout=10.0)
                    self._status_q.put(("info", "Saved %s" % path))
                except QMPError as ex:
                    fr = self._frame
                    if fr and have_pil and fmt == "png":     # QEMU built without PNG: save the last frame
                        w, h, data, off = fr
                        Image.frombuffer("RGB", (w, h), data[off:off + w * h * 3], "raw", "RGB", 0, 1).save(path)
                        self._status_q.put(("info", "Saved %s" % path))
                    else:
                        self._status_q.put(("warn", "Screenshot failed: %s" % ex))
            threading.Thread(target=work, daemon=True).start()

        # -- shutdown --------------------------------------------------------
        def _quit(self):
            if self._closing:
                return
            self._closing = True
            for qcode in list(self._held):            # never leave a button pressed in the guest
                try:
                    self.qmp.input_events([key_event(qcode, False)])
                except QMPError:
                    pass
            if self._fingers:
                try:
                    self.qmp.input_events(touch_events("cancel", self._fingers_now()))
                except QMPError:
                    pass
            if self.grabber:
                self.grabber.stop_ev.set()
            if self._serial_tail:
                self._serial_tail.stop_ev.set()
            self._phone_win = None
            self.qmp.close()
            self.destroy()

    app = Panel()
    if not run:
        return app
    app.mainloop()
    return app


# ---------------------------------------------------------------------------------------------
# selftest (headless): helpers, the QMP client and the grabber against a fake QEMU
# ---------------------------------------------------------------------------------------------

class _FakeQEMU(threading.Thread):
    """A QMP server that records input events and answers screendump with a generated PPM."""

    def __init__(self, path, w=8, h=6):
        super().__init__(daemon=True)
        self.path, self.w, self.h = path, w, h
        self.events, self.errors_for = [], set()
        self.qom_sets = []
        self.qom_tree = {"/machine": ["battery-level", "usb-attached", "baseband-modem", "battery-charging"]}
        self.qom_vals = {("/machine", "battery-level"): 80, ("/machine/baseband-modem", "call-state"): "idle"}
        self.shade = 0
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(1)
        self.conn = None

    def run(self):
        c, _ = self.srv.accept()
        self.conn = c
        f = c.makefile("rwb")
        f.write(b'{"QMP":{"version":{"qemu":{"major":9}},"capabilities":[]}}\r\n')
        f.flush()
        for line in f:
            req = json.loads(line)
            rid, cmd, a = req.get("id"), req["execute"], req.get("arguments", {})
            if cmd in self.errors_for:
                out = {"error": {"class": "GenericError", "desc": "no such thing"}}
            elif cmd == "input-send-event":
                self.events.append(a["events"])
                out = {"return": {}}
            elif cmd == "qom-set":
                self.qom_sets.append(a)
                out = {"return": {}}
            elif cmd == "qom-list":
                if a["path"] in self.qom_tree:
                    out = {"return": [{"name": n, "type": "int"} for n in self.qom_tree[a["path"]]]}
                else:
                    out = {"error": {"class": "GenericError", "desc": "Device '%s' not found" % a["path"]}}
            elif cmd == "qom-get":
                v = self.qom_vals.get((a["path"], a["property"]))
                out = {"return": v} if v is not None else \
                    {"error": {"class": "GenericError", "desc": "Property '%s' not found" % a["property"]}}
            elif cmd == "screendump":
                px = bytes([self.shade, 80, 160]) * (self.w * self.h)
                with open(a["filename"], "wb") as g:
                    g.write(b"P6\n# fake\n%d %d\n255\n" % (self.w, self.h) + px)
                out = {"return": {}}
            else:
                out = {"return": {}}
            if rid is not None:
                out["id"] = rid
            f.write((json.dumps(out) + "\r\n").encode())
            f.flush()
            if cmd == "x-event":
                f.write(b'{"event":"SHUTDOWN","data":{},"timestamp":{"seconds":1,"microseconds":0}}\r\n')
                f.flush()

    def stop(self):
        for s in (self.conn, self.srv):
            try:
                s.shutdown(socket.SHUT_RDWR)  # the handler's makefile keeps the fd alive past close()
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass


def selftest():
    bad = []

    def check(name, ok, detail=""):
        print("%-66s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            bad.append(name)
            if detail:
                print("    " + str(detail))

    # view -> screen mapping: each rotation maps the four displayed corners onto the four screen corners
    corners = [(0, 0), (1, 0), (1, 1), (0, 1)]
    want = {0: [(0, 0), (1, 0), (1, 1), (0, 1)], 90: [(0, 1), (0, 0), (1, 0), (1, 1)],
            180: [(1, 1), (0, 1), (0, 0), (1, 0)], 270: [(1, 0), (1, 1), (0, 1), (0, 0)]}
    for rot in (0, 90, 180, 270):
        got = [tuple(round(x) for x in view_to_source(u, v, rot)) for u, v in corners]
        check("view_to_source rotated %d" % rot, got == want[rot], got)
    # a rotation by r then by 360-r is the identity on any point
    ok = all(abs(view_to_source(*view_to_source(0.3, 0.8, r), (360 - r) % 360)[i] - (0.3, 0.8)[i]) < 1e-9
             for r in (90, 180, 270) for i in (0, 1))
    check("view_to_source composes back to identity", ok)
    check("frac_to_abs clamps and scales", (frac_to_abs(-1), frac_to_abs(0), frac_to_abs(1), frac_to_abs(2),
                                            frac_to_abs(0.5)) == (0, 0, ABS_MAX, ABS_MAX, 16384))
    check("scale_to_ratio snaps to integer ratios",
          [scale_to_ratio(s) for s in (2.7, 1.0, 0.8, 0.5, 0.34, 0.1)] == [(2, 1), (1, 1), (1, 2), (1, 2), (1, 3), (1, 10)])

    # input events
    ev = touch_events("begin", [(0, 5, 100, 200), (1, 6, 300, 400)])
    check("touch_events: data for every finger before the phase",
          [e["data"]["type"] for e in ev] == ["data"] * 4 + ["begin"] * 2)
    check("touch_events: slot/tracking/axis/value fields",
          ev[0]["data"] == {"type": "data", "slot": 0, "tracking-id": 5, "axis": "x", "value": 100}
          and ev[5]["data"]["slot"] == 1 and ev[5]["data"]["axis"] == "x")
    check("key_event shape", key_event("p", True) == {"type": "key", "data": {"down": True,
          "key": {"type": "qcode", "data": "p"}}})
    check("gesture fingers: single, pinch about the centre, two-finger",
          gesture_fingers("single", 0.2, 0.3, 300) == [(0.2, 0.3)]
          and all(abs(a - b) < 1e-9 for p, q in zip(gesture_fingers("pinch", 0.2, 0.3, 300), [(0.2, 0.3), (0.8, 0.7)])
                  for a, b in zip(p, q))
          and abs(gesture_fingers("pan2", 0.2, 0.3, 480)[1][0] - 0.3) < 1e-9
          and gesture_fingers("pan2", 0.98, 0.3, 480)[1][0] == 1.0)

    # phone controls
    check("valid_phone_number: digits, optional leading +, 1-20 long",
          [valid_phone_number(x) for x in ("5551234", "+15551234567", "1" * 20, "1" * 21, "", "+", "12a4", "1+2")]
          == [True, True, True, False, False, False, False, False])
    check("sms_value joins number and text, keeps '|' in the text",
          sms_value(" +639171234567 ", "hi | there") == "+639171234567|hi | there")
    for name, args in (("bad number", ("abc", "hi")), ("empty text", ("555", "   "))):
        try:
            sms_value(*args)
            check("sms_value rejects %s" % name, False)
        except ValueError:
            check("sms_value rejects %s" % name, True)
    check("valid_plmn: 5 or 6 digits", [valid_plmn(x) for x in ("00101", "310410", "1234", "1234567", "31a41")]
          == [True, True, False, False, False])
    check("valid_carrier: printable, <=32, no double quote",
          [valid_carrier(x) for x in ("Globe", "", "x" * 32, "x" * 33, 'a"b', "a\nb")]
          == [True, False, True, False, False, False])
    check("every carrier preset passes its own validators",
          all(valid_carrier(n) and valid_plmn(m) for n, m in CARRIERS))
    check("charging_args: iPod/iPhone string property, A4 usb-charger bool, neither",
          charging_args({"battery-charging"}, "on") == ("battery-charging", "on")
          and charging_args({"usb-charger"}, "off") == ("usb-charger", False)
          and charging_args({"usb-charger"}, "auto") == ("usb-charger", True)
          and charging_args({"usb-attached"}, "on") is None)
    caps = phone_caps(["battery-level", "baseband-modem", "usb-attached"])
    check("phone_caps reads what /machine offers",
          caps["modem"] and caps["battery"] and caps["usb"] and not caps["charging"])
    check("qom_set_args shape", qom_set_args("/machine", "battery-level", 5)
          == {"path": "/machine", "property": "battery-level", "value": 5})
    check("signal presets stay inside the slider range",
          all(SIGNAL_MIN_DBM <= d <= SIGNAL_MAX_DBM for _, d in SIGNAL_PRESETS))

    # PPM
    pix = bytes(range(24))
    check("parse_ppm with a comment", parse_ppm(b"P6\n# hi\n4 2\n255\n" + pix) == (4, 2, 16))
    for name, blob in (("not P6", b"P5\n1 1\n255\n\0"), ("truncated pixels", b"P6\n4 2\n255\n" + pix[:5]),
                       ("16-bit", b"P6\n1 1\n65535\n" + bytes(6)), ("empty", b"")):
        try:
            parse_ppm(blob)
            check("parse_ppm rejects %s" % name, False)
        except ValueError:
            check("parse_ppm rejects %s" % name, True)

    # launcher hook
    check("build_qemu_args: adds our QMP socket",
          build_qemu_args(["-M", "ipad1", "-display", "sdl,show-cursor=on", "-serial", "mon:stdio"], "/tmp/a.sock")
          == ["-M", "ipad1", "-display", "sdl,show-cursor=on", "-serial", "mon:stdio", "-qmp", "unix:/tmp/a.sock,server,nowait"])
    check("build_qemu_args: hide_display swaps the display, keeps the rest",
          build_qemu_args(["-M", "ipad1", "-display", "sdl,show-cursor=on", "-audio", "driver=none"], None, True)
          == ["-M", "ipad1", "-audio", "driver=none", "-display", "none"])
    check("build_qemu_args: commas in the socket path are escaped",
          build_qemu_args([], "/tmp/a,b.sock")[-1] == "unix:/tmp/a,,b.sock,server,nowait")
    check("build_qemu_args: serial_log spells mon:stdio out with a logfile",
          build_qemu_args(["-M", "x", "-serial", "mon:stdio", "-audio", "driver=none"], None, False, "/tmp/s.log")
          == ["-M", "x", "-chardev", "stdio,id=ltserial,mux=on,logfile=/tmp/s.log", "-serial", "chardev:ltserial",
              "-mon", "chardev=ltserial,mode=readline", "-audio", "driver=none"])
    check("build_qemu_args: serial_log leaves other -serial options alone",
          build_qemu_args(["-serial", "file:/tmp/x"], None, False, "/tmp/s.log") == ["-serial", "file:/tmp/x"])
    check("build_qemu_args: no serial_log, no serial edit",
          build_qemu_args(["-serial", "mon:stdio"]) == ["-serial", "mon:stdio"])

    # serial log cleaning: the doubled-newline problem
    sc = SerialCleaner()
    check("serial: \\r\\n, \\n\\r\\n and \\r\\r\\n are each one line break",
          sc.feed(b"one\r\ntwo\n\r\nthree\r\r\nfour\n") == ["one", "two", "three", "four"])
    sc = SerialCleaner()
    got = sc.feed(b"abc\r") + sc.feed(b"\ndef\r\n") + sc.feed(b"\n\nghi")
    check("serial: a break split across chunks does not make blank lines; the tail waits",
          got == ["abc", "def"] and sc.flush() == ["ghi"] and sc.flush() == [], got)
    sc = SerialCleaner()
    check("serial: escape sequences and control characters are dropped",
          sc.feed(b"\x1b[0m\x1b[1;32mok\x1b[0m\x07 done\x00\r\n") == ["ok done"])
    sc = SerialCleaner()
    got = sc.feed(b"caf\xc3") + sc.feed(b"\xa9 \xff\r\n")
    check("serial: UTF-8 split across chunks and invalid bytes do not raise",
          len(got) == 1 and got[0].startswith("café ") and "�" in got[0], got)

    # serial tail: a file that appears late, appended in pieces
    d2 = tempfile.mkdtemp(prefix="touchpanel-serial-")
    try:
        slog, seen = os.path.join(d2, "serial.log"), []
        tail = SerialTail(slog, seen.extend)
        tail.start()
        time.sleep(0.3)
        with open(slog, "ab") as f:
            f.write(b"boot\r\n\r\nlogin: ")
            f.flush()
            time.sleep(0.2)
            check("serial tail: complete lines arrive, the prompt waits", seen == ["boot"], seen)
            time.sleep(SERIAL_PARTIAL_FLUSH_S + 0.4)
            check("serial tail: an unfinished line is shown after a short idle", seen == ["boot", "login:"], seen)
            f.write(b"root\n")
            f.flush()
        time.sleep(0.4)
        check("serial tail: later appends are followed", seen == ["boot", "login:", "root"], seen)
        tail.stop_ev.set()
        tail.join(2)
    finally:
        shutil.rmtree(d2, ignore_errors=True)

    # QMP client + grabber against the fake
    d = tempfile.mkdtemp(prefix="touchpanel-selftest-")
    sock = os.path.join(d, "q.sock")
    srv = _FakeQEMU(sock)
    srv.start()
    seen_events, closed, errs = [], threading.Event(), []
    try:
        c = QMPClient(sock, on_event=seen_events.append, on_close=closed.set, on_error=lambda a, b: errs.append((a, b)))
        c.connect(timeout=5)
        check("QMP: handshake and a command with a reply", c.execute("query-status") == {})
        c.input_events([key_event("h", True)])
        c.input_events([key_event("h", False)])
        c.execute("query-status")  # replies are in order: both input commands have been handled
        check("QMP: input events arrive in order", [e[0]["data"]["down"] for e in srv.events] == [True, False])
        srv.errors_for.add("bogus")
        try:
            c.execute("bogus")
            check("QMP: an error reply raises QMPError", False)
        except QMPError as e:
            check("QMP: an error reply raises QMPError", "no such thing" in str(e), e)
        c.send_nowait("bogus")
        c.execute("query-status")
        check("QMP: a failed send_nowait is reported", errs == [("bogus", "no such thing")], errs)
        c.execute("x-event")
        time.sleep(0.2)
        check("QMP: events are delivered", seen_events == ["SHUTDOWN"], seen_events)

        c.qom_set(MODEM_PATH, "incoming-sms", "555|hello")
        c.qom_set(MACHINE_PATH, "battery-level", 15)
        check("QMP: qom_set sends path/property/value",
              srv.qom_sets == [{"path": MODEM_PATH, "property": "incoming-sms", "value": "555|hello"},
                               {"path": MACHINE_PATH, "property": "battery-level", "value": 15}], srv.qom_sets)
        check("QMP: qom_get returns the value", c.qom_get(MACHINE_PATH, "battery-level") == 80)
        check("QMP: qom_names lists a path; a missing path is empty (no modem)",
              "baseband-modem" in c.qom_names(MACHINE_PATH) and c.qom_names(MODEM_PATH) == [])
        try:
            c.qom_get(MODEM_PATH, "nope")
            check("QMP: qom_get of a missing property raises", False)
        except QMPError:
            check("QMP: qom_get of a missing property raises", True)

        frames = []
        g = FrameGrabber(c, lambda w, h, data, off: frames.append((w, h, len(data) - off)), fps=60)
        g.start()
        time.sleep(0.5)
        n1 = len(frames)
        check("grabber: first frame delivered, unchanged frames are not repeated",
              n1 == 1 and frames[0] == (8, 6, 8 * 6 * 3), frames[:3])
        srv.shade = 99
        g.kick()
        time.sleep(0.6)
        check("grabber: a changed frame is delivered", len(frames) == 2, len(frames))
        g.stop_ev.set()
        g.join(2)

        srv.stop()
        check("QMP: on_close fires when QEMU goes away", closed.wait(2))
        try:
            c.execute("query-status", timeout=1)
            check("QMP: execute after close raises", False)
        except QMPError:
            check("QMP: execute after close raises", True)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    try:
        QMPClient(os.path.join(d, "none.sock")).connect(timeout=0.4)
        check("QMP: a missing socket times out with QMPError", False)
    except QMPError:
        check("QMP: a missing socket times out with QMPError", True)

    print("\nFAILURES: %s" % ", ".join(bad) if bad else "\nALL OK")
    return 1 if bad else 0


# ---------------------------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------------------------

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--exec-qemu":
        exec_qemu(argv[1:])
        return 0
    ap = argparse.ArgumentParser(
        description="On-screen buttons and touch screen for a running qemu-ios machine (over QMP)")
    ap.add_argument("--qmp", help="QMP unix socket of the running QEMU (-qmp unix:PATH,server,nowait)")
    ap.add_argument("--title", help="window title")
    ap.add_argument("--fps", type=float, default=15.0, help="screen refresh rate while active (default 15)")
    ap.add_argument("--rotate", type=int, choices=(0, 90, 180, 270), default=0,
                    help="show the screen rotated clockwise (needs Pillow)")
    ap.add_argument("--scale", default="fit", help="'fit' (default) or a factor such as 1, 0.5")
    ap.add_argument("--connect-timeout", type=float, default=90.0, help="seconds to wait for QEMU's socket")
    ap.add_argument("--serial-log", help="file QEMU appends the guest's serial output to (LT_SERIAL_LOG for "
                                         "--exec-qemu); shown, cleaned up, in a pane beside the screen")
    ap.add_argument("--keep-open", action="store_true", help="do not close the window when QEMU exits")
    ap.add_argument("--selftest", action="store_true", help="run the headless self-test and exit")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.qmp:
        ap.error("--qmp SOCKET is required")
    if args.scale != "fit":
        try:
            args.scale = float(args.scale)
            if not 0.05 <= args.scale <= 8:
                raise ValueError
        except ValueError:
            ap.error("--scale must be 'fit' or a number between 0.05 and 8")
    try:
        import tkinter  # noqa: F401
    except ImportError:
        sys.exit("touchPanel: tkinter is missing (Debian/Ubuntu: sudo apt install python3-tk)")
    _gui_main(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
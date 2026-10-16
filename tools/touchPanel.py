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

Optional: Pillow (with ImageTk) gives smooth fit-to-window scaling and 90-degree view rotation (an iPad's
landscape panel shows the portrait UI sideways).  Without it the screen is shown at 1:1, 1:2, 1:3 ... or 2:1.

Also: `--exec-qemu` is the launcher hook manageFirm.py uses to add a QMP socket (and optionally drop the SDL
window) to a bundle's run.sh without editing it; see exec_qemu().
"""
from __future__ import annotations

import argparse
import json
import os
import queue
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


def build_qemu_args(args, qmp_sock=None, hide_display=False):
    """The launcher hook's argument edit: add our own QMP socket, and optionally replace the display with
    `-display none` (the panel is the screen).  Existing monitors and sockets are left alone."""
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
    if qmp_sock:
        out += ["-qmp", "unix:%s,server,nowait" % qmp_sock.replace(",", ",,")]
    return out


def exec_qemu(argv):
    """`--exec-qemu ARGS...`: replace this process with the real QEMU (LT_REAL_QEMU), same arguments plus the
    edits above (LT_QMP_SOCK, LT_HIDE_DISPLAY=1).  A bundle's run.sh runs `$QEMU -M ...`; manageFirm.py points
    QEMU at a one-line shell wrapper that runs this."""
    real = os.environ.get("LT_REAL_QEMU")
    if not real:
        sys.exit("touchPanel: --exec-qemu needs LT_REAL_QEMU")
    args = build_qemu_args(argv, os.environ.get("LT_QMP_SOCK"), os.environ.get("LT_HIDE_DISPLAY") == "1")
    os.execv(real, [real] + args)


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
            menubar.add_cascade(label="View", menu=view)
            self.config(menu=menubar)

            body = ttk.Frame(self, padding=4)
            body.pack(fill="both", expand=True)
            side = ttk.Frame(body)
            side.pack(side="right", fill="y", padx=(6, 0))
            self.canvas = tk.Canvas(body, width=360, height=480, bg="#101010", highlightthickness=0,
                                    cursor="circle")
            self.canvas.pack(side="left", fill="both", expand=True)
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

        # -- status / lifecycle ----------------------------------------------
        def _set_status(self, text):
            self._status_text = text
            self._refresh_status()

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
                    else:
                        self._set_status(text)
            except queue.Empty:
                pass
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
                s0 = min(1.0, 0.85 * sh / rh, 0.85 * (sw - 140) / rw)
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
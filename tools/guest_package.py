#!/usr/bin/env python3
"""Guest package seed: the loader and seed package a prepared device starts with.

Python port of FirmwareKit's GuestPackage.seed (LightTouchMac) over the .itpack format written by
contrib/guest-package/mkpkg.c, plus the OpenGLES-hook handling that goes with it.

    pack = read_itpack("armv7.itpack")                       # [(name, bytes)] in entry order
    written, record = seed(mnt, "armv7.itpack", gles=True)   # mnt: the mounted, writable system volume

`written` are the volume-relative paths created (root-owned when run as root); `record` is the
device.lock.json "guest_package" object.

What the seed does to the volume (mkpkg.seed):
  * the loader  usr/local/bin/it_boot + System/Library/LaunchDaemons/com.qemu.it-boot.plist
    (the legacy-linked loader/it_boot-legacy for a family that requires link=legacy);
  * the package for the volume's ProductBuildVersion as it_boot installs one:
    usr/local/lighttouch/pkgs/<serial>/ with its `offer`, `current` -> pkgs/<serial>, and `state`
    ("seed N" then one "hook <respring> <target>" line per installed hook);
  * each hook whose target exists on the volume: the target replaced by the package's bytes and
    <target>.baked (or an empty <target>.baked-absent) keeping what the volume had.  The GL engines'
    hooks are kept only when `gles` (the preparer installed the shim / front end);
  * the baked launch jobs the package provides are removed.

Not ported: FitCheck.loads (the dyld load proof of every Mach-O on this firmware, which needs the
firmware's images and a Mach-O loader model).  The loader and payloads are therefore installed unproven.
"""
import fnmatch
import hashlib
import json
import os
import plistlib
import struct
import zlib

MAGIC = b"ITPACK01"
ROOT = "usr/local/lighttouch"
LOADER = ("usr/local/bin/it_boot", "System/Library/LaunchDaemons/com.qemu.it-boot.plist")
SYSTEM_VERSION = "System/Library/CoreServices/SystemVersion.plist"
HOOK_PROVENANCE = b"file-or-absence 1\n"
MBX = "/System/Library/Frameworks/OpenGLES.framework/MBXGLEngine.bundle/MBXGLEngine"
OPENGLES = "/System/Library/Frameworks/OpenGLES.framework/OpenGLES"
APPSYNC = "/usr/lib/libappsync.dylib"


class GuestPackageError(Exception):
    pass


def is_gl_target(target):
    """The GL engines' stock paths (mkpkg GL_TARGETS: MBX, GLENGINE, GLD and 2.x's OPENGLES front end)."""
    base = os.path.basename(target)
    return (target in (MBX, OPENGLES) or target.startswith("/System/Library/Frameworks/OpenGLES.framework/")
            or base.startswith("GLEngine") or base.startswith("GLD"))


# ---------------------------------------------------------------------------------------------
# .itpack: MAGIC, u32le index length, JSON index {"format":1,"entries":[{"name","size"}]}, one zlib stream
# ---------------------------------------------------------------------------------------------

def read_itpack(path):
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) < 12 or blob[:8] != MAGIC:
        raise GuestPackageError("%s: not an itpack (bad magic)" % path)
    ilen = struct.unpack_from("<I", blob, 8)[0]
    if 12 + ilen > len(blob):
        raise GuestPackageError("%s: index runs past the file" % path)
    index = json.loads(blob[12:12 + ilen])
    if index.get("format") != 1:
        raise GuestPackageError("%s: unsupported itpack format %r" % (path, index.get("format")))
    body = zlib.decompress(blob[12 + ilen:])
    out, off = [], 0
    for e in index["entries"]:
        n = int(e["size"])
        if off + n > len(body):
            raise GuestPackageError("%s: entry %s runs past the stream" % (path, e["name"]))
        out.append((e["name"], body[off:off + n]))
        off += n
    if off != len(body):
        raise GuestPackageError("%s: %d stray bytes after the last entry" % (path, len(body) - off))
    return out


def write_itpack(path, entries):
    """Test helper: what mkpkg.c's pack() writes (one zlib stream, level 9, per-entry compress then flush)."""
    idx = json.dumps({"format": 1, "entries": [{"name": n, "size": len(d)} for n, d in entries]},
                     separators=(", ", ": ")).encode()
    z = zlib.compressobj(9)
    body = b"".join(z.compress(d) for _, d in entries) + z.flush()
    with open(path, "wb") as f:
        f.write(MAGIC + struct.pack("<I", len(idx)) + idx + body)


def _build_matches(build, patterns):
    """requires.builds: exact ids or "<major>*" (every build of that iOS major, e.g. 5* = 2.x)."""
    for p in patterns:
        if p.endswith("*") and p[:-1].isdigit():
            digits = ""
            for c in build:
                if not c.isdigit():
                    break
                digits += c
            if digits == p[:-1]:
                return True
        elif fnmatch.fnmatchcase(build, p):
            return True
    return False


def packages(entries, build, board=None, stubs=False):
    """[(family, manifest)] whose requires match `build` (and `board` when given); stub families only with `stubs`."""
    out = []
    for name, data in entries:
        if not name.endswith("/manifest.json") or name.count("/") != 1:
            continue
        man = json.loads(data)
        req = man.get("requires", {})
        if man.get("stub") and not stubs:
            continue
        if not _build_matches(build, req.get("builds", [])):
            continue
        if board and req.get("boards") and board not in req["boards"]:
            continue
        out.append((man["family"], man))
    return out


def offer_text(man, build):
    """The offer it_boot parses (it_boot.c parse_offer): header, build, serial, then file/job/hook lines whose
    index is the entry's position in the manifest's files (the host serves each payload by that index)."""
    hooks = {h["file"]: h for h in man.get("hooks", [])}
    lines = ["ltpkg 1", "build %s" % build, "serial %d %s" % (man["serial"], man["version"])]
    for i, f in enumerate(man["files"]):
        name = f["name"]
        h = hooks.get(name)
        kind = "hook" if h else ("job" if name.startswith("jobs/") else "file")
        line = "%s %d %s %s %d %s" % (kind, i, name, f["mode"], f["size"], f["sha256"])
        if h:
            line += " " + h["target"] + (" respring" if h.get("respring") else "")
        lines.append(line)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------------------
# the volume edits
# ---------------------------------------------------------------------------------------------

def _stat(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _put(path, data, mode):
    """Write `data` as a fresh plain file keeping the owner of what was there (a stock file may carry
    UF_COMPRESSED + decmpfs, which would keep serving the old bytes)."""
    st = _stat(path)
    if st is not None and not os.path.isdir(path):
        os.unlink(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)
    if st is not None:
        try:
            os.chown(path, st.st_uid, st.st_gid)
        except OSError:
            pass


def preserve_hook(volume, target, put=None):
    """Keep the original file or its absence before an installer changes it (GuestPackage.preserveHook).
    Existing provenance is immutable.  -> the volume-relative marker path."""
    at = lambda rel: os.path.join(volume, rel)
    baked, absent = target + ".baked", target + ".baked-absent"
    have_baked, have_absent = _stat(at(baked)), _stat(at(absent))
    if have_baked is not None and have_absent is not None:
        raise GuestPackageError("conflicting hook provenance for %s" % target)
    if have_absent is not None:
        if not os.path.isfile(at(absent)) or have_absent.st_size != 0:
            raise GuestPackageError("invalid absent hook marker for %s" % target)
        return absent
    if have_baked is not None:
        return baked
    put = put or (lambda rel, data, mode: _put(at(rel), data, mode))
    st = _stat(at(target))
    if st is not None:
        with open(at(target), "rb") as f:
            put(baked, f.read(), st.st_mode & 0o7777)
        return baked
    put(absent, b"", 0o644)
    return absent


def seed(volume, itpack, gles=False, omitted=(), board=None, log=print):
    """GuestPackage.seed.  -> (written, record)."""
    entries = read_itpack(itpack)
    by_name = {}
    for n, d in entries:
        by_name.setdefault(n, d)
    at = lambda rel: os.path.join(volume, rel)

    try:
        with open(at(SYSTEM_VERSION), "rb") as f:
            build = plistlib.load(f).get("ProductBuildVersion")
    except (OSError, plistlib.InvalidFileException) as e:
        raise GuestPackageError("no readable /%s (%s)" % (SYSTEM_VERSION, e))
    if not build:
        raise GuestPackageError("no ProductBuildVersion in /%s" % SYSTEM_VERSION)

    fams = packages(entries, build, board=board, stubs=True)
    if len(fams) != 1:
        raise GuestPackageError("%s: %d packages for build %s" % (os.path.basename(itpack), len(fams), build))
    family, man = fams[0]

    hooks = [h for h in man.get("hooks", [])
             if (gles or not is_gl_target(h["target"])) and os.path.exists(at(h["target"][1:]))]
    if any(os.path.exists(at(h["target"][1:] + ".baked-absent")) for h in hooks) \
            and by_name.get("loader/hook-provenance") != HOOK_PROVENANCE:
        raise GuestPackageError("guest loader cannot restore absent hook originals; rebuild the guest exports")
    kept = {h["file"] for h in hooks}
    for h in man.get("hooks", []):
        if h["file"] in kept or is_gl_target(h["target"]) or h["target"] in omitted:
            continue
        log("warning: %s/%s (hook): its target %s is not on this firmware: the hook is dropped"
            % (family, h["file"], h["target"]))
    man = dict(man, hooks=hooks)
    # a dropped hook's payload is not shipped either
    dropped = {h["file"] for h in json.loads(by_name[family + "/manifest.json"]).get("hooks", [])} - kept
    man["files"] = [f for f in man["files"] if f["name"] not in dropped]

    legacy = man.get("requires", {}).get("link") == "legacy" and "loader/it_boot-legacy" in by_name
    loader_name = "loader/it_boot-legacy" if legacy else "loader/it_boot"
    if loader_name not in by_name:
        raise GuestPackageError("%s: no %s" % (os.path.basename(itpack), loader_name))

    written = []

    def put(rel, data, mode):
        missing, parent = [], os.path.dirname(rel)
        while parent and not os.path.isdir(at(parent)):
            missing.insert(0, parent)
            parent = os.path.dirname(parent)
        for d in missing:
            os.mkdir(at(d), 0o777)
        _put(at(rel), data, mode)
        written.extend(missing + [rel])

    def payload(name):
        if name not in by_name:
            raise GuestPackageError("%s: no %s" % (os.path.basename(itpack), name))
        return by_name[name]

    put(LOADER[0], by_name[loader_name], 0o755)
    put(LOADER[1], payload("loader/com.qemu.it-boot.plist"), 0o644)
    serial = int(man["serial"])
    pkg = "%s/pkgs/%d" % (ROOT, serial)
    for f in man["files"]:
        put(pkg + "/" + f["name"], payload(family + "/" + f["name"]), int(f["mode"], 8))
    put(pkg + "/offer", offer_text(man, build).encode(), 0o644)
    cur = at(ROOT + "/current")
    if _stat(cur) is not None:
        os.unlink(cur)
    os.symlink("pkgs/%d" % serial, cur)
    state = "seed %d\n" % serial
    put(ROOT + "/state", state.encode(), 0o644)
    written.append(ROOT + "/current")

    modes = {f["name"]: int(f["mode"], 8) for f in man["files"]}
    for h in hooks:
        target = h["target"][1:]
        backup = preserve_hook(volume, target, put=put)
        if backup not in written:
            written.append(backup)
        put(target, payload(family + "/" + h["file"]), modes.get(h["file"], 0o755))
        # a first offer without this hook must restore .baked even before the loader reads the seed offer
        state += "hook %d %s\n" % (1 if h.get("respring") else 0, h["target"])
        put(ROOT + "/state", state.encode(), 0o644)

    jobs = [os.path.basename(j) for j in man.get("jobs", [])]
    for j in jobs:
        p = at("System/Library/LaunchDaemons/" + j)
        if _stat(p) is not None:
            os.unlink(p)

    with open(itpack, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    return written, {
        "family": family, "seed": serial, "version": man["version"], "gles": bool(gles),
        "itpack": {"path": itpack, "sha256": sha}, "hooks": [h["target"] for h in hooks], "jobs": jobs,
    }

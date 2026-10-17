#!/usr/bin/env python3
"""Build the nand/ page directory for an iPod touch 2G / 3G (n72ap) device, on Linux.

firmwarekit's n72ap create used to stop after nor.bin and iBoot.bin, so run.sh died with

    qemu-system-arm: no NAND at ".../nand": expected a page directory or a packed image

This is the missing step: a Linux port of imgtools/build_nand.py (which needs macOS' hdiutil/diskutil):

  1. decrypt the rootfs DMG with the catalog key (vfdecrypt) and pull the raw HFS+ volume out of it
  2. grow the volume to the recipe's system size (firmwarekit.hfs_grow, what `hdiutil resize` did)
  3. loop-mount it read-write (root + the hfsplus module), write a single-root fstab and the still
     encrypted kernelcache where iBoot looks for it, drop Finder/Spotlight litter, unmount
  4. lay the volume over the four chip-selects with ftlmap.predict() and generate every page that
     formula does not cover (GPT, FTL/VFL metadata, NAND signature, bad-block table) with
     imgtools/ipod2g_nand.py, so no template image is needed

Usage from firmwarekit.create_img3:   n72_nand.build(ipsw, entry, ri, out, work)
"""
import os
import re
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
IMGTOOLS = os.path.join(HERE, "..", "imgtools", "imgtools")

KC_DIR = "System/Library/Caches/com.apple.kernelcaches"
KC_NAME = "kernelcache.s5l8720x"          # the path iBoot asks FMSS for
FSTAB = "private/etc/fstab"
FSTAB_RW = "/dev/disk0s1 / hfs rw 0 1\n"  # one volume, no separate /private/var partition
JUNK = (".fseventsd", ".Spotlight-V100", ".Trashes", ".TemporaryItems", ".DS_Store")
BLOCK = 4096
DEFAULT_SYSTEM_MIB = 7168


def nand_epoch(version):
    """Restore.plist DeviceMap SCEP: 1 on iPhone OS 2.x, 4 on 3.x and later (a 3.1.3 kernel refuses a '1' store)."""
    m = re.match(r"\d+", version or "")
    return 1 if (m and int(m.group()) < 3) else 4


def build(ipsw_path, entry, ri, out, work, log=print, jailbreak_dir=None, activate=True):
    """Write <out>/nand.  Returns the number of page files written.
    jailbreak_dir: the fetched Cydia bootstrap directory (firmwarekit.jb_fetch); when given, afc2 + Cydia are
    installed in the volume after the other edits.
    activate: patch + re-sign lockdownd so the device reports Activated (the "Connect to iTunes" screen otherwise);
    a patcher that rejects this lockdownd is a warning, not a failure."""
    import firmwarekit as fk                      # lazy: firmwarekit imports this module's caller
    import ipad1_fw

    fk.require_root("building the n72ap NAND (loop-mounting the rootfs)")   # before any slow work
    nand_dir = os.path.join(out, "nand")
    if os.path.exists(nand_dir):
        raise fk.FirmwareError("%s already exists; refusing to overwrite a NAND image" % nand_dir)

    sys.path.insert(0, os.path.abspath(IMGTOOLS))
    import build_nand                              # write_pages() + the volume formula
    import ipod2g_nand                             # noqa: F401  (generated bookkeeping pages)

    recipe = entry.get("recipe", {})
    system_mib = int(recipe.get("system_mib", DEFAULT_SYSTEM_MIB))
    blocks = system_mib * (1 << 20) // BLOCK
    epoch = nand_epoch(entry.get("version", ri.get("version", "")))

    z = zipfile.ZipFile(ipsw_path)
    comp = ipad1_fw.components(z)
    osimg = comp.get("OS")
    if not osimg:
        raise fk.FirmwareError("the IPSW names no system image (OS) to build a NAND from")
    key = entry.get("keys", {}).get("rootfs", {}).get("key")
    if not key:
        raise fk.FirmwareError("catalog entry %s has no rootfs key" % entry.get("id"))

    os.makedirs(work, exist_ok=True)
    dec = os.path.join(work, "rootfs.dmg")
    img = os.path.join(work, "system.img")
    mnt = os.path.join(work, "mnt_sys")

    log("[nand 1/5] decrypting the root filesystem (%s) ..." % osimg)
    with z.open(osimg) as s, open(dec, "wb") as d:
        fk.vfdecrypt(s, d, bytes.fromhex(key))

    log("[nand 2/5] extracting the HFS+ volume ...")
    fk.extract_rootfs(dec, img, work)
    os.remove(dec)

    log("[nand 3/5] growing the volume to %d MiB (%d blocks) ..." % (system_mib, blocks))
    fk.hfs_grow(img, blocks * BLOCK)

    kc_member = ri.get("kernelcache")
    if not kc_member or kc_member not in z.namelist():
        raise fk.FirmwareError("the IPSW has no kernelcache to install into the volume")

    def edit(m):
        log("[nand 4/5] fstab + kernelcache (/%s/%s) ..." % (KC_DIR, KC_NAME))
        with open(os.path.join(m, FSTAB), "w") as f:
            f.write(FSTAB_RW)
        dst = os.path.join(m, KC_DIR, KC_NAME)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:                # encrypted, unmodified: the emulated AES engine decrypts it
            f.write(z.read(kc_member))
        for junk in JUNK:
            p = os.path.join(m, junk)
            shutil.rmtree(p, ignore_errors=True)
            if os.path.isfile(p):
                os.unlink(p)
        if activate:
            log("[nand 4/5] activating lockdownd ...")
            try:
                rep = fk.activate_volume(m, log, image=img)
                log("  lockdownd: %s -> %s" % (rep["input_sha256"][:12], rep["output_sha256"][:12]))
            except fk.ActivationError as e:
                log("warning: lockdownd was NOT activated (%s)" % e)
                log("         the patcher rejected this lockdownd; the device will stop at \"Connect to iTunes\"")
            except (fk.FirmwareError, OSError) as e:
                log("warning: lockdownd was NOT activated (%s)" % e)
        if jailbreak_dir:
            log("[nand 4/5] installing the jailbreak (afc2, Cydia, Substrate) ...")
            try:
                fk.jailbreak_volume(m, jailbreak_dir, img, log)
            except OSError as e:
                raise fk.FirmwareError("the jailbreak edits failed (%s); the volume may be full" % e)

    fk.with_mounted(img, mnt, edit)
    try:
        os.rmdir(mnt)
    except OSError:
        pass

    log("[nand 5/5] writing the page directory (a few hundred thousand small files) ...")
    written, generated = build_nand.write_pages(img, nand_dir, None, blocks, epoch=epoch)
    log("nand/: %d volume pages + %d generated metadata pages (NAND epoch %d)" % (written, generated, epoch))
    try:
        os.remove(img)
    except OSError:
        pass
    return written + generated


if __name__ == "__main__":
    print(__doc__)
#!/usr/bin/env python3
"""
firmwarekit.py -- prepare Apple iOS devices for qemu-ios on Linux.

A Python port of LightTouchMac's Swift `firmwarekit create`, supporting all boards in the
firmware catalog (../FirmwareKit/). Boards and their QEMU machine names:

  m68ap  iPhone 2G       -M iPhone-2G       IMG2/NOR+NAND  (iPhone OS 1.x)
  n45ap  iPod Touch 1G   -M iPod-Touch-1G   IMG2/NOR+NAND  (iPhone OS 1.x–2.x)
  n72ap  iPod Touch 2G/3G -M iPod-Touch     IMG3/NOR+NAND  (iPhone OS 2.x–3.x)
  n18ap  iPod Touch 3G   -M n18             IMG3/kboot     (iPhone OS 3.x)
  n88ap  iPhone 3GS      -M n88             IMG3/kboot     (iPhone OS 3.x)
  k48ap  iPad 1          -M ipad1           IMG3/iBoot NOR (iOS 3.x–5.x)
  n81ap  iPod Touch 4G   -M iPod-Touch-4G   IMG3/kboot     (iOS 4.x)
  n90ap  iPhone 4 GSM    -M iPhone-4        IMG3/kboot     (iOS 4.x)

Usage:
    python3 firmwarekit.py create --ipsw <IPSW> \
        --catalog iphone/firmware-catalog.json --id m68ap-1A543a --out DEV
    python3 firmwarekit.py selftest
    python3 firmwarekit.py difftest .../CActivation/activation.c

Outputs in --out:  iBoot.bin  nor.bin  nand/  identity.json  run.sh

Boards that boot through a bootrom (m68ap, n45ap, n72ap) take `--bootrom PATH`: the file is copied into
--out (as bootrom_<soc>) and run.sh uses that copy, so no $BOOTROM is needed to run the device.

Ported from Swift: IMG3 decryption with the catalog keys (every board; ipad1_fw.decrypt_catalog), the n72ap NOR
(all_flash img3s packed with SHSH wrapped under the emulated UID, N72NOR) and the guest package seed
(`--guest-package ARMV6/ARMV7.itpack`: loader, seed package, OpenGLES front end / AppSync hooks; guest_package.py).
NOT ported from Swift: the n72ap system volume and NAND page store (N72NAND), SystemConfiguration (Wi-Fi/proxy)
seeding, HFS+ journaling, catalog date normalisation, the guest package's FitCheck load proof.
Activation patch and rootfs decrypt/grow are fully ported for m68ap/n45ap; the lockdownd activation patch
(with ad-hoc re-signing of the signed-era binary) also runs on k48ap/n81ap/n90ap, needs root to mount the
rootfs, and is skipped by --skip-activation.

Requires: Python 3.9+, `cryptography`, and for `create`: root, the Linux `hfsplus` kernel
module, and `dmg2img` or `7z` (for the rootfs DMG).
"""
import argparse
import hashlib
import hmac
import json
import os
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ---------------------------------------------------------------------------------------------
# bytes helpers
# ---------------------------------------------------------------------------------------------


def le16(b, o):
    return b[o] | b[o + 1] << 8


def le32(b, o):
    return b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24


def put(b, o, v, n):
    for k in range(n):
        b[o + k] = (v >> (8 * k)) & 0xFF


def put32(b, o, v):
    put(b, o, v & 0xFFFFFFFF, 4)


def crc(b):
    return zlib.crc32(bytes(b)) & 0xFFFFFFFF


def hexb(s):
    return bytes.fromhex(s)


class FirmwareError(Exception):
    pass


# ---------------------------------------------------------------------------------------------
# AES: CBC via `cryptography`; the NOR-signing "decryption key schedule" core in pure Python
# ---------------------------------------------------------------------------------------------


def aes_cbc(data, key, iv, decrypt=True):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    x = c.decryptor() if decrypt else c.encryptor()
    return x.update(data) + x.finalize()


def _gmul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = ((a << 1) & 0xFF) ^ (0x1B if a & 0x80 else 0)
        b >>= 1
    return p


def _make_sbox():
    s = [0] * 256
    for x in range(256):
        inv = 0
        if x:
            for y in range(1, 256):
                if _gmul(x, y) == 1:
                    inv = y
                    break
        r = inv
        for i in range(1, 5):
            r ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        s[x] = r ^ 0x63
    return s


SBOX = _make_sbox()


class AESCore:
    """AES encryption rounds over the *decryption* key schedule (OpenSSL's AES_set_decrypt_key:
    the encryption round keys reversed, InvMixColumns on all but the first and last), as the
    emulated S5L8900 UID engine does.  `decrypt_schedule=False` gives ordinary AES (for testing)."""

    def __init__(self, key, decrypt_schedule=True):
        nk = len(key) // 4
        rounds = nk + 6
        w = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
        rcon = 1
        for i in range(nk, 4 * (rounds + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = [SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
                t[0] ^= rcon
                rcon = _gmul(rcon, 2)
            elif nk > 6 and i % nk == 4:
                t = [SBOX[x] for x in t]
            w.append([a ^ b for a, b in zip(w[i - nk], t)])
        enc = [sum(w[4 * r:4 * r + 4], []) for r in range(rounds + 1)]
        if decrypt_schedule:
            keys = []
            for r, k in enumerate(reversed(enc)):
                if r == 0 or r == rounds:
                    keys.append(k)
                else:
                    keys.append(sum((self._inv_mix(k[c:c + 4]) for c in range(0, 16, 4)), []))
            self.keys = keys
        else:
            self.keys = enc

    @staticmethod
    def _inv_mix(c):
        return [
            _gmul(c[i], 14) ^ _gmul(c[(i + 1) % 4], 11) ^ _gmul(c[(i + 2) % 4], 13) ^ _gmul(c[(i + 3) % 4], 9)
            for i in range(4)
        ]

    def encrypt_block(self, inp):
        rounds = len(self.keys) - 1
        s = [a ^ b for a, b in zip(inp, self.keys[0])]
        for r in range(1, rounds + 1):
            s = [SBOX[x] for x in s]
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows, column-major state
            if r != rounds:
                out = []
                for c in range(0, 16, 4):
                    a = s[c:c + 4]
                    out += [
                        _gmul(a[i], 2) ^ _gmul(a[(i + 1) % 4], 3) ^ a[(i + 2) % 4] ^ a[(i + 3) % 4]
                        for i in range(4)
                    ]
                s = out
            s = [a ^ b for a, b in zip(s, self.keys[r])]
        return s

    def cbc_encrypt(self, d, iv):
        prev = list(iv)
        out = []
        for o in range(0, len(d), 16):
            prev = self.encrypt_block([a ^ b for a, b in zip(d[o:o + 16], prev)])
            out += prev
        return out


# ---------------------------------------------------------------------------------------------
# 8900 containers and IMG2
# ---------------------------------------------------------------------------------------------

KEY_837 = hexb("188458A6D15034DFE386F23B61D43774")  # S5L8900 key 0x837 (public)


def apple8900_body(d):
    """The payload of an 8900 v1.0 container (format 3: AES-128-CBC under key 0x837, 4: plain).
    A final partial AES block is stored in the clear."""
    if len(d) < 0x800 or d[:4] != b"8900" or d[4:7] != b"1.0":
        raise FirmwareError("not an 8900 v1.0 container")
    size = le32(d, 0xC)
    if 0x800 + size > len(d):
        raise FirmwareError("8900 payload runs past the file")
    body = d[0x800:0x800 + size]
    fmt = d[7]
    if fmt == 4:
        return bytes(body)
    if fmt == 3:
        n = size & ~15
        return aes_cbc(body[:n], KEY_837, bytes(16)) + body[n:]
    raise FirmwareError("8900 format %d (only 3, encrypted, and 4, plain, are known)" % fmt)


IMG2_HEADER = 0x400


def img2_header(body):
    if len(body) < IMG2_HEADER or body[:4] != b"2gmI":
        raise FirmwareError("not an IMG2 image")
    typ = body[4:8][::-1].decode("ascii", "replace")
    load, padded, dlen = le32(body, 0xC), le32(body, 0x10), le32(body, 0x14)
    if dlen > padded or IMG2_HEADER + padded > len(body):
        raise FirmwareError("IMG2 %s data runs past the image" % typ)
    return typ, load, padded, dlen


def img2_payload(body):
    _, _, _, dlen = img2_header(body)
    return bytes(body[IMG2_HEADER:IMG2_HEADER + dlen])


# ---------------------------------------------------------------------------------------------
# NOR (N45NOR + N72NOR SysCfg / nvram)
# ---------------------------------------------------------------------------------------------

NOR_SIZE, NOR_BLOCK, NOR_DIR, NOR_FIRST_BLOCK, NOR_NVRAM = 0x100000, 0x40, 0x8400, 1040, 0xFC000
NOR_SYSCFG, NOR_NVRAM_BANK = 0x4000, 0x2000
NOR_ORDER = ["dtre", "batC", "logo", "nsrv", "batl", "batL", "recm"]
BOOT_ARGS = "debug=0x8 kextlog=0xfff cpus=1 rd=disk0s1 serial=1 io=0xffff8fff"
HASH_PADDING = hexb(
    "ad2ee38d2d9be43599044433653df07498d8563b4ff96a5545ce82f29a5ac2bc47616d654f766572a6a09913"
)

_UID = list(hexb("0123456789ABCDEF0123456789ABCDEF"))
_VERIFY_SEED = list(hexb("CDF345B312E748858BBE2147F0E58088"))
_VERIFY_IV = list(hexb("115D7041824B986FBB996C9C6978F1A5"))
_verify_core = None


def img2_verify_encrypt(d):
    global _verify_core
    if _verify_core is None:
        k = AESCore(_UID).cbc_encrypt(_VERIFY_SEED, _VERIFY_IV)
        vkey = sum((k[i:i + 4][::-1] for i in range(0, 16, 4)), [])
        _verify_core = AESCore([0] * 16 + vkey)
    return bytes(_verify_core.cbc_encrypt(list(d), [0] * 16))


def nor_sign(body):
    """add_img2: block count, trusted-write and encrypted flags, data hash, header CRC, extension
    CRC, header hash (SHA-1s encrypted under the IMG2 verify key)."""
    b = bytearray(body)
    if len(b) < IMG2_HEADER:
        raise FirmwareError("IMG2 shorter than its header")
    padded = le32(b, 0x10)
    if IMG2_HEADER + padded > len(b):
        raise FirmwareError("IMG2 data runs past the image")
    put32(b, 0x18, len(b) // NOR_BLOCK + 5)
    flags = le32(b, 0x1C) | 1 << 24 | 1 << 1
    put32(b, 0x1C, flags)
    data_hash = hashlib.sha1(bytes(b[IMG2_HEADER:IMG2_HEADER + padded])).digest() + HASH_PADDING[:44]
    b[0x20:0x60] = img2_verify_encrypt(data_hash)
    put32(b, 0x64, crc(b[0:0x64]))
    if flags & 1 << 30:
        nxt = le32(b, 0x60)
        if 0x6C + nxt > IMG2_HEADER:
            raise FirmwareError("IMG2 extension runs past the header")
        put32(b, 0x68, crc(b[0x6C:0x6C + nxt]))
    header_hash = hashlib.sha1(bytes(b[0:0x3E0])).digest() + HASH_PADDING[:12]
    b[0x3E0:0x400] = img2_verify_encrypt(header_hash)
    return bytes(b)


def write_syscfg(nor, ident):
    nor[NOR_SYSCFG:NOR_SYSCFG + 4] = b"gfCS"
    for i, v in enumerate([0xC8, 0x2000, 0x00010001, 0, 4]):
        put32(nor, NOR_SYSCFG + 4 + 4 * i, v)
    for i, (tag, key) in enumerate(
        [("Mod#", "model-number"), ("Regn", "region-info"), ("SrNm", "serial-number"), ("Batt", "battery-serial")]
    ):
        value = ident.get(key, "").encode()
        if len(value) > 16:
            raise FirmwareError("%s is longer than a SysCfg value" % key)
        o = NOR_SYSCFG + 0x18 + i * 0x14
        nor[o:o + 20] = tag.encode()[::-1] + value + bytes(16 - len(value))


def chrp(sig, length, name):
    h = bytearray([sig, 0, (length // 16) & 0xFF, (length // 16) >> 8]) + name.encode() + bytes(12 - len(name))
    s = 0
    for x in [h[0]] + list(h[2:]):
        s += x
        if s > 0xFF:
            s = (s & 0xFF) + 1
    h[1] = s
    return bytes(h)


def nvram_bank(common):
    bank = bytearray(NOR_NVRAM_BANK)
    bank[0:16] = chrp(0x5A, 0x20, "nvram")
    put32(bank, 0x14, 0x10)
    body = b"".join(("%s=%s" % kv).encode() + b"\0" for kv in common)
    if len(body) > 0x800 - 16:
        raise FirmwareError("nvram common partition overflows")
    bank[0x20:0x30] = chrp(0x70, 0x800, "common")
    bank[0x30:0x30 + len(body)] = body
    bank[0x820:0x830] = chrp(0xA1, 0x810, "APL,OSXPanic")
    bank[0x1030:0x1040] = chrp(0x7F, NOR_NVRAM_BANK - 0x1030, "w" * 12)
    put32(bank, 0x10, zlib.adler32(bytes(bank[0x14:])) & 0xFFFFFFFF)
    return bytes(bank)


def build_nor(ident, images, boot_args=BOOT_ARGS):
    nor = bytearray(NOR_SIZE)
    write_syscfg(nor, ident)
    nor[NOR_DIR:NOR_DIR + 4] = b"2GMI"
    put32(nor, NOR_DIR + 4, NOR_BLOCK)
    put32(nor, NOR_DIR + 8, NOR_FIRST_BLOCK)
    put32(nor, NOR_DIR + 16, 512 * 1024)
    put32(nor, NOR_DIR + 0x30, crc(nor[NOR_DIR:NOR_DIR + 0x30]))
    off = NOR_FIRST_BLOCK * NOR_BLOCK
    for t in NOR_ORDER:
        if t not in images:
            raise FirmwareError("all_flash has no IMG2 of type %s" % t)
        img = nor_sign(images[t])
        if off + len(img) > NOR_NVRAM:
            raise FirmwareError("NOR image area overflows the nvram partition (%s)" % t)
        nor[off:off + len(img)] = img
        off += (len(img) // NOR_BLOCK + 5) * NOR_BLOCK
    common = [("boot-args", boot_args)]
    if "wifi-mac" in ident:
        common.append(("wifiaddr", ident["wifi-mac"].upper()))
    if "bt-mac" in ident:
        common.append(("btaddr", ident["bt-mac"].upper()))
    nor[NOR_NVRAM:NOR_NVRAM + NOR_NVRAM_BANK] = nvram_bank(common)
    return bytes(nor)


# ---------------------------------------------------------------------------------------------
# NAND (N45NAND): bank<N>/<page>.page, 2048 data + 64 spare bytes
# ---------------------------------------------------------------------------------------------

PAGE, SPARE, PAGES_PER_BLOCK, BLOCKS_PER_BANK = 2048, 64, 128, 4096
FTL_START, CXT_BLOCKS, FREE_BLOCKS, DATA_START = 201, 3, 20, 23
VFL_CXT_BLOCK, VFL_CXT_COPIES, LOG_CXTS = 35, 8, 18
MAP_TABLES = BLOCKS_PER_BANK * 2 // PAGE
RESERVED_START, MAX_RESERVED = VFL_CXT_BLOCK + 4, 820
MAPPED_LBNS, FIRST_LBA = 3800, 3
HFS_TYPE = hexb("005346480000aa11aa1100306543ecac")


def superblock(banks):
    return PAGES_PER_BLOCK * banks


def location_vpn(vpn, banks):
    sb = superblock(banks)
    v = vpn + FTL_START * sb
    return (v % banks, v // sb * PAGES_PER_BLOCK + (v // banks) % PAGES_PER_BLOCK)


def location_lpn(lpn, banks):
    return location_vpn(DATA_START * superblock(banks) + lpn, banks)


def data_spare(lpn):
    s = bytearray(SPARE)
    put(s, 0, lpn, 4)
    s[8], s[9], s[10], s[11] = 0xFF, 0x40, 0xFF, 0xFF
    return bytes(s)


def cxt_spare(typ, index, age=0xFFFFFFFF):
    s = bytearray(SPARE)
    put(s, 0, age, 4)
    put(s, 4, index, 2)
    s[6] = s[7] = s[8] = 0xFF
    s[9] = typ
    s[10] = s[11] = 0xFF
    return bytes(s)


def vfl_context(bank):
    d = bytearray(PAGE)
    put(d, 0, bank, 4)
    for i in range(CXT_BLOCKS):
        put(d, 4 + 2 * i, i, 2)
    put(d, 0xC, 0xFFFFFFFF, 4)
    put(d, 0x12, VFL_CXT_COPIES, 2)
    put(d, 0x14, 1, 2)
    put(d, 0x1A, 1, 2)
    put(d, 0x1C, RESERVED_START, 2)
    put(d, 0x1E, FTL_START - RESERVED_START, 2)
    put(d, 0x20, BLOCKS_PER_BANK - 1, 2)
    for i in range(0x688, 0x7A2):
        d[i] = 0xFF
    d[0x688 + (BLOCKS_PER_BANK - 1) // 64] &= ~(1 << (7 - ((BLOCKS_PER_BANK - 1) // 8) % 8)) & 0xFF
    for i in range(4):
        put(d, 0x7A2 + 2 * i, VFL_CXT_BLOCK + i, 2)
    put(d, 0x7AA, MAX_RESERVED, 2)
    s = x = 0
    for o in range(0, 0x7F8, 4):
        w = le32(d, o)
        s = (s + w) & 0xFFFFFFFF
        x ^= w
    put(d, 0x7F8, (s + 0xAABBCCDD) & 0xFFFFFFFF, 4)
    put(d, 0x7FC, x ^ 0xAABBCCDD, 4)
    return bytes(d)


VFL_SPARE = bytes([0xFF] * 8 + [0x00, 0x80] + [0xFF] * (SPARE - 10))


def ftl_meta(banks):
    d = bytearray(PAGE)
    put(d, 0, 0xFFFFFFFE, 4)
    put(d, 4, 1, 4)
    put(d, 8, FREE_BLOCKS, 2)
    for i in range(FREE_BLOCKS):
        put(d, 14 + 2 * i, CXT_BLOCKS + i, 2)
    for i in range(MAP_TABLES):
        put(d, 56 + 4 * i, 1 + i, 4)
    for i in range(LOG_CXTS):
        put(d, 420 + 20 * i + 4, 0xFFFF, 2)
    for i in range(CXT_BLOCKS):
        put(d, 786 + 2 * i, i, 2)
    put(d, 792, superblock(banks) - 1, 4)
    put(d, 796, 1, 4)
    put(d, 2040, 0x46560000, 4)
    put(d, 2044, (~0x46560000) & 0xFFFFFFFF, 4)
    return bytes(d)


def partition_pages(fs_pages):
    mbr = bytearray(PAGE)
    mbr[0x1BE + 4] = 0xEE
    put(mbr, 0x1BE + 8, FIRST_LBA, 4)
    put(mbr, 0x1BE + 12, fs_pages, 4)
    mbr[0x1FE], mbr[0x1FF] = 0x55, 0xAA
    ent = bytearray(PAGE)
    ent[0:16] = HFS_TYPE
    ent[16:32] = hexb("3c1f8e52067d4b0a9b612f0e8814c35d")
    put(ent, 0x20, FIRST_LBA, 8)
    put(ent, 0x28, FIRST_LBA + fs_pages - 1, 8)
    for i, c in enumerate("System".encode("utf-16-le")[::2]):
        put(ent, 0x38 + 2 * i, c, 2)
    hdr = bytearray(PAGE)
    hdr[0:8] = b"EFI PART"
    put(hdr, 8, 0x00010000, 4)
    put(hdr, 12, 0x5C, 4)
    put(hdr, 0x18, 1, 8)
    put(hdr, 0x28, FIRST_LBA, 8)
    put(hdr, 0x30, FIRST_LBA + fs_pages - 1, 8)
    hdr[0x38:0x48] = hexb("6a2e5c109f3b4e418d271c44a510e701")
    put(hdr, 0x48, 2, 8)
    put(hdr, 0x50, 1, 4)
    put(hdr, 0x54, 0x80, 4)
    put(hdr, 0x58, crc(ent[0:0x80]), 4)
    put(hdr, 0x10, crc(hdr[0:0x5C]), 4)
    return [bytes(mbr), bytes(hdr), bytes(ent)]


def fil_id(iboot):
    """The NAND signature iBoot's driver wants: the one 'C00N' little-endian literal in it."""
    ids = set()
    for o in range(0, len(iboot) - 3, 4):
        w = le32(iboot, o)
        if w & 0xFFFFFFF0 == 0x43303030 and w & 0xF <= 9:
            ids.add(w)
    if len(ids) != 1:
        raise FirmwareError("iBoot: %d NAND driver versions ('C00N' literals), wanted one" % len(ids))
    return ids.pop()


def metadata_pages(fs_pages, fil, banks, bbt_map):
    zero = bytes(SPARE)
    f = bytearray(PAGE)
    put(f, 0, fil, 4)
    pages = {(0, 0): bytes(f) + zero}
    bbt = bytearray(b"DEVICEINFOBBT" + bytes(PAGE - 13))
    if bbt_map:
        put(bbt, 0x34, BLOCKS_PER_BANK // 8, 4)
        for i in range(BLOCKS_PER_BANK // 8):
            bbt[0x38 + i] = 0xFF
        bbt[0x38 + (BLOCKS_PER_BANK - 1) // 8] &= ~(1 << ((BLOCKS_PER_BANK - 1) % 8)) & 0xFF
    for b in range(banks):
        pages[(b, (BLOCKS_PER_BANK - 1) * PAGES_PER_BLOCK)] = bytes(bbt) + zero
        cxt = vfl_context(b) + VFL_SPARE
        for c in range(VFL_CXT_COPIES):
            pages[(b, VFL_CXT_BLOCK * PAGES_PER_BLOCK + c)] = cxt
    pages[location_vpn(0, banks)] = bytes(PAGE) + cxt_spare(0x43, 0)
    for i in range(MAP_TABLES):
        d = bytearray(PAGE)
        for j in range(PAGE // 2):
            lbn = i * PAGE // 2 + j
            put(d, 2 * j, lbn + DATA_START if lbn < MAPPED_LBNS else 0xFFFF, 2)
        pages[location_vpn(1 + i, banks)] = bytes(d) + cxt_spare(0x46, i)
    pages[location_vpn(superblock(banks) - 1, banks)] = ftl_meta(banks) + cxt_spare(0x43, 0, 0xFFFFFFFE)
    for lba, d in enumerate(partition_pages(fs_pages)):
        pages[location_lpn(lba, banks)] = d + data_spare(lba)
    return pages


def write_nand(volume, out, fil, banks, bbt_map, progress=None):
    """Page directory for a flat HFS+ volume: metadata pages, then every page of every logical
    block the volume spans, zeros included.  Returns (filesystem pages, metadata pages)."""
    size = os.path.getsize(volume)
    fs_pages = (size + PAGE - 1) // PAGE
    sb = superblock(banks)
    blocks = (FIRST_LBA + fs_pages + sb - 1) // sb
    if blocks > MAPPED_LBNS:
        raise FirmwareError("a %d-byte volume is larger than the NAND's mapped logical blocks" % size)
    for b in range(banks):
        os.makedirs(os.path.join(out, "bank%d" % b), exist_ok=True)

    def path(p):
        return os.path.join(out, "bank%d" % p[0], "%d.page" % p[1])

    meta = metadata_pages(fs_pages, fil, banks, bbt_map)
    for p, d in meta.items():
        with open(path(p), "wb") as fh:
            fh.write(d)
    written = 0
    with open(volume, "rb") as vf:
        for lbn in range(blocks):
            first = lbn * sb
            skip = max(0, FIRST_LBA - first)
            vf.seek((first + skip - FIRST_LBA) * PAGE)
            n = (sb - skip) * PAGE
            data = vf.read(n)
            data += bytes(n - len(data))
            for i in range(sb - skip):
                lpn = first + skip + i
                with open(path(location_lpn(lpn, banks)), "wb") as fh:
                    fh.write(data[i * PAGE:(i + 1) * PAGE] + data_spare(lpn))
                written += 1
            if progress:
                progress(lbn + 1, blocks)
    return written, len(meta)



def nand_extract(nand_dir, out):
    """Rebuild the flat HFS+ volume image from a page directory made by write_nand (the base image only:
    pages the guest wrote later live in the emulator's overlay and are not followed)."""
    banks = len([d for d in os.listdir(nand_dir) if d.startswith("bank")])
    if not banks:
        raise FirmwareError("%s has no bank<N> directories" % nand_dir)

    def page(lpn):
        b, p = location_lpn(lpn, banks)
        path = os.path.join(nand_dir, "bank%d" % b, "%d.page" % p)
        if not os.path.exists(path):
            return bytes(PAGE)
        with open(path, "rb") as f:
            return f.read(PAGE).ljust(PAGE, b"\0")

    mbr = page(0)
    if mbr[0x1FE:0x200] != b"\x55\xaa":
        raise FirmwareError("no MBR at logical page 0")
    start, count = le32(mbr, 0x1BE + 8), le32(mbr, 0x1BE + 12)
    with open(out, "wb") as f:
        for i in range(count):
            f.write(page(start + i))
    return count


# ---------------------------------------------------------------------------------------------
# Identity (own synthesis; the Swift tool derives its fields from a seed the same way in spirit)
# ---------------------------------------------------------------------------------------------

SERIAL_CHARS = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10


def synthesize_iphone(seed, model="MA501", region="LL/A"):
    h = hashlib.sha256(seed.encode()).digest()
    serial = "".join(SERIAL_CHARS[x % len(SERIAL_CHARS)] for x in h[0:11])
    wifi = bytes([0x02]) + h[28:32] + bytes([h[27] & 0xFE])
    bt = wifi[:5] + bytes([wifi[5] + 1])
    mac = lambda b: ":".join("%02x" % x for x in b)
    bh = hashlib.sha256(("battery:" + seed).encode()).digest()
    battery = "".join(str(x % 10) for x in bh[:12])
    ih = hashlib.sha256(("imei:" + seed).encode()).digest()
    imei14 = "00000000" + "".join(str(x % 10) for x in ih[:6])  # TAC 00000000: assigned to no real device
    imei = imei14 + str(luhn(imei14))
    udid = hashlib.sha1((serial + imei + mac(wifi) + mac(bt)).encode()).hexdigest()
    return {
        "serial-number": serial, "imei": imei, "wifi-mac": mac(wifi), "bt-mac": mac(bt),
        "battery-serial": battery, "model-number": model, "region-info": region, "seed": seed, "udid": udid,
    }


# ---------------------------------------------------------------------------------------------
# IPSW, Restore.plist, rootfs decrypt, DMG -> HFS+ slice
# ---------------------------------------------------------------------------------------------


class IPSW:
    def __init__(self, path):
        self.z = zipfile.ZipFile(path)

    def names(self):
        return self.z.namelist()

    def read(self, n):
        return self.z.read(n)

    def open(self, n):
        return self.z.open(n)


def restore_info(ipsw):
    p = plistlib.loads(ipsw.read("Restore.plist"))
    maps = p["DeviceMap"]
    m = next((x for x in maps if not x.get("BoardConfig", "").endswith("xall")), maps[0])
    kc = ((p.get("KernelCachesByPlatform") or {}).get(m.get("Platform", "")) or {}).get("Release") or (
        p.get("RestoreKernelCaches") or {}
    ).get("Release")
    return {
        "board": m["BoardConfig"], "platform": m.get("Platform", ""), "product": p["ProductType"],
        "version": p["ProductVersion"], "build": p["ProductBuildVersion"], "kernelcache": kc,
        "system_image": (p.get("SystemRestoreImages") or {}).get("User"),
    }


def read_full(f, n):
    b = bytearray()
    while len(b) < n:
        c = f.read(n - len(b))
        if not c:
            break
        b += c
    return bytes(b)


def vfdecrypt(src, dst, key36):
    """Apple 'encrcdsa' v2 image, AES-128 key + HMAC-SHA1 key (36 bytes); chunk n's IV is
    HMAC-SHA1(hmac_key, be32(n))[:16].  Streams `src` (a file object) front to back."""
    if len(key36) != 36:
        raise FirmwareError("vfdecrypt key must be 36 bytes, got %d" % len(key36))
    aes_key, hmac_key = key36[:16], key36[16:]
    header = read_full(src, 0x100)
    if len(header) != 0x100 or header[:8] != b"encrcdsa":
        raise FirmwareError("not encrcdsa")
    bs = int.from_bytes(header[52:56], "big")
    left = int.from_bytes(header[56:64], "big")
    data_off = int.from_bytes(header[64:72], "big")
    if bs <= 0 or bs % 16 or bs > 1 << 24:
        raise FirmwareError("encrcdsa block size %d" % bs)
    carried = b""
    if data_off < 0x100:
        carried = header[data_off:0x100]
    else:
        skip = data_off - 0x100
        while skip > 0:
            c = src.read(min(skip, bs))
            if not c:
                raise FirmwareError("short image")
            skip -= len(c)
    n = 0
    while left > 0:
        ct = carried + read_full(src, bs - len(carried))
        carried = b""
        if not ct:
            raise FirmwareError("short image")
        if len(ct) % 16:
            raise FirmwareError("encrcdsa chunk %d is %d bytes, not whole AES blocks" % (n, len(ct)))
        iv = hmac.new(hmac_key, struct.pack(">I", n), hashlib.sha1).digest()[:16]
        pt = aes_cbc(ct, aes_key, iv)
        take = min(len(pt), left)
        dst.write(pt[:take])
        left -= take
        n += 1


def apm_hfs_slice(raw):
    """(byte offset, byte length) of the Apple_HFS(X) partition in an Apple Partition Map."""
    if len(raw) < 4 or raw[0] != 0x45 or raw[1] != 0x52:
        raise FirmwareError("not an Apple partition map")
    bs = raw[2] << 8 | raw[3]
    n = int.from_bytes(raw[bs + 4:bs + 8], "big")
    for i in range(1, max(n, 1) + 1):
        e = bs * i
        if e + 80 > len(raw):
            break
        typ = raw[e + 48:e + 80].split(b"\0")[0]
        if typ in (b"Apple_HFSX", b"Apple_HFS"):
            return (int.from_bytes(raw[e + 8:e + 12], "big") * bs, int.from_bytes(raw[e + 12:e + 16], "big") * bs)
    raise FirmwareError("no Apple_HFS(X) partition")


def extract_rootfs(dmg, out, work):
    """The raw HFS+ volume out of a (decrypted) rootfs DMG: a bare volume is copied; a UDIF image
    is converted to raw (dmg2img, else 7z) and its Apple_HFS(X) partition copied out."""
    with open(dmg, "rb") as f:
        f.seek(1024)
        if f.read(2) in (b"H+", b"HX"):
            with open(dmg, "rb") as s, open(out, "wb") as o:
                while True:
                    c = s.read(1 << 24)
                    if not c:
                        break
                    o.write(c)
            return
    raw = os.path.join(work, "raw.img")
    d7 = os.path.join(work, "7z")
    try:
        if subprocess.run(["which", "dmg2img"], capture_output=True).returncode == 0:
            subprocess.run(["dmg2img", "-i", dmg, "-o", raw], check=True, stdout=subprocess.DEVNULL)
        elif subprocess.run(["which", "7z"], capture_output=True).returncode == 0:
            os.makedirs(d7, exist_ok=True)
            subprocess.run(["7z", "x", "-y", "-o" + d7, dmg], check=True, stdout=subprocess.DEVNULL)
            cands = sorted((os.path.getsize(os.path.join(d7, f)), f) for f in os.listdir(d7))
            if not cands:
                raise FirmwareError("7z extracted nothing from the DMG")
            os.replace(os.path.join(d7, cands[-1][1]), raw)
        else:
            raise FirmwareError("need dmg2img or 7z to convert the UDIF rootfs")
        with open(raw, "rb") as f:
            head = f.read(64 * 512)
            f.seek(1024)
            if f.read(2) in (b"H+", b"HX"):
                os.replace(raw, out)
                return
            off, ln = apm_hfs_slice(head)
            f.seek(off)
            with open(out, "wb") as o:
                left = ln
                while left > 0:
                    c = f.read(min(left, 1 << 24))
                    if not c:
                        raise FirmwareError("raw image ends inside its HFS partition")
                    o.write(c)
                    left -= len(c)
    finally:
        if os.path.exists(raw):
            try:
                os.remove(raw)
            except OSError:
                pass
        if os.path.exists(d7):
            shutil.rmtree(d7, ignore_errors=True)


# ---------------------------------------------------------------------------------------------
# HFS+ grow (VolumeMount.grow + what hdiutil resize does that Linux lacks)
# ---------------------------------------------------------------------------------------------

VH = 1024
# volume header fields (big-endian)
_O_ATTR, _O_BS, _O_TOTAL, _O_FREE, _O_NEXTALLOC, _O_WRITECOUNT = 4, 40, 44, 48, 52, 68
_O_ALLOC = 112  # allocation file ForkData: size u64, clump u32, totalBlocks u32, 8 x (start, count)


def be32(b, o):
    return int.from_bytes(b[o:o + 4], "big")


def be64(b, o):
    return int.from_bytes(b[o:o + 8], "big")


def hfs_grow(path, new_bytes):
    """Grow an HFS+/HFSX volume image in place to `new_bytes`: allocation bitmap extended (the
    allocation file is moved into the new space if it must grow), volume header updated, the
    alternate header moved to the new end - 1024."""
    with open(path, "r+b") as f:
        f.seek(VH)
        vh = bytearray(f.read(512))
        if vh[0:2] not in (b"H+", b"HX"):
            raise FirmwareError("not an HFS+ volume")
        bs, old_total = be32(vh, _O_BS), be32(vh, _O_TOTAL)
        new_total = new_bytes // bs
        file_size = os.path.getsize(path)
        if new_total * bs != new_bytes:
            raise FirmwareError("%d bytes is not a whole number of %d-byte allocation blocks" % (new_bytes, bs))
        if new_total < old_total:
            raise FirmwareError("volume is already larger than %d bytes" % new_bytes)
        if new_total == old_total:
            return
        # the alternate volume header: at the end of the volume, or at the end of the file
        old_avh = None
        for cand in (old_total * bs - 1024, file_size - 1024):
            if cand > VH:
                f.seek(cand)
                if f.read(4) == bytes(vh[0:4]):
                    old_avh = cand
                    break
        # allocation file
        a_size, a_clump, a_blocks = be64(vh, _O_ALLOC), be32(vh, _O_ALLOC + 8), be32(vh, _O_ALLOC + 12)
        extents = [(be32(vh, _O_ALLOC + 16 + 8 * i), be32(vh, _O_ALLOC + 20 + 8 * i)) for i in range(8)]
        extents = [(s, c) for s, c in extents if c]
        if sum(c for _, c in extents) != a_blocks:
            raise FirmwareError("allocation file has extents in the overflow file; not supported")
        cap = bytearray()
        for s, c in extents:
            f.seek(s * bs)
            cap += f.read(c * bs)
        bits = bytearray(cap)
        need_bytes = (new_total + 7) // 8
        need_blocks = (need_bytes + bs - 1) // bs
        if len(bits) < need_blocks * bs:
            bits += bytes(need_blocks * bs - len(bits))
        used = lambda i: bits[i >> 3] & (0x80 >> (i & 7))

        def setbit(i):
            bits[i >> 3] |= 0x80 >> (i & 7)

        def clrbit(i):
            bits[i >> 3] &= ~(0x80 >> (i & 7)) & 0xFF

        # the old reserved last block (it held the alternate header) becomes ordinary space
        if old_avh is not None and old_avh // bs == old_total - 1:
            clrbit(old_total - 1)
        new_extents = extents
        new_a_blocks = a_blocks
        if need_blocks > a_blocks:
            # relocate the allocation file into the new space (first free run after the old end)
            start = old_total
            for i in range(start, start + need_blocks):
                if used(i):
                    raise FirmwareError("new space is not free")
            for s, c in extents:
                for i in range(s, s + c):
                    clrbit(i)
            for i in range(start, start + need_blocks):
                setbit(i)
            new_extents = [(start, need_blocks)]
            new_a_blocks = need_blocks
        setbit(new_total - 1)  # the new last block holds the alternate header
        free = sum(1 for i in range(new_total) if not used(i))
        # write the bitmap
        if len(new_extents) == 1 and new_extents[0][1] * bs > len(bits):
            bits += bytes(new_extents[0][1] * bs - len(bits))
        f.truncate(new_bytes)
        pos = 0
        for s, c in new_extents:
            f.seek(s * bs)
            f.write(bytes(bits[pos:pos + c * bs]))
            pos += c * bs
        # header
        struct.pack_into(">I", vh, _O_TOTAL, new_total)
        struct.pack_into(">I", vh, _O_FREE, free)
        struct.pack_into(">I", vh, _O_WRITECOUNT, (be32(vh, _O_WRITECOUNT) + 1) & 0xFFFFFFFF)
        if new_a_blocks != a_blocks or new_extents != extents:
            struct.pack_into(">Q", vh, _O_ALLOC, new_a_blocks * bs)
            struct.pack_into(">I", vh, _O_ALLOC + 12, new_a_blocks)
            for i in range(8):
                s, c = new_extents[i] if i < len(new_extents) else (0, 0)
                struct.pack_into(">II", vh, _O_ALLOC + 16 + 8 * i, s, c)
        if old_avh is not None:
            f.seek(old_avh)
            f.write(bytes(512))
        f.seek(VH)
        f.write(bytes(vh))
        f.seek(new_bytes - 1024)
        f.write(bytes(vh))


# ---------------------------------------------------------------------------------------------
# kernelcache path, volume edits (SystemEdits / N45Board.volumes) through a Linux hfsplus mount
# ---------------------------------------------------------------------------------------------

KC_PREFIX = b"/System/Library/Caches/com.apple.kernelcaches/"
FSTAB_RW = "/dev/disk0s1 / hfs rw 0 1\n"
DAEMONS = "System/Library/LaunchDaemons"
KEPT_DAEMONS = {
    "com.apple.AddressBook.plist", "com.apple.CommCenter.plist", "com.apple.configd.plist",
    "com.apple.mDNSResponder.plist", "com.apple.mobile.lockdown.plist", "com.apple.notifyd.plist",
    "com.apple.SpringBoard.plist", "com.apple.usbptpd.plist", "coreaudiod.plist",
}
KEPT_WHEN_SHIPPED = {"com.apple.mobile.lockbot.plist"}
IPHONE_DAEMONS = {"com.apple.BTServer.plist"}
ROOT_LIBRARY = "private/var/root/Library"
SPRINGBOARD = "System/Library/CoreServices/SpringBoard.app/SpringBoard"
PREFS_BAKED = [
    ("SBDidShowReorderText", True), ("SBBacklightLevel2", 1.0), ("SBBacklightLevel", 1.0),
    ("SBAutoLockTime", -1), ("SBAutoDimTime", -1), ("SBHideACPower", True),
    ("SBEnableALS", False), ("SBShowBatteryPercentage", False),
]


def kernelcache_path(iboot):
    hits = set()
    i = 0
    while True:
        r = iboot.find(KC_PREFIX, i)
        if r < 0:
            break
        j = r + len(KC_PREFIX)
        while j < len(iboot) and 0x21 <= iboot[j] <= 0x7E:
            j += 1
        if j > r + len(KC_PREFIX):
            hits.add(iboot[r + 1:j].decode())
        i = r + len(KC_PREFIX)
    if len(hits) != 1:
        raise FirmwareError("iBoot names %d kernelcache paths (%s); expected exactly one" % (len(hits), sorted(hits)))
    return hits.pop()


def removed_daemons(jobs, iphone=True):
    return sorted(j for j in jobs if j not in KEPT_DAEMONS and j not in KEPT_WHEN_SHIPPED
                  and not (iphone and j in IPHONE_DAEMONS))


def _put(path, data, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    if mode is not None:
        os.chmod(path, mode)


def _load_plist(path):
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return None


def make_log_dirs(m, jobs):
    made = []
    for job in sorted(jobs):
        d = _load_plist(os.path.join(m, DAEMONS, job))
        if not isinstance(d, dict):
            continue
        for key in ("StandardOutPath", "StandardErrorPath"):
            p = d.get(key)
            if not isinstance(p, str) or not p.startswith("/"):
                continue
            dirn = os.path.dirname(p)[1:]
            if dirn.startswith("var/"):
                dirn = "private/" + dirn
            if dirn and dirn not in made and not os.path.exists(os.path.join(m, dirn)):
                os.makedirs(os.path.join(m, dirn), exist_ok=True)
                made.append(dirn)
    return made


def springboard_user(m):
    d = _load_plist(os.path.join(m, DAEMONS, "com.apple.SpringBoard.plist"))
    if isinstance(d, dict) and d.get("UserName") == "mobile":
        return ("private/var/mobile/Library", 501)
    return (ROOT_LIBRARY, 0)


def seed_plist(path, edit):
    d = _load_plist(path) if os.path.exists(path) else {}
    d = d if isinstance(d, dict) else {}
    edit(d)
    _put(path, plistlib.dumps(d, fmt=plistlib.FMT_XML))


def edit_volume(m, iboot, ipsw, kc_member, log=print, activate=True):
    """N45Board.volumes' edits, over a mounted writable volume `m` (the parts that need no helper
    binaries).  Returns a report dict."""
    rep = {}
    kc_path = kernelcache_path(iboot)
    rep["kernelcache_path"] = kc_path
    _put(os.path.join(m, "private/etc/fstab"), FSTAB_RW.encode())
    kc_dst = os.path.join(m, kc_path)
    restore_only = ".restore." in os.path.basename(kc_member)
    if not (restore_only and os.path.exists(kc_dst)):
        _put(kc_dst, ipsw.read(kc_member))
    jobs = [j for j in os.listdir(os.path.join(m, DAEMONS)) if j.endswith(".plist")]
    absent = sorted(KEPT_DAEMONS - set(jobs))
    if absent:
        log("warning: this firmware ships no %s" % ", ".join(absent))
    gone = removed_daemons(jobs)
    for j in gone:
        os.remove(os.path.join(m, DAEMONS, j))
    rep["launch_daemons_removed"] = gone
    rep["log_dirs_made"] = make_log_dirs(m, [j for j in jobs if j not in gone])
    for d in ("", "/AddressBook", "/Lockdown", "/Preferences", "/Preferences/SystemConfiguration"):
        os.makedirs(os.path.join(m, ROOT_LIBRARY + d), exist_ok=True)
    for d, mode in (("private/var/run", 0o755), ("private/var/tmp", 0o1777)):  # only if the image lacks them
        full = os.path.join(m, d)
        if not os.path.isdir(full):
            os.makedirs(full, exist_ok=True)
            os.chmod(full, mode)
            rep.setdefault("dirs_created", []).append(d)
    _put(os.path.join(m, ROOT_LIBRARY, "Lockdown/data_ark.plist"),
         plistlib.dumps({"-BrickState": False}, fmt=plistlib.FMT_XML), 0o600)
    lib, uid = springboard_user(m)
    sbp = None
    try:
        with open(os.path.join(m, SPRINGBOARD), "rb") as f:
            sbp = f.read()
    except OSError:
        pass
    prefs_path = os.path.join(m, lib, "Preferences/com.apple.springboard.plist")
    if sbp is not None:
        named = [(k, v) for k, v in PREFS_BAKED if (k + "\0").encode() in sbp]
        if (b"SBDisableIdleSleep\0" in sbp):
            named.append(("SBDisableIdleSleep", True))
        if named:
            def edit(d):
                for k, v in named:
                    d[k] = v
            seed_plist(prefs_path, edit)
            if uid:
                os.chown(prefs_path, uid, uid)
        rep["prefs"] = [k for k, _ in named]
    if activate:
        rep["activation"] = activate_volume(m, log)
    return rep


def require_root(what):
    """Loop-mounting needs root.  sudo is never used from here (no terminal to ask on, so it hangs or fails
    unpredictably): run firmwarekit as root, or start it through manageFirm, which uses pkexec."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise FirmwareError("%s needs root: run firmwarekit as root (e.g. `pkexec env PATH=$PATH python3 "
                            "firmwarekit.py create ...`), or create the device from manageFirm.py, which asks "
                            "for it through pkexec" % what)


def with_mounted(volume, mnt, fn, rw=True):
    """Loop-mount `volume` (HFS+) at `mnt`, run fn(mnt), unmount.  rw=False mounts it read-only (a journaled
    volume then mounts too, and nothing on it is touched)."""
    require_root("mounting the volume " + ("read-write" if rw else "read-only"))
    os.makedirs(mnt, exist_ok=True)
    r = subprocess.run(["mount", "-t", "hfsplus", "-o", "loop,rw,force" if rw else "loop,ro", volume, mnt],
                       capture_output=True, text=True)
    if r.returncode:
        raise FirmwareError("mounting the volume %s failed (need the Linux hfsplus "
                            "module; a journaled volume mounts read-only): %s"
                            % ("read-write" if rw else "read-only", r.stderr.strip()))
    try:
        return fn(mnt)
    finally:
        subprocess.run(["sync"])
        subprocess.run(["umount", mnt], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---------------------------------------------------------------------------------------------
# Activation: the lockdownd patch (port of FirmwareKit's CActivation/activation.c)
# ---------------------------------------------------------------------------------------------
#
# Pattern-based, no firmware offsets: finds the single place in a 32-bit ARM Mach-O lockdownd where
# "no activation record" or the activation check is decided and makes it report Activated.  For
# iPhone OS 1.0 that is `conditional_initializer`:
#     cmp rN, #0 ; moveq flag, #1 ; ldreq state, =Unactivated ; ... ; beq store
# changed to  `moveq flag, #0 ; ldreq state, =Activated`.  A present record is verified as before.
#
# Scope: every path activation.c knows.  The 1.x (unsigned) initializer is patched in place and left
# unsigned.  A lockdownd that carries LC_CODE_SIGNATURE, or a match that is not a legacy initializer
# (signed-era firmware: iOS 2.x-5.x, the A4 boards), is re-signed after the patch the way FirmwareKit's
# Activation.signed does: every code-directory page hash is recomputed, CS_ADHOC is set, and the CMS blob
# (which the patch invalidates) is dropped.  Size and signing allocation do not change.

ACT_MESSAGE = b"Short circuiting activation state to Activated.\0"
ACT_FUNCTION = "dealwith_activation"
M32 = 0xFFFFFFFF


class ActivationError(FirmwareError):
    pass


def _sext(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def _b24(ins):
    """An ARM B/BL's byte displacement: sign-extended 24-bit word offset * 4."""
    return _sext(ins & 0xFFFFFF, 24) * 4


class _Match:
    __slots__ = ("off", "va", "target", "width", "isa", "replacement", "legacy", "shared_no_record", "conditional")

    def __init__(self, **kw):
        self.off = self.va = self.target = self.width = 0
        self.isa = ""
        self.replacement = b""
        self.legacy = self.shared_no_record = self.conditional = False
        for k, v in kw.items():
            setattr(self, k, v)


class _Image:
    def __init__(self, data):
        self.n = len(data)
        self.b = bytes(data) + bytes(64)  # padding so a stray read past the end is zeros, not an exception
        self.segments = []
        self.text_va = self.text_size = self.text_off = self.message_va = 0
        self.sig = None  # LC_CODE_SIGNATURE (dataoff, datasize), if the binary carries one

    def u16(self, o):
        return self.b[o] | self.b[o + 1] << 8

    def u32(self, o):
        b = self.b
        return b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24

    @staticmethod
    def fits(off, n, size):
        return off <= size and n <= size - off

    def fileoff(self, va, n):
        result = None
        for (sva, ssize, soff) in self.segments:
            if va >= sva and self.fits(va - sva, n, ssize):
                if result is not None:
                    return None
                result = soff + va - sva
        return result

    def word(self, va):
        o = self.fileoff(va, 4)
        return None if o is None else self.u32(o)

    def text_address(self, va, n):
        return va >= self.text_va and self.fits(va - self.text_va, n, self.text_size)

    def cstring(self, va, s):
        raw = s.encode() + b"\0"
        o = self.fileoff(va, len(raw))
        return o is not None and self.b[o:o + len(raw)] == raw

    def cfstring(self, va, text):
        o = self.fileoff(va, 16)
        return (o is not None and self.u32(o + 4) == 0x7C8 and self.u32(o + 12) == len(text)
                and self.cstring(self.u32(o + 8), text))

    def log_message(self, va):
        if not self.message_va:
            return False
        if va == self.message_va:
            return True
        o = self.fileoff(va, 16)
        return (o is not None and self.u32(o + 4) == 0x7C8 and self.u32(o + 8) == self.message_va
                and self.u32(o + 12) == len(ACT_MESSAGE) - 1)

    def arm_literal(self, pc, ins):
        if ins & 0xFF7F0000 != 0xE51F0000:
            return None
        addr = (pc + 8) & M32
        addr = (addr + (ins & 4095)) & M32 if ins & 0x800000 else (addr - (ins & 4095)) & M32
        return self.word(addr)


def _act_parse(m):
    d, n = m.b, m.n
    if n < 28 or m.u32(0) != 0xFEEDFACE or m.u32(4) != 12 or m.u32(12) != 2:
        seen = ("magic 0x%08x, cputype %d, filetype %d" % (m.u32(0), m.u32(4), m.u32(12))) if n >= 16 else "%d bytes" % n
        raise ActivationError("expected a thin little-endian 32-bit ARM Mach-O executable (found %s)" % seen)
    count, commands = m.u32(16), m.u32(20)
    if not m.fits(28, commands, n) or count > commands // 8:
        raise ActivationError("invalid load commands")
    o, end, texts = 28, 28 + commands, 0

    def named(p, s):
        raw = s.encode()
        return len(raw) < 16 and d[p:p + len(raw)] == raw and d[p + len(raw)] == 0

    for _ in range(count):
        if not m.fits(o, 8, end):
            raise ActivationError("truncated load command")
        cmd, ln = m.u32(o), m.u32(o + 4)
        if ln < 8 or ln % 4 or not m.fits(o, ln, end):
            raise ActivationError("invalid load command size")
        if cmd == 0x1D:
            if ln < 16 or m.sig is not None:
                raise ActivationError("invalid code signature load command")
            m.sig = (m.u32(o + 8), m.u32(o + 12))
        if cmd == 1:
            if ln < 56:
                raise ActivationError("truncated segment")
            va, vs, off, fs, ns = m.u32(o + 24), m.u32(o + 28), m.u32(o + 32), m.u32(o + 36), m.u32(o + 48)
            if ns > (ln - 56) // 68 or not m.fits(off, fs, n) or fs > vs or va + vs > 0x100000000:
                raise ActivationError("invalid segment bounds")
            if fs:
                if len(m.segments) == 64:
                    raise ActivationError("too many segments")
                for (sva, ssize, _soff) in m.segments:
                    if va < sva + ssize and sva < va + fs:
                        raise ActivationError("overlapping mapped segments")
                m.segments.append((va, fs, off))
            for j in range(ns):
                s = o + 56 + 68 * j
                if named(s, "__text") and named(s + 16, "__TEXT"):
                    a, z, f = m.u32(s + 32), m.u32(s + 36), m.u32(s + 40)
                    if (not named(o + 8, "__TEXT") or a < va or f < off or not z or not m.fits(a - va, z, fs)
                            or not m.fits(f - off, z, fs) or a - va != f - off):
                        raise ActivationError("invalid text section")
                    m.text_va, m.text_size, m.text_off = a, z, f
                    texts += 1
        o += ln
    if o != end or texts != 1:
        raise ActivationError("expected exactly one valid text section")
    hits, found, i = 0, -1, d.find(ACT_MESSAGE, 0, n)
    while i >= 0:
        hits += 1
        found = i
        i = d.find(ACT_MESSAGE, i + 1, n)
    if hits > 1:
        raise ActivationError("ambiguous activation log strings")
    if not hits:
        return
    hits = 0
    for (sva, ssize, soff) in m.segments:
        if found >= soff and m.fits(found - soff, len(ACT_MESSAGE), ssize):
            m.message_va = sva + (found - soff)
            hits += 1
    if hits != 1:
        raise ActivationError("activation string has no unique mapped address")


def _log_block(m, pc, thumb):
    """Straight-line argument construction ending in a direct log call.  -> (ok, address after the call)."""
    regs, known, after = [0] * 16, 0, 0
    for _ in range(16):
        if not m.text_address(pc, 2 if thumb else 4):
            return False, after
        o = m.fileoff(pc, 2 if thumb else 4)
        if o is None:
            return False, after
        ins = m.u16(o) if thumb else m.u32(o)
        if thumb:
            if ins & 0xFBF0 in (0xF240, 0xF2C0):  # MOVW / MOVT T3
                if not m.text_address(pc, 4):
                    return False, after
                hi = m.u16(o + 2)
                rd = (hi >> 8) & 15
                if hi & 0x8000 or rd == 15:
                    return False, after
                imm = ((ins & 15) << 12) | (((ins >> 10) & 1) << 11) | (((hi >> 12) & 7) << 8) | (hi & 255)
                if ins & 0xFBF0 == 0xF2C0:
                    if not known & (1 << rd):
                        return False, after
                    regs[rd] = ((regs[rd] & 65535) | (imm << 16)) & M32
                else:
                    regs[rd] = imm
                known |= 1 << rd
                pc = (pc + 4) & M32
            elif ins & 0xF800 == 0x2000:  # MOVS immediate
                rd = (ins >> 8) & 7
                regs[rd] = ins & 255
                known |= 1 << rd
                pc = (pc + 2) & M32
            elif ins & 0xF800 == 0x4800:  # LDR literal T1
                rd = (ins >> 8) & 7
                val = m.word((((pc + 4) & ~3) + 4 * (ins & 255)) & M32)
                if val is None:
                    return False, after
                regs[rd] = val
                known |= 1 << rd
                pc = (pc + 2) & M32
            elif ins in (0xF8DF, 0xF85F):  # LDR literal T2
                if not m.text_address(pc, 4):
                    return False, after
                hi = m.u16(o + 2)
                rd = hi >> 12
                if rd == 15:
                    return False, after
                addr = (pc + 4) & ~3 & M32
                addr = (addr + (hi & 4095)) & M32 if ins == 0xF8DF else (addr - (hi & 4095)) & M32
                val = m.word(addr)
                if val is None:
                    return False, after
                regs[rd] = val
                known |= 1 << rd
                pc = (pc + 4) & M32
            elif ins & 0xF800 == 0x6800:  # LDR immediate T1: never evidence
                known &= ~(1 << (ins & 7))
                pc = (pc + 2) & M32
            elif ins & 0xFF00 == 0x4400:  # ADD high register, PC
                rd = (ins & 7) | ((ins >> 4) & 8)
                rm = (ins >> 3) & 15
                if rm != 15 or rd == 15 or not known & (1 << rd):
                    return False, after
                regs[rd] = (regs[rd] + pc + 4) & M32
                pc = (pc + 2) & M32
            elif ins & 0xF800 == 0xF000 and m.text_address(pc, 4) and m.u16(o + 2) & 0xD000 == 0xD000:
                hi = m.u16(o + 2)  # BL immediate T1
                s, j1, j2 = (ins >> 10) & 1, (hi >> 13) & 1, (hi >> 11) & 1
                imm = ((s << 24) | ((0 if (j1 ^ s) else 1) << 23) | ((0 if (j2 ^ s) else 1) << 22)
                       | ((ins & 1023) << 12) | ((hi & 2047) << 1))
                delta = _sext(imm, 25)
                if not m.text_address((pc + 4 + delta) & M32, 2):
                    return False, after
                after = (pc + 4) & M32
                break
            else:
                return False, after
        else:
            if ins & 0xFF7F0000 == 0xE51F0000:  # unconditional LDR literal
                rd = (ins >> 12) & 15
                if rd == 15:
                    return False, after
                addr = (pc + 8) & M32
                addr = (addr + (ins & 4095)) & M32 if ins & (1 << 23) else (addr - (ins & 4095)) & M32
                val = m.word(addr)
                if val is None:
                    return False, after
                regs[rd] = val
                known |= 1 << rd
                pc = (pc + 4) & M32
            elif ins & 0xFFF00000 == 0xE0800000 and not ins & 0x00000FF0:  # ADD register, no shifts
                rd, rn, rm = (ins >> 12) & 15, (ins >> 16) & 15, ins & 15
                if rd == 15 or (rn != 15 and not known & (1 << rn)) or (rm != 15 and not known & (1 << rm)):
                    return False, after
                regs[rd] = ((pc + 8 if rn == 15 else regs[rn]) + (pc + 8 if rm == 15 else regs[rm])) & M32
                known |= 1 << rd
                pc = (pc + 4) & M32
            elif ins & 0xFF000000 == 0xEB000000:  # BL immediate
                if not m.text_address((pc + 8 + _b24(ins)) & M32, 4):
                    return False, after
                after = (pc + 4) & M32
                break
            else:
                return False, after
    ok = bool(after) and (
        (known & 3 == 3 and m.cstring(regs[0], ACT_FUNCTION) and m.log_message(regs[1]))
        or (known & 7 == 7 and regs[0] == 0 and m.cstring(regs[1], ACT_FUNCTION) and m.log_message(regs[2]))
    )
    return ok, after


def _bounded(frm, target):
    return abs(target - frm) <= 4096


def _stack_store(ins, reg):
    return ins & 0xFFF if ins & 0xFFFFF000 == (0xE58D0000 | (reg << 12)) else None


def _nearby_function(m, va):
    start = va - 4096 if va > 4096 else 0
    for p in range(start, va, 4):
        if m.text_address(p, 4):
            ins = m.word(p)
            if ins is not None:
                value = m.arm_literal(p, ins)
                if value is not None and m.cstring(value, "determine_activation_state"):
                    return True
    return False


def _activated_literal_pc(m, va):
    """The nearest word in .text, within reach of `va`, that points at the Activated CFString."""
    best, literal = None, None
    for r in range(0, m.text_size - 3, 4):
        pc = m.text_va + r
        delta = pc - (va + 8)
        if abs(delta) <= 4095 and (best is None or abs(delta) < best) and m.cfstring(m.u32(m.text_off + r), "Activated"):
            best, literal = abs(delta), pc
    return literal


def _legacy_initializer(m, o, va):
    ins = m.u32(o)
    value = m.arm_literal(va, ins)
    if value is None or not m.cfstring(value, "Unactivated") or not _nearby_function(m, va):
        return None
    state = (ins >> 12) & 15
    if state >= 13 or not m.text_address(va, 24):
        return None
    a, b, c, e, jump = (m.u32(o + 4 * k) for k in range(1, 6))
    shared = False
    if a & 0xFFFF0FFF == 0xE3A00001:
        # early 1.x: the no-record state and brick boolean in stack slots
        flag = (a >> 12) & 15
        if flag >= 13 or flag == state or va < m.text_va + 12:
            return None
        slot1, slot2 = _stack_store(b, flag), _stack_store(c, state)
        if slot1 is None or slot2 is None or slot1 == slot2 or e & 0xFF000000 != 0xEA000000:
            return None
        cmp_, mov, guard = m.u32(o - 12), m.u32(o - 8), m.u32(o - 4)
        if (cmp_ & 0xFFF0FFFF != 0xE3500000 or mov & 0xFFFF0FF0 != 0xE1A00000 or guard & 0xFF000000 != 0x1A000000
                or (va + 4 + _b24(guard)) & M32 != va + 20):
            return None
        dest = (va + 24 + _b24(e)) & M32
        if not m.text_address(dest, 4) or dest <= va + 24 or not _bounded(va, dest):
            return None
        change = 4
    else:
        if c & 0xFFF00FFF != 0xE2800001:
            return None
        flag = (c >> 12) & 15
        if flag >= 13 or (c >> 16) & 15 != flag or state == flag or va < m.text_va + 8:
            return None
        slot1, slot2 = _stack_store(a, flag), _stack_store(b, flag)
        if slot1 is None or slot2 is None:
            return None
        if e & 0xFF000000 == 0xEA000000:
            shared = True
            if va < m.text_va + 36:
                return None
            cmp_, guard = m.u32(o - 36), m.u32(o - 32)
            fn = m.arm_literal((va - 28) & M32, m.u32(o - 28))
            msg = m.arm_literal((va - 24) & M32, m.u32(o - 24))
            if (cmp_ != (0xE3500000 | (flag << 16)) or guard & 0xFF000000 != 0x1A000000 or fn is None
                    or not m.cstring(fn, "determine_activation_state") or msg is None
                    or not m.cstring(msg, "There is no activation record?")
                    or m.u32(o - 20) & 0xFF000000 != 0xEB000000 or m.u32(o - 12) & 0xFF000000 != 0xEB000000
                    or m.u32(o - 8) != 0xE3500000 or m.u32(o - 4) & 0xFF000000 != 0x1A000000):
                return None
            dest = (va + 24 + _b24(e)) & M32
            if not m.text_address(dest, 4):
                return None
            store = m.word(dest)
            slot3 = None if store is None else _stack_store(store, state)
            if slot3 is None:
                return None
        else:
            cmp_, guard = m.u32(o - 8), m.u32(o - 4)
            slot3 = _stack_store(e, state)
            if (cmp_ != (0xE3500000 | (flag << 16)) or guard & 0xFF000000 != 0x1A000000
                    or (va + 4 + _b24(guard)) & M32 != va + 24 or slot3 is None or jump & 0xFF000000 != 0xEA000000):
                return None
            dest = (va + 28 + _b24(jump)) & M32
        change = 12
        if (slot1 == slot2 or slot1 == slot3 or slot2 == slot3 or not m.text_address(dest, 4)
                or dest <= va + 24 or not _bounded(va, dest)):
            return None
    literal = _activated_literal_pc(m, va)
    if literal is None:
        return None
    width = change + 4
    rep = bytearray(m.b[o:o + width])
    delta = literal - (va + 8)
    rep[0:4] = struct.pack("<I", 0xE51F0000 | (state << 12) | (0x800000 if delta >= 0 else 0) | abs(delta))
    rep[change:change + 4] = struct.pack("<I", 0xE3A00000 | (flag << 12))
    return _Match(off=o, va=va, target=dest, width=width, isa="arm", replacement=bytes(rep),
                  legacy=not shared, shared_no_record=shared)


def _conditional_initializer(m, o, va):
    """1.0 (1A543a): cmp rN,#0 ; moveq flag,#1 ; ldreq state,=Unactivated ; ... ; beq store."""
    ins = m.u32(o)
    if ins & 0xFF7F0000 != 0x051F0000 or va < m.text_va + 8 or not m.text_address(va, 16):
        return None
    value = m.arm_literal(va, ins | 0xE0000000)
    if value is None or not m.cfstring(value, "Unactivated"):
        return None
    cmp_, set_ = m.u32(o - 8), m.u32(o - 4)
    state, flag = (ins >> 12) & 15, (set_ >> 12) & 15
    if (cmp_ & 0xFFF0FFFF != 0xE3500000 or set_ & 0xFFFF0FFF != 0x03A00001 or state >= 13 or flag >= 13
            or state == flag or (cmp_ >> 16) & 15 == state):
        return None
    dest = 0
    k = 1
    while k <= 3 and not dest:
        b = m.u32(o + 4 * k)
        if b & 0xFF000000 == 0x0A000000:
            dest = (va + 4 * k + 8 + _b24(b)) & M32
        elif b & 0x0E000000 == 0x0A000000 or (b >> 12) & 15 == state or (b >> 12) & 15 == flag:
            return None  # other control flow, or the two values overwritten before the store
        k += 1
    if not dest or dest <= va or not _bounded(va, dest) or not m.text_address(dest, 4):
        return None
    logged, p = False, dest
    while p < dest + 1024 and m.text_address(p, 4) and not logged:
        w = m.word(p)
        if w is not None:
            v = m.arm_literal(p, w)
            logged = v is not None and m.cstring(v, "The activation state has not changed.")
        p += 4
    literal = _activated_literal_pc(m, va)
    if not logged or literal is None:
        return None
    delta = literal - (va + 8)
    load = (ins & 0xFF7FF000) | (0x800000 if delta >= 0 else 0) | abs(delta)
    rep = struct.pack("<II", 0x03A00000 | (flag << 12), load)
    return _Match(off=o - 4, va=va - 4, target=dest, width=8, isa="arm", replacement=rep,
                  legacy=True, conditional=True)


def _act_locate(m):
    result, count = None, 0
    rel = 0
    while m.fits(rel, 8, m.text_size):
        o, va = m.text_off + rel, m.text_va + rel
        cmp_, b = m.u16(o), m.u16(o + 2)
        width, target = 0, 0
        if cmp_ & 0xF800 == 0x2800 and cmp_ & 255 <= 1:
            if b & 0xFF00 == 0xD000:
                width = 2
                target = (va + 6 + _sext(b & 255, 8) * 2) & M32
            elif b & 0xFBC0 == 0xF000 and m.u16(o + 4) & 0xD000 == 0x8000:
                hi = m.u16(o + 4)
                imm = (((b >> 10) & 1) << 20) | (((hi >> 11) & 1) << 19) | (((hi >> 13) & 1) << 18) \
                    | ((b & 63) << 12) | ((hi & 2047) << 1)
                width = 4
                target = (va + 6 + _sext(imm, 21)) & M32
            if width and _bounded(va, target) and m.text_address(target, 2):
                ok, after = _log_block(m, va + 2 + width, True)
                fall = ok and (target < va or target >= after)
                take = (target < va or target > va + 2 + width) and _log_block(m, target, True)[0]
                if fall and take:
                    raise ActivationError("ambiguous branch destinations; file unchanged")
                if fall or take:
                    if fall:
                        rep = struct.pack("<H", 0xBF00) * (width // 2)
                    else:
                        delta = target - (va + 6)
                        if width == 2:
                            rep = struct.pack("<H", 0xE000 | ((delta >> 1) & 2047))
                        else:
                            imm = delta & M32
                            sign = (imm >> 24) & 1
                            rep = struct.pack("<HH", 0xF000 | (sign << 10) | ((imm >> 12) & 1023),
                                              0x9000 | ((0 if ((imm >> 23) & 1) ^ sign else 1) << 13)
                                              | ((0 if ((imm >> 22) & 1) ^ sign else 1) << 11) | ((imm >> 1) & 2047))
                    result = _Match(off=o + 2, va=va + 2, target=target, width=width, isa="thumb", replacement=rep)
                    count += 1
        if not m.message_va and not va & 3:
            leg = _legacy_initializer(m, o, va) or _conditional_initializer(m, o, va)
            if leg:
                result = leg
                count += 1
        if not va & 3 and m.fits(rel, 12, m.text_size):
            c, br = m.u32(o), m.u32(o + 4)
            if c & 0xFFF0FFFE == 0xE3500000 and br & 0xFF000000 == 0x0A000000:
                target = (va + 12 + _b24(br)) & M32
                if _bounded(va, target) and m.text_address(target, 4):
                    ok, after = _log_block(m, va + 8, False)
                    fall = ok and (target < va or target >= after)
                    take = (target < va or target > va + 8) and _log_block(m, target, False)[0]
                    if fall and take:
                        raise ActivationError("ambiguous branch destinations; file unchanged")
                    if fall or take:
                        word = 0xE1A00000 if fall else (br | 0xE0000000)
                        result = _Match(off=o + 4, va=va + 4, target=target, width=4, isa="arm",
                                        replacement=struct.pack("<I", word))
                        count += 1
        rel += 2
    if count != 1:
        raise ActivationError("ambiguous activation paths; file unchanged" if count
                              else "no supported activation path (or already patched); file unchanged")
    return result


def activation_strategy(match):
    return ("conditional-no-record-initializer" if match.conditional
            else "legacy-no-record-initializer" if match.legacy
            else "ipod-no-record-initializer" if match.shared_no_record
            else "development-activation-shortcut")


def _be32(b, o):
    return b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]


def resign_lockdownd(data, sig):
    """Port of FirmwareKit's Activation.signed: rebuild the existing code-directory page hashes as an
    ad-hoc signature, keeping entitlements and special-slot hashes.  The patch changes neither the size
    nor the signing allocation.  -> bytes.  Raises ActivationError before anything is returned."""
    b = bytearray(data)

    def invalid():
        return ActivationError("Unsupported code signature")

    start, size = sig
    if size < 12 or start > len(b) - size or _be32(b, start) != 0xFADE0CC0:
        raise invalid()
    length, count = _be32(b, start + 4), _be32(b, start + 8)
    if length < 12 or length > size or count > (length - 12) // 8:
        raise invalid()
    entries, directories = [], 0
    for i in range(count):
        typ, offset = _be32(b, start + 12 + i * 8), _be32(b, start + 16 + i * 8)
        if offset < 12 + count * 8 or offset > length - 8:
            raise invalid()
        blob = start + offset
        blob_len = _be32(b, blob + 4)
        if blob_len < 8 or blob_len > length - offset:
            raise invalid()
        if typ == 0 or 0x1000 <= typ <= 0x1005:  # CodeDirectory and its alternates
            if blob_len < 44 or _be32(b, blob) != 0xFADE0C02:
                raise invalid()
            hash_off, special = _be32(b, blob + 16), _be32(b, blob + 24)
            slots, limit = _be32(b, blob + 28), _be32(b, blob + 32)
            hash_size, hash_type, exponent = b[blob + 36], b[blob + 37], b[blob + 39]
            if not (0 < exponent <= 20 and 0 < limit <= start
                    and ((hash_type == 1 and hash_size == 20) or (hash_type == 2 and hash_size == 32))
                    and hash_off >= 44 + special * hash_size and hash_off <= blob_len
                    and slots <= (blob_len - hash_off) // hash_size):
                raise invalid()
            page = 1 << exponent
            if slots != (limit + page - 1) // page:
                raise invalid()
            if _be32(b, blob + 8) >= 0x20100:  # scatter layouts need a different page mapping
                if blob_len < 48 or _be32(b, blob + 44) != 0:
                    raise invalid()
            put_be = struct.pack_into
            put_be(">I", b, blob + 12, _be32(b, blob + 12) | 2)  # CS_ADHOC
            algo = hashlib.sha1 if hash_type == 1 else hashlib.sha256
            for slot in range(slots):
                digest = algo(bytes(b[slot * page:min(limit, (slot + 1) * page)])).digest()
                at = blob + hash_off + slot * hash_size
                b[at:at + hash_size] = digest
            directories += 1
        if typ != 0x10000:  # drop the now-invalid CMS signature
            entries.append((typ, offset))
    if directories == 0 or not any(t == 0 for t, _ in entries):
        raise invalid()
    for i in range(count):
        t, o = entries[i] if i < len(entries) else (0, 0)
        struct.pack_into(">II", b, start + 12 + i * 8, t, o)
    struct.pack_into(">I", b, start + 8, len(entries))
    return bytes(b)


def _activate_thin(data, allow_signed_era=True, resign=True):
    """-> (patched bytes, report).  Raises ActivationError (the input is never modified in place).
    A signed binary, or a signed-era match, comes back re-signed (ad hoc); the unsigned 1.x path stays
    unsigned.  allow_signed_era=False restores the 1.x-only behaviour; resign=False patches the bytes only,
    like the C original (activation.c leaves signing to the caller)."""
    m = _Image(data)
    _act_parse(m)
    match = _act_locate(m)
    if not match.legacy and not allow_signed_era:
        raise ActivationError("matched a signed-era path (%s); signed-era patching is disabled"
                              % activation_strategy(match))
    out = bytearray(data)
    out[match.off:match.off + match.width] = match.replacement
    resigned = False
    if resign and (not match.legacy or m.sig is not None):
        # Later paths still require a valid signature allocation; 1.x may stay unsigned.
        if m.sig is None:
            raise ActivationError("signed-era lockdownd has no code signature allocation to refresh")
        out = bytearray(resign_lockdownd(bytes(out), m.sig))
        resigned = True
    return bytes(out), {
        "strategy": activation_strategy(match), "isa": match.isa, "offset": match.off, "virtual_address": match.va,
        "width": match.width, "original": bytes(data[match.off:match.off + match.width]).hex(),
        "replacement": match.replacement.hex(), "resigned": resigned,
        "input_sha256": hashlib.sha256(data).hexdigest(), "output_sha256": hashlib.sha256(bytes(out)).hexdigest(),
    }


def _fat_arm_slices(data):
    """[(cpusubtype, offset, size)] of the 32-bit ARM slices of a fat (universal) Mach-O; None if `data`
    is not fat.  iOS 4.x system daemons ship as armv6 + armv7 fat binaries."""
    if len(data) < 8 or struct.unpack_from(">I", data, 0)[0] != 0xCAFEBABE:
        return None
    n = struct.unpack_from(">I", data, 4)[0]
    if not 0 < n <= 16 or 8 + 20 * n > len(data):
        raise ActivationError("invalid fat Mach-O header")
    out = []
    for i in range(n):
        cputype, subtype, off, size, _align = struct.unpack_from(">5I", data, 8 + 20 * i)
        if off + size > len(data) or size < 28:
            raise ActivationError("invalid fat Mach-O slice")
        if cputype == 12:
            out.append((subtype & 0x00FFFFFF, off, size))
    return out


def activate_lockdownd(data, allow_signed_era=True, resign=True):
    """-> (patched bytes, report).  Like _activate_thin, and also accepts a fat (armv6 + armv7) lockdownd:
    every 32-bit ARM slice is patched and re-signed in place, the file keeps its layout.  The newest slice
    (armv7, what the A4 boards run) must patch, or this raises; an older slice that cannot be patched is
    left stock and listed in report["skipped_slices"], since the newest CPU never executes it."""
    slices = _fat_arm_slices(data)
    if slices is None:
        return _activate_thin(data, allow_signed_era, resign)
    if not slices:
        raise ActivationError("fat Mach-O has no 32-bit ARM slice")
    newest = max(sub for sub, _off, _size in slices)
    out, rep, skipped = bytearray(data), None, []
    for sub, off, size in sorted(slices):
        try:
            patched, r = _activate_thin(bytes(data[off:off + size]), allow_signed_era, resign)
        except ActivationError as e:
            if sub == newest:
                raise ActivationError("armv%d slice: %s" % (sub, e))
            skipped.append("armv%d: %s" % (sub, e))
            continue
        if len(patched) != size:
            raise ActivationError("patched slice changed size")
        out[off:off + size] = patched
        if sub == newest:
            rep = dict(r, offset=r["offset"] + off, slice="armv%d" % sub)
    rep["skipped_slices"] = skipped
    rep["input_sha256"] = hashlib.sha256(data).hexdigest()
    rep["output_sha256"] = hashlib.sha256(bytes(out)).hexdigest()
    return bytes(out), rep


LOCKDOWND = "usr/libexec/lockdownd"


# --- HFS+ compression (decmpfs) -------------------------------------------------------------
#
# iOS 4.x rootfs files are stored HFS+-compressed: the data fork is empty, UF_COMPRESSED is set and
# the bytes live in the com.apple.decmpfs xattr (type 3, small files) or in the resource fork
# (type 4, everything bigger, including lockdownd).  The Linux hfsplus driver knows nothing about
# that, so a plain read() of lockdownd returns 0 bytes.  These helpers rebuild the real contents.

DECMPFS_XATTR = "osx.com.apple.decmpfs"
RSRC_XATTR = "osx.com.apple.ResourceFork"


def _getxattr(path, name):
    try:
        return os.getxattr(path, name)
    except (OSError, AttributeError):
        return None


def decmpfs_decode(hdr, rsrc=None):
    """Contents of a decmpfs-compressed file from its com.apple.decmpfs attribute `hdr` and, for type 4,
    its resource fork `rsrc` (a callable returning the bytes, or the bytes)."""
    if len(hdr) < 16 or hdr[:4] != b"fpmc":
        raise FirmwareError("com.apple.decmpfs attribute has a bad magic")
    ctype, usize = struct.unpack_from("<IQ", hdr, 4)
    if ctype in (1, 3):                       # 1: raw inline, 3: zlib inline (0xFF lead byte = stored)
        body = hdr[16:]
        if ctype == 1 or body[:1] == b"\xff":
            out = body[1:] if ctype == 3 else body
        else:
            out = zlib.decompress(body)
    elif ctype == 4:                          # zlib blocks of 64 KiB in the resource fork
        fork = rsrc() if callable(rsrc) else rsrc
        if not fork:
            raise FirmwareError("decmpfs type 4 file but its resource fork could not be read")
        base = struct.unpack_from(">I", fork, 0)[0]            # normally 0x100
        nblocks = struct.unpack_from("<I", fork, base + 4)[0]
        parts = []
        for i in range(nblocks):
            off, size = struct.unpack_from("<II", fork, base + 8 + 8 * i)
            blk = fork[base + 4 + off: base + 4 + off + size]
            parts.append(blk[1:] if blk[:1] == b"\xff" else zlib.decompress(blk))
        out = b"".join(parts)
    else:
        raise FirmwareError("decmpfs compression type %d is not supported (only 1, 3, 4)" % ctype)
    if len(out) != usize:
        raise FirmwareError("decmpfs size mismatch: header says %d bytes, decoded %d" % (usize, len(out)))
    return out


def _fork_from_extents(f, bsize, fork):
    """Bytes of an HFSPlusForkData `fork` read through its 8 inline extents."""
    lsize, _clump, total = struct.unpack_from(">QII", fork, 0)
    ext = [struct.unpack_from(">II", fork, 16 + 8 * i) for i in range(8)]
    if sum(c for _s, c in ext) < total:
        raise FirmwareError("fork needs extents-overflow records (fragmented), not supported")
    out = bytearray()
    for start, cnt in ext:
        if not cnt:
            break
        f.seek(start * bsize)
        out += f.read(cnt * bsize)
    return bytes(out[:lsize])


def _hfs_catalog_files(img):
    """Parse the catalog of a raw HFS+ volume image: {path: (fileID, resource-fork bytes loader)}."""
    with open(img, "rb") as f:
        f.seek(1024)
        vh = f.read(512)
        if vh[:2] not in (b"H+", b"HX"):
            raise FirmwareError("%s is not a raw HFS+ volume" % img)
        bsize = struct.unpack_from(">I", vh, 40)[0]

        def fork_bytes(fork):
            return _fork_from_extents(f, bsize, fork)

        cat = fork_bytes(vh[272:272 + 80])
        nsize = struct.unpack_from(">H", cat, 32)[0]
        node = struct.unpack_from(">I", cat, 24)[0]            # first leaf node
        folders = {2: (1, "")}                                 # folderID -> (parent, name); 2 = root
        files = []
        while node:
            nd = cat[node * nsize:(node + 1) * nsize]
            flink, _blink, kind, _h, nrec = struct.unpack_from(">IIbBH", nd, 0)
            if kind != -1:
                raise FirmwareError("catalog leaf chain is corrupt")
            for i in range(nrec):
                off = struct.unpack_from(">H", nd, nsize - 2 * (i + 1))[0]
                klen = struct.unpack_from(">H", nd, off)[0]
                parent, nlen = struct.unpack_from(">IH", nd, off + 2)
                name = nd[off + 8:off + 8 + 2 * nlen].decode("utf-16-be")
                rec = off + 2 + klen
                rec += rec & 1
                rtype = struct.unpack_from(">h", nd, rec)[0]
                if rtype == 1:
                    folders[struct.unpack_from(">I", nd, rec + 8)[0]] = (parent, name)
                elif rtype == 2:
                    files.append((parent, name, struct.unpack_from(">I", nd, rec + 8)[0],
                                  bytes(nd[rec + 168:rec + 248])))
            node = flink

        def pathof(parent, name):
            parts = [name]
            while parent > 2 and parent in folders:
                parent, n = folders[parent]
                parts.append(n)
            return "/".join(reversed(parts))

        found = {pathof(p, n): (fid, rfork) for p, n, fid, rfork in files}

    def load(fk):
        with open(img, "rb") as f2:
            return _fork_from_extents(f2, bsize, fk)
    return found, load


def read_hfs_file(m, relpath, image=None):
    """Bytes of `relpath` on the mounted volume `m`, undoing HFS+ compression.  `image` is the raw volume
    behind the mount; it is only needed to fetch a resource fork the kernel driver does not expose."""
    path = os.path.join(m, relpath)
    with open(path, "rb") as f:
        data = f.read()
    hdr = _getxattr(path, DECMPFS_XATTR)
    if hdr is None:
        return data, False
    if data:
        return data, False                    # compressed flag left on a file that has a data fork: trust it

    def rsrc():
        got = _getxattr(path, RSRC_XATTR)
        if got:
            return got
        if not image:
            return None
        subprocess.run(["sync"])
        files, load = _hfs_catalog_files(image)
        ent = files.get(relpath)
        return load(ent[1]) if ent else None
    return decmpfs_decode(hdr, rsrc), True


def activate_volume(m, log=print, image=None):
    """SystemEdits.activate: patch lockdownd on the mounted volume `m` (owner/mode kept).  A decmpfs-compressed
    lockdownd (iOS 4.x) is decompressed and rewritten as a plain file; `image` is the raw volume behind `m`."""
    path = os.path.join(m, LOCKDOWND)
    before, compressed = read_hfs_file(m, LOCKDOWND, image)
    if not before:
        raise ActivationError("%s reads as 0 bytes on the volume and has no decmpfs data" % LOCKDOWND)
    after, rep = activate_lockdownd(before)
    st = os.stat(path)
    mode = st.st_mode & 0o7777
    if compressed:
        # Replace, don't overwrite: the stock file carries UF_COMPRESSED + com.apple.decmpfs, and iOS would keep
        # reading the old bytes from that attribute.  A fresh file is plain and uncompressed.
        tmp = path + ".new"
        with open(tmp, "wb") as f:
            f.write(after)
        os.chmod(tmp, mode)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except (PermissionError, AttributeError):
            pass
        os.unlink(path)
        os.rename(tmp, path)
        rep["decompressed"] = True
    else:
        os.chmod(path, mode | 0o200)
        try:
            with open(path, "r+b") as f:  # in place: the catalog record, owner and mode stay
                f.write(after)
        finally:
            os.chmod(path, mode)
    log("activation: %s at file offset 0x%x (%s): %s -> %s%s%s" % (
        rep["strategy"], rep["offset"], rep["isa"], rep["original"], rep["replacement"],
        " (re-signed ad hoc)" if rep.get("resigned") else "",
        " (was HFS+-compressed, rewritten as a plain file)" if rep.get("decompressed") else ""))
    return rep


# ---------------------------------------------------------------------------------------------
# Jailbreak option (port of FirmwareKit's SystemEdits.installJailbreak, installAFC2, installCydia, Cydia)
# ---------------------------------------------------------------------------------------------
#
# `create --jailbreak` leaves on the device what a jailbreak of the time left: afc2 (lockdown's AFC served at "/"
# as root) and Cydia with Substrate, from saurik's freeze.tar as Legacy iOS Kit ships it (pinned by commit and
# SHA-1).  Cydia's Startup job finishes the install on the first boot (dpkg of the AutoInstall packages, uicache),
# so the first boot of a jailbroken device takes longer.  The K48 family (and, harmlessly, the other kboot boards)
# boots with amfi_get_out_of_my_way=1: with AMFI asking amfid about every ad hoc signed library, Substrate's launcher
# makes amfid wait on itself and the boot stops before SpringBoard.
#
# Scope: iPhone OS 2.0 and later, on the boards whose rootfs create mounts (m68ap, n45ap, n72ap, n18ap, n88ap, k48ap,
# n81ap, n90ap; n72ap through n72_nand.build, so not with --skip-nand).  Substrate comes for 3.x to 6.x, Cydia
# HTTPatch for 3.x (as in Swift).  Not ported: the iPod touch 2G's it_typein-by-Substrate move, and
# `firmwarekit edit --action jailbreak` on an existing device.

JB_SOURCE = ("https://raw.githubusercontent.com/LukeZGD/Legacy-iOS-Kit/"
             "4b0a582f4d53e105be373b495734c8ed639fd634/resources/jailbreak/")
JB_FILES = (
    ("freeze.tar.gz", "c943e5ece72b7b71da589c22663a8f9b3b3d1190"),      # Cydia 1.1.30, apt, dpkg, bash, ...
    ("cydiasubstrate.tar", "264f47938acc09e6cc2890a3cc7c7988a6822da3"),   # MobileSubstrate (3.x-6.x)
    ("cydiahttpatch.tar", "3a1302c6294fe290c6d52186dd4fe56cda7fd661"),    # Cydia over http (3.x)
)
JB_SUBSTRATE_MAJORS = range(3, 7)
JB_HTTPATCH_MAJOR = 3
JB_BOOT_ARG = "amfi_get_out_of_my_way=1"
JB_NO_STASH = ".cydia_no_stash"
JB_METADATA = "private/var/lib/cydia/metadata.plist"
JB_EXCLUDED = "private/var/Keychains"       # the bootstrap's trust store: iOS's own stays
JB_SB_PREFS = "private/var/mobile/Library/Preferences/com.apple.springboard.plist"
# Cydia's default third-party sources as reachable today (keyed as CydiaAddSource keys them).
JB_SOURCES = ("http://apt.thebigboss.org/repofiles/cydia/", "http://modmyi.saurik.com/",
              "http://zodttd.saurik.com/repo/cydia/")
# Patcyh (a Substrate extension for lsd and installd, iOS 8.3+) comes out, as Legacy iOS Kit takes it out below 8.3.
JB_PATCYH = (
    "Library/MobileSubstrate/DynamicLibraries/patcyh.dylib",
    "Library/MobileSubstrate/DynamicLibraries/patcyh.plist", "usr/lib/libpatcyh.dylib",
    "private/var/lib/dpkg/info/com.saurik.patcyh.list", "private/var/lib/dpkg/info/com.saurik.patcyh.postrm",
    "private/var/lib/dpkg/info/com.saurik.patcyh.extrainst_",
)
LOCKDOWN_SERVICES = "System/Library/Lockdown/Services.plist"
AFCD, AFC2D = "usr/libexec/afcd", "usr/libexec/afc2d"
SYSTEM_VERSION = "System/Library/CoreServices/SystemVersion.plist"
MOBILE_UID = 501


def jb_boot_args(boot_args):
    """The boot-args of a jailbroken device."""
    return boot_args if JB_BOOT_ARG in boot_args.split() else boot_args + " " + JB_BOOT_ARG


def jb_default_cache():
    """Where the bootstrap is kept between runs: the invoking user's ~/.cache/firmwarekit/Jailbreak."""
    base = os.environ.get("XDG_CACHE_HOME")
    who = invoking_user()
    if who:
        import pwd
        try:
            base = os.path.join(pwd.getpwuid(who[0]).pw_dir, ".cache")
        except KeyError:
            pass
    return os.path.join(base or os.path.expanduser("~/.cache"), "firmwarekit", "Jailbreak")


def jb_fetch(directory, log=print, download=None):
    """The bootstrap packages in `directory`, each downloaded first when missing or other bytes (SHA-1 pinned).
    -> the directory."""
    import urllib.request

    def fetch(url, dst):
        req = urllib.request.Request(url, headers={"User-Agent": "firmwarekit"})
        with urllib.request.urlopen(req, timeout=60) as r, open(dst, "wb") as f:
            shutil.copyfileobj(r, f)
    download = download or fetch
    os.makedirs(directory, exist_ok=True)
    for name, sha1 in JB_FILES:
        dst = os.path.join(directory, name)
        if os.path.isfile(dst) and sha1_file(dst) == sha1:
            continue
        part = os.path.join(directory, "." + name + ".download")
        log("Cydia: " + JB_SOURCE + name)
        try:
            download(JB_SOURCE + name, part)
            got = sha1_file(part)
            if got != sha1:
                raise FirmwareError("Cydia: %s SHA-1 is %s, not %s" % (name, got, sha1))
            os.replace(part, dst)
        except OSError as e:
            raise FirmwareError("Cydia: could not download %s (%s); fetch it by hand into %s" % (name, e, directory))
        finally:
            if os.path.exists(part):
                os.remove(part)
    who = invoking_user()
    if who:     # downloaded as root: the cache stays the user's
        for name in [""] + [n for n, _ in JB_FILES]:
            try:
                os.chown(os.path.join(directory, name) if name else directory, who[0], who[1])
            except OSError:
                pass
    return directory


def jb_entry_path(name):
    """A tar member name as a volume path: no leading ./, no trailing /."""
    return (name[2:] if name.startswith("./") else name).strip("/")


def jb_members(package):
    """[(volume path, permission bits, is a regular file)] of a bootstrap package, the excluded trust store out."""
    import tarfile
    out = []
    with tarfile.open(package) as t:
        for ti in t.getmembers():
            path = jb_entry_path(ti.name)
            if not path or path == JB_EXCLUDED or path.startswith(JB_EXCLUDED + "/"):
                continue
            out.append((path, ti.mode & 0o7777, ti.isreg()))
    return out


def jb_packages(directory, major):
    """The packages to extract for iOS `major`: the bootstrap, Substrate on 3.x-6.x, Cydia HTTPatch on 3.x."""
    names = [JB_FILES[0][0]]
    if major in JB_SUBSTRATE_MAJORS:
        names.append(JB_FILES[1][0])
    if major == JB_HTTPATCH_MAJOR:
        names.append(JB_FILES[2][0])
    return [os.path.join(directory, n) for n in names]


def _replace_file(path, data, mode=None):
    """Write `data` as a fresh plain file (a stock file may carry UF_COMPRESSED + com.apple.decmpfs, which
    would keep serving the old bytes), keeping its mode and owner."""
    try:
        st = os.stat(path)
    except OSError:
        st = None
    if st is not None:
        os.unlink(path)
    _put(path, data, mode if mode is not None else (st.st_mode & 0o7777 if st else None))
    if st is not None:
        try:
            os.chown(path, st.st_uid, st.st_gid)
        except OSError:
            pass


def _macho_sig(thin):
    """(offset, size) of a thin 32-bit little-endian Mach-O's LC_CODE_SIGNATURE, or None."""
    if len(thin) < 28 or struct.unpack_from("<I", thin, 0)[0] != 0xFEEDFACE:
        return None
    ncmds = struct.unpack_from("<I", thin, 16)[0]
    at = 28
    for _ in range(ncmds):
        if at + 8 > len(thin):
            return None
        cmd, size = struct.unpack_from("<II", thin, at)
        if size < 8:
            return None
        if cmd == 0x1D and at + 16 <= len(thin):
            return struct.unpack_from("<II", thin, at + 8)
        at += size
    return None


def resign_macho(data):
    """Activation.signed for any 32-bit ARM Mach-O (fat or thin): the code-directory page hashes rebuilt as an
    ad hoc signature, entitlements kept; size and layout unchanged."""
    slices = _fat_arm_slices(data)
    spans = [(0, len(data))] if slices is None else [(off, size) for _sub, off, size in slices]
    if not spans:
        raise ActivationError("fat Mach-O has no 32-bit ARM slice")
    out = bytearray(data)
    for off, size in spans:
        thin = bytes(data[off:off + size])
        sig = _macho_sig(thin)
        if sig is None:
            raise ActivationError("no code signature to refresh")
        out[off:off + size] = resign_lockdownd(thin, sig)
    return bytes(out)


def afc2_strings(afcd):
    """7.1's afcd serving "/" as the XPC service com.apple.afc2: its root and service name replaced in place (each
    by a string no longer, padded with NULs).  Unsigned; the caller signs."""
    d = afcd
    for frm, to in ((b"/private/var/mobile/Media", b"/"), (b"com.apple.afcd", b"com.apple.afc2")):
        old = frm + b"\0"
        if old not in d:
            raise FirmwareError("afcd: no %s" % frm.decode())
        d = d.replace(old, to + b"\0" + bytes(len(frm) - len(to)))
    return d


def _read_plist(m, rel, image=None):
    data, _ = read_hfs_file(m, rel, image)
    return plistlib.loads(data)


def jb_install_afc2(m, image=None, log=print):
    """afc2: a com.apple.afc2 lockdown service serving "/" as root.  Through 7.0 it is the stock afcd under old-style
    lockdown at "/"; 7.1's afcd takes neither --lockdown nor -d, so afc2 there is a copy of it (afc2d) run by its own
    launchd job without the stock job's user.  -> the log line."""
    stock, _ = read_hfs_file(m, AFCD, image)
    old_style = b"--lockdown" in stock
    services = _read_plist(m, LOCKDOWN_SERVICES, image)
    if "com.apple.afc" not in services:
        raise FirmwareError("%s has no com.apple.afc service" % LOCKDOWN_SERVICES)
    if old_style:
        services["com.apple.afc2"] = {"AllowUnactivatedService": True, "Label": "com.apple.afc2",
                                      "ProgramArguments": ["/usr/libexec/afcd", "--lockdown", "-d", "/"]}
    else:
        services["com.apple.afc2"] = {"AllowUnactivatedService": True, "Label": "com.apple.afc2",
                                      "XPCServiceName": "com.apple.afc2"}
    _replace_file(os.path.join(m, LOCKDOWN_SERVICES), plistlib.dumps(services, fmt=plistlib.FMT_XML))
    if old_style:
        return "afc2: com.apple.afc2 runs afcd at / (Lockdown/Services.plist)"
    _put(os.path.join(m, AFC2D), resign_macho(afc2_strings(stock)), 0o755)
    job_rel = DAEMONS + "/com.apple.afcd.plist"
    job = _read_plist(m, job_rel, image)
    if job.get("Label") != "com.apple.afcd":
        raise FirmwareError("%s: not com.apple.afcd's job" % os.path.basename(job_rel))
    job["Label"] = "com.apple.afc2"
    job["MachServices"] = {"com.apple.afc2": True}
    job["ProgramArguments"] = ["/" + AFC2D]
    job.pop("UserName", None)
    _put(os.path.join(m, DAEMONS, "com.apple.afc2.plist"), plistlib.dumps(job, fmt=plistlib.FMT_XML), 0o644)
    return "afc2: com.apple.afc2 is afc2d, afcd at / as an XPC service (Lockdown/Services.plist)"


def jb_drop_patcyh_packages(text):
    """dpkg's status/available text without the com.saurik.patcyh paragraph."""
    return "\n\n".join(p for p in text.split("\n\n") if not p.startswith("Package: com.saurik.patcyh\n"))


def jb_install_cydia(m, directory, major, log=print):
    """The bootstrap extracted into the mounted system volume `m`, keeping every file the firmware already has
    (tar --skip-old-files); its set-user-ID files (cydo, su, login, passwd) get their archive modes back, what it
    added under /private/var/mobile becomes mobile's.  -> the log line."""
    def exists(rel):
        return os.path.lexists(os.path.join(m, rel))

    entries, special = [], []
    packages = jb_packages(directory, major)
    for p in packages:
        for path, mode, is_reg in jb_members(p):
            entries.append(path)
            if is_reg and mode & 0o6000:
                special.append((path, mode))
    added = {e for e in entries if not exists(e)}
    # tar gives an existing folder the archive's mode and owner; the firmware's stay.
    folders = {}
    for e in entries:
        st = os.lstat(os.path.join(m, e)) if exists(e) else None
        if st is not None and stat.S_ISDIR(st.st_mode):
            folders[e] = (st.st_mode & 0o7777, st.st_uid, st.st_gid)
    for p in packages:
        r = subprocess.run(["tar", "-xf", p, "-C", m, "--skip-old-files", "--no-same-owner",
                            "-p", "--exclude", "./" + JB_EXCLUDED, "--exclude", JB_EXCLUDED],
                           capture_output=True, text=True)
        if r.returncode:
            raise FirmwareError("tar -x %s: %s" % (os.path.basename(p), r.stderr.strip() or r.returncode))
    for rel, (mode, uid, gid) in folders.items():
        try:
            os.chmod(os.path.join(m, rel), mode)
            os.chown(os.path.join(m, rel), uid, gid)
        except OSError:
            pass
    if not exists("Applications/Cydia.app/Cydia"):
        raise FirmwareError("Cydia bootstrap: no Applications/Cydia.app/Cydia after extracting")
    for rel in JB_PATCYH:
        try:
            os.remove(os.path.join(m, rel))
        except OSError:
            pass
    for rel in ("private/var/lib/dpkg/status", "private/var/lib/dpkg/available"):
        path = os.path.join(m, rel)
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            continue
        _replace_file(path, jb_drop_patcyh_packages(text).encode())
    entries = [e for e in entries if e not in JB_PATCYH]
    # SpringBoard lists a system app outside its own set only with this key.
    had_prefs = exists(JB_SB_PREFS)
    seed_plist(os.path.join(m, JB_SB_PREFS), lambda d: d.__setitem__("SBShowNonDefaultSystemApps", True))
    # Cydia's first launch would otherwise stash /Applications, /usr/share and the rest onto the data volume
    # ("Preparing Filesystem", then exit) to free a stock-sized root; this root is grown, so no stash.
    _put(os.path.join(m, JB_NO_STASH), b"", 0o644)
    # Its sources: read once by Cydia (as mobile), which keeps them in its preferences and removes the file.
    sources = {"deb:%s:stable" % uri: {"Type": "deb", "URI": uri, "Distribution": "stable", "Sections": ["main"]}
               for uri in JB_SOURCES}
    _put(os.path.join(m, JB_METADATA), plistlib.dumps({"Version": 1, "Sources": sources}, fmt=plistlib.FMT_XML), 0o644)
    mobile = [e for e in entries if e.startswith("private/var/mobile/") and (e in added or os.path.islink(os.path.join(m, e)))]
    if not had_prefs and JB_SB_PREFS not in mobile:
        mobile.append(JB_SB_PREFS)
    for rel in mobile:
        try:
            os.lchown(os.path.join(m, rel), MOBILE_UID, MOBILE_UID)
        except OSError:
            pass
    for path, mode in special:      # tar was told not to keep owners; the modes it can't be trusted with are set here
        if path in added and exists(path):
            os.chmod(os.path.join(m, path), mode)
    return "Cydia: %s, %d of %d entries added" % (", ".join(os.path.basename(p) for p in packages),
                                                  len(added), len(entries))


def jailbreak_volume(m, directory, image=None, log=print):
    """SystemEdits.installJailbreak over the mounted writable system volume `m` (`image`: the raw volume behind it):
    afc2, then Cydia with Substrate.  Run after the volume's other edits (edit_volume removes launch daemons the
    bootstrap's Cydia.Startup job must outlive).  -> a report dict."""
    ver = _read_plist(m, SYSTEM_VERSION, image).get("ProductVersion", "")
    major = int(ver.split(".")[0]) if ver[:1].isdigit() else 0
    if major < 2:
        raise FirmwareError("the jailbreak needs iPhone OS 2.0 or later (this volume is %s)" % (ver or "unknown"))
    rep = {"ios": ver}
    rep["afc2"] = jb_install_afc2(m, image, log)
    log(rep["afc2"])
    rep["cydia"] = jb_install_cydia(m, directory, major, log)
    log(rep["cydia"])
    return rep


def jailbreak_kboot_rootfs(system_img, system_mib, work, directory, log=print):
    """The jailbreak edits inside the extracted rootfs image of a kboot board: the volume grown to the partition
    size first (Cydia needs the room), then mounted and edited."""
    try:
        hfs_grow(system_img, system_mib << 20)
    except FirmwareError as e:
        if "already larger" not in str(e):
            raise
    mnt = os.path.join(work, "mnt_jb")
    print("installing the jailbreak (afc2, Cydia, Substrate) in the rootfs...")
    try:
        return with_mounted(system_img, mnt, lambda m: jailbreak_volume(m, directory, system_img, log))
    except OSError as e:
        raise FirmwareError("the jailbreak edits failed (%s); the volume inside the image may be full" % e)
    finally:
        try:
            os.rmdir(mnt)
        except OSError:
            pass



# ---------------------------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------------------------


def catalog_entry(path, eid):
    with open(path) as f:
        cat = json.load(f)
    for e in cat["entries"]:
        if e.get("id") == eid:
            return e
    raise FirmwareError("catalog has no entry %s" % eid)


def sha1_file(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


# ---------------------------------------------------------------------------------------------
# Board metadata: QEMU machine name, temp prefix, NAND banks, boot style
# ---------------------------------------------------------------------------------------------

# board -> (qemu_machine, tmp_prefix, nand_banks, nand_bbt_map, boot_style)
# boot_style: "img2"  = 8900+IMG2 NOR (m68/n45)
#             "img3"  = IMG3 NOR packed at 0x8000 (n72)
#             "kboot" = direct kernel / KBoot (n18/n88/n81/n90)
#             "iboot" = iBoot NOR with SHSH wrapping (k48)
BOARD_META = {
    "m68ap": ("iPhone-2G",     "m68",  4, True,  "img2"),
    "n45ap": ("iPod-Touch-1G", "n45",  4, True,  "img2"),
    "n72ap": ("iPod-Touch",    "n72",  4, False, "img3"),
    "n18ap": ("n18",           "n18",  4, False, "kboot"),
    "n88ap": ("n88",           "n88",  4, False, "kboot"),
    "k48ap": ("ipad1",         "k48",  4, False, "kboot"),
    "n81ap": ("iPod-Touch-4G", "n81",  4, False, "kboot"),
    "n90ap": ("iPhone-4",      "n90",  4, False, "kboot"),
}


# board -> (SoC, file name the bootrom gets inside the device folder).  Only boards that boot through
# a bootrom are listed; the kboot boards (n18/n88/k48/n81/n90) start the kernel directly.
BOOTROMS = {
    "m68ap": ("S5L8900", "bootrom_s5l8900"),
    "n45ap": ("S5L8900", "bootrom_s5l8900"),
    "n72ap": ("S5L8720", "bootrom_s5l8720"),
}

# Shell line that sets D to the directory holding run.sh (works from any cwd, through symlinks-free paths).
SH_DIR_LINE = 'D=$(cd "$(dirname "$0")" && pwd)\n'


def resolve_bootrom(board, path):
    """The --bootrom argument -> absolute path (or None when not given / not used by this board)."""
    if not path:
        return None
    if board not in BOOTROMS:
        print("note: %s boots without a bootrom; ignoring --bootrom" % board)
        return None
    full = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(full):
        raise FirmwareError("bootrom %s not found (or not a file)" % full)
    if os.path.getsize(full) == 0:
        raise FirmwareError("bootrom %s is empty" % full)
    return full


def install_bootrom(src, board, out):
    """Copy the user's bootrom into the device folder under its canonical name -> that name."""
    soc, name = BOOTROMS[board]
    dst = os.path.join(out, name)
    if not (os.path.exists(dst) and os.path.samefile(src, dst)):
        shutil.copyfile(src, dst)
    os.chmod(dst, 0o644)
    print("bootrom %s -> %s (%s)" % (src, name, soc))
    return name


def bootrom_guard(board):
    """run.sh lines choosing the bootrom: the copy bundled next to run.sh wins, else $BOOTROM."""
    soc, name = BOOTROMS[board]
    return (
        '[ -f "$D/%s" ] && BOOTROM="$D/%s"\n'
        '[ -n "$BOOTROM" ] || { echo "no bootrom: re-run firmwarekit create with --bootrom, '
        'or put the %s bootrom at $D/%s, or set BOOTROM"; exit 1; }\n'
        '[ -f "$BOOTROM" ] || { echo "bootrom not found: $BOOTROM"; exit 1; }\n'
    ) % (name, name, soc, name)


def _write_run_sh(path, body):
    """Write run.sh with the standard header and make it executable."""
    with open(path, "w") as f:
        f.write("#!/bin/sh\n")
        f.write(body)
    os.chmod(path, 0o755)


def _cleanup_trap(tmp_prefix):
    """A sh trap that removes /tmp/<prefix>-* on exit."""
    return "trap 'rm -rf /tmp/%s-*' EXIT\n" % tmp_prefix


# ---------------------------------------------------------------------------------------------
# IMG2 boards: m68ap (iPhone 2G) and n45ap (iPod Touch 1G)
# ---------------------------------------------------------------------------------------------

def create_img2(args, entry, ipsw, ri, out, work):
    """Build NOR+NAND for m68ap/n45ap (IMG2/8900, iPhone OS 1.x/early 2.x)."""
    board = ri["board"]
    meta = BOARD_META[board]
    qemu_machine, tmp_prefix, nand_banks, bbt_map, _ = meta
    recipe = entry["recipe"]
    system_bytes = int(recipe.get("system_mib", 512)) << 20

    # boot files: iBoot.bin and nor.bin
    prefix = "Firmware/all_flash/all_flash.%s.production/" % board
    images, iboot = {}, None
    for n in ipsw.names():
        if n.startswith(prefix) and n.endswith(".img2"):
            body = apple8900_body(ipsw.read(n))
            typ = img2_header(body)[0]
            images[typ] = body
            if n == prefix + "iBoot.%s.RELEASE.img2" % board:
                iboot = img2_payload(body)
    if iboot is None:
        raise FirmwareError("no iBoot.%s.RELEASE.img2 in the IPSW" % board)
    fil = fil_id(iboot)
    print("iBoot %d bytes, NAND signature 0x%X" % (len(iboot), fil))

    model = {"m68ap": "MA501", "n45ap": "MA623"}.get(board, "MA501")
    ident = synthesize_iphone(args.seed or args.id + "-default", model=model)
    if args.imei:
        ident["imei"] = args.imei
    if args.wifi_mac:
        ident["wifi-mac"] = args.wifi_mac

    nor = build_nor(ident, images)
    with open(os.path.join(out, "nor.bin"), "wb") as f:
        f.write(nor)
    with open(os.path.join(out, "iBoot.bin"), "wb") as f:
        f.write(iboot)
    with open(os.path.join(out, "identity.json"), "w") as f:
        json.dump(ident, f, indent=1)
    print("wrote nor.bin, iBoot.bin, identity.json")

    # rootfs: decrypt, extract, grow, edit
    os_member = ri["system_image"]
    if not os_member:
        raise FirmwareError("Restore.plist names no system image")
    rootfs_keys = entry.get("keys", {}).get("rootfs", {})
    key_hex = rootfs_keys.get("key")
    if not key_hex:
        raise FirmwareError("catalog entry has no rootfs key")
    if rootfs_keys.get("file") and rootfs_keys["file"] != os.path.basename(os_member):
        raise FirmwareError("catalog key is for %s but the IPSW's system image is %s"
                            % (rootfs_keys["file"], os_member))
    dec = os.path.join(work, "rootfs.dmg")
    print("decrypting %s ..." % os_member)
    with ipsw.open(os_member) as s, open(dec, "wb") as d:
        vfdecrypt(s, d, hexb(key_hex))
    vol = os.path.join(work, "volume.img")
    print("extracting the HFS+ volume ...")
    extract_rootfs(dec, vol, work)
    os.remove(dec)
    print("growing to %d MiB ..." % (system_bytes >> 20))
    hfs_grow(vol, system_bytes)
    if args.no_volume_edit:
        print("--no-volume-edit: skipping fstab/kernelcache/daemon edits; the image will NOT boot as is")
        rep = {}
    else:
        print("mounting and editing (needs root + hfsplus) ...")
        def edits(m):
            r = edit_volume(m, iboot, ipsw, ri["kernelcache"], activate=not args.skip_activation)
            if getattr(args, "guest_package", None):   # after edit_volume: the seed removes the baked jobs it replaces
                r["guest_package"] = seed_guest_package(m, args, board)
            if getattr(args, "jailbreak", False):      # after edit_volume: it removes launch daemons
                r["jailbreak"] = jailbreak_volume(m, args.jb_dir, vol)
            return r
        rep = with_mounted(vol, os.path.join(work, "mnt"), edits)
        print("edits:", json.dumps(rep, indent=1))
        if subprocess.run(["which", "fsck.hfsplus"], capture_output=True).returncode == 0:
            r = subprocess.run(["fsck.hfsplus", "-fn", vol], capture_output=True, text=True)
            print("fsck.hfsplus on the edited volume: %s"
                  % ("clean" if r.returncode == 0 else "PROBLEMS\n" + r.stdout[-1500:]))

    print("writing the NAND page directory (this is a few hundred thousand small files) ...")
    last = [0]

    def prog(i, n):
        if i * 10 // n != last[0]:
            last[0] = i * 10 // n
            print("  %d%%" % (last[0] * 10))
    written, meta_pages = write_nand(vol, os.path.join(out, "nand"), fil, nand_banks, bbt_map, prog)
    print("%d filesystem pages, %d metadata pages" % (written, meta_pages))
    if not args.keep_work:
        try:
            os.remove(vol)
        except OSError:
            pass

    # the bootrom: the user's copy goes into the device folder, run.sh prefers it
    if args.bootrom_path:
        install_bootrom(args.bootrom_path, board, out)
    else:
        print("note: no --bootrom given; run.sh will need $BOOTROM (or %s in this folder)" % BOOTROMS[board][1])
    imei_str = ident.get("imei", "")
    wifi_str = ident.get("wifi-mac", "")
    run_body = SH_DIR_LINE
    run_body += _cleanup_trap(tmp_prefix)
    run_body += bootrom_guard(board)
    run_body += """mkdir -p /tmp/%s-ovl
cp -n "$D/nor.bin" /tmp/%s-nor.bin
chmod u+w /tmp/%s-nor.bin
exec ${QEMU:-qemu-system-arm} \\
  -M %s,bootrom=$BOOTROM,direct-iboot="$D/iBoot.bin",nand="$D/nand",nand-overlay=/tmp/%s-ovl,imei=%s,wifi-mac=%s \\
  -drive if=pflash,format=raw,file=/tmp/%s-nor.bin \\
  -serial mon:stdio -display sdl,show-cursor=on -audio driver=none \\
  -qmp unix:/tmp/%s-qmp.sock,server,nowait
""" % (tmp_prefix, tmp_prefix, tmp_prefix,
       qemu_machine, tmp_prefix, imei_str, wifi_str,
       tmp_prefix, tmp_prefix)
    _write_run_sh(os.path.join(out, "run.sh"), run_body)

    print("""
done: %s
Not done (the Swift firmwarekit handles these): Wi-Fi + proxy SystemConfiguration seeding, HFS+ journaling,
catalog date normalisation.  The guest package / OpenGLES hook is baked with --guest-package ITPACK."""
          % out)


# ---------------------------------------------------------------------------------------------
# IMG3 boards: n72ap (iPod Touch 2G/3G) -- NOR packed with img3s
# ---------------------------------------------------------------------------------------------

def _build_nor_module():
    # appended, never first: imgtools/imgtools has older copies of ipad1_fw/ipad1_kboot/macho/... that must not
    # shadow this directory's
    d = os.path.join(ROOT, "imgtools", "imgtools")
    if d not in sys.path:
        sys.path.append(d)
    import build_nor
    return build_nor


def create_img3(args, entry, ipsw, ri, out, work):
    """n72ap (iPod Touch 2G): decrypt the boot chain with the catalog's IMG3 keys, pack the all_flash img3s
    into a 1 MiB NOR (IMG2 superblock, SysCfg, images at 0x8000 with SHSH wrapped under the emulated UID,
    nvram at 0xfc000: imgtools/build_nor.py, FirmwareKit's N72NOR) and write the iBoot the machine enters.

    The system volume and NAND page store come from tools/n72_nand.py (Linux port of imgtools/build_nand.py;
    needs root and the hfsplus module); --skip-nand leaves nand/ out."""
    board = ri["board"]
    qemu_machine, tmp_prefix, nand_banks, bbt_map, _ = BOARD_META[board]
    major = int((ri["version"].split(".")[0] or "0"))
    bn = _build_nor_module()

    # all_flash img3s: LLB, iBoot, DeviceTree, logos ... (the NOR's contents); kept as shipped in img3/
    prefix = "Firmware/all_flash/all_flash.%s.production/" % board
    members = {os.path.basename(n): n for n in ipsw.names() if n.startswith(prefix) and not n.endswith("/")}
    flash_dir = os.path.join(work, "all_flash")
    img3_dir = os.path.join(out, "img3")
    os.makedirs(flash_dir, exist_ok=True)
    os.makedirs(img3_dir, exist_ok=True)
    for fname, member in sorted(members.items()):
        data = ipsw.read(member)
        with open(os.path.join(flash_dir, fname), "wb") as f:
            f.write(data)
        if fname.endswith((".img3", ".img2")):
            with open(os.path.join(img3_dir, fname), "wb") as f:
                f.write(data)
    print("all_flash members: %s" % ", ".join(sorted(members)))

    ident = synthesize_iphone(args.seed or args.id + "-default", model="MB528")
    if args.wifi_mac:
        ident["wifi-mac"] = args.wifi_mac
    with open(os.path.join(out, "identity.json"), "w") as f:
        json.dump(ident, f, indent=1)

    # the NOR: 2.x iBoot unwraps only iBoot's own SHSH, 3.x+ every image's (build_nor.py's docstring)
    nor_path = os.path.join(out, "nor.bin")
    print("building nor.bin (%s)..." % ("wrapping iBoot's SHSH only" if major < 3 else "wrapping every SHSH"))
    try:
        bn.build(None, flash_dir, nor_path, bn.DEFAULT_ORDER, base=bn.synth_base(ident),
                 wrap_types=["ibot"] if major < 3 else None, hardware_uid=True)
    except SystemExit as e:           # build_nor reports a missing image / no SHSH as SystemExit
        raise FirmwareError("nor.bin: %s" % e)

    # decrypt the boot chain with the catalog keys (iBoot.bin is the image the machine enters on 3.x+)
    dec_dir = os.path.join(work, "decrypted")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import ipad1_fw
    print("decrypting firmware components using catalog keys...")
    ipad1_fw.decrypt_catalog(args.ipsw, entry, dec_dir, rootfs=False)
    iboot_out = None
    if major >= 3 and os.path.exists(os.path.join(dec_dir, "iBoot.bin")):
        iboot_out = os.path.join(out, "iBoot.bin")
        shutil.copyfile(os.path.join(dec_dir, "iBoot.bin"), iboot_out)
    for name in ("kernelcache.mach", "DeviceTree.bin"):
        if os.path.exists(os.path.join(dec_dir, name)):
            shutil.copyfile(os.path.join(dec_dir, name), os.path.join(out, name))

    # run.sh: the machine option the NOR is wrapped for (aes-uid=hardware: the AES engine honors iBoot's UID
    # derivation, as N72NOR wraps for), the NOR, the NAND store and iBoot when 3.x+
    if args.bootrom_path:
        install_bootrom(args.bootrom_path, board, out)
    else:
        print("note: no --bootrom given; run.sh will need $BOOTROM (or %s in this folder)" % BOOTROMS[board][1])
    if not getattr(args, "skip_nand", False):
        import n72_nand
        n72_nand.build(args.ipsw, entry, ri, out, work,
                       jailbreak_dir=getattr(args, "jb_dir", None) if getattr(args, "jailbreak", False) else None,
                       activate=not getattr(args, "skip_activation", False))
    run_body = SH_DIR_LINE
    run_body += _cleanup_trap(tmp_prefix)
    run_body += bootrom_guard(board)
    run_body += """exec ${QEMU:-qemu-system-arm} \\
  -M %s,bootrom=$BOOTROM,aes-uid=hardware,nand="$D/nand",nor="$D/nor.bin"%s \\
  -serial mon:stdio -display sdl,show-cursor=on -audio driver=none
""" % (qemu_machine, ',direct-iboot="$D/iBoot.bin"' if iboot_out else "")
    _write_run_sh(os.path.join(out, "run.sh"), run_body)
    if getattr(args, "skip_nand", False):
        print("""
done: %s
nor.bin%s written.  --skip-nand: the NAND page store is not built (imgtools/build_nand.py makes one):
run.sh expects a nand/ directory next to it.""" % (out, " and iBoot.bin" if iboot_out else ""))
    else:
        print("\ndone: %s\nnor.bin%s and nand/ written." % (out, " and iBoot.bin" if iboot_out else ""))


# ---------------------------------------------------------------------------------------------
# KBoot boards: n18ap, n88ap, n81ap, n90ap
# ---------------------------------------------------------------------------------------------

_KBOOT_MODELS = {
    "n18ap": "MC008",   # iPod Touch 3G
    "n88ap": "MC132",   # iPhone 3GS
    "n81ap": "MC540",   # iPod Touch 4G
    "n90ap": "MC318",   # iPhone 4 GSM
}
_KBOOT_BOOTROMS = {
    "n18ap": "S5L8922", "n88ap": "S5L8920",
    "n81ap": "S5L8930", "n90ap": "S5L8930",
}


# A4 boards whose iOS 4.x/5.x lockdownd is patched and re-signed at create time.
_ACTIVATED_KBOOT = ("k48ap", "n81ap", "n90ap")


def activate_kboot_rootfs(system_img, work, log=print):
    """Patch + re-sign lockdownd inside the extracted rootfs image.  The edit is in place and the same size, so the
    volume layout does not change.  A failure is reported, not fatal: the bundle is still produced, unactivated."""
    mnt = os.path.join(work, "mnt_sys")
    print("activating lockdownd in the rootfs...")
    try:
        rep = with_mounted(system_img, mnt, lambda m: activate_volume(m, log, image=system_img))
        print("  lockdownd: %s -> %s" % (rep["input_sha256"][:12], rep["output_sha256"][:12]))
        return rep
    except ActivationError as e:
        print("warning: lockdownd was NOT activated (%s)" % e)
        print("         the patcher rejected this lockdownd; the device will stop at \"Connect to iTunes\"")
        return None
    except FirmwareError as e:
        print("warning: lockdownd was NOT activated (%s)" % e)
        print("         rerun as root, or pass --skip-activation to silence this")
        return None
    except OSError as e:     # e.g. ENOSPC: the HFS+ volume inside the image is full (a decmpfs lockdownd is rewritten)
        print("warning: lockdownd was NOT activated (%s)" % e)
        print("         the volume inside the image has no room for the patched file; the bundle is built unactivated")
        return None
    finally:
        try:
            os.rmdir(mnt)
        except OSError:
            pass


def seed_guest_package(m, args, board, log=print):
    """Guest package seed (the loader, the seed package, the GL/AppSync hooks) over the mounted writable system
    volume `m`: guest_package.seed.  -> the lock's guest_package record."""
    sys.path.insert(0, HERE)
    import guest_package
    try:
        written, rec = guest_package.seed(m, args.guest_package, gles=not getattr(args, "no_gles", False),
                                          board=board, log=log)
    except guest_package.GuestPackageError as e:
        raise FirmwareError("guest package: %s" % e)
    log("guest package %s (seed %d): %d paths written, hooks: %s"
        % (rec["family"], rec["seed"], len(written), ", ".join(os.path.basename(h) for h in rec["hooks"]) or "none"))
    return rec


# ---------------------------------------------------------------------------------------------
# Data volume seeding (kboot boards)
# ---------------------------------------------------------------------------------------------
#
# /private/var is its own partition (disk0s2) that the kernel mounts over the rootfs's /private/var.  A real
# restore fills it from the skeleton that ships inside the rootfs (db, log, run, root, mobile, tmp, lib, ...).
# Left as a fresh mkfs.hfsplus it is empty: launchd cannot create /var/db/launchd.db, syslogd/configd/lockdownd/
# SpringBoard have no home and the boot ends in a reboot loop.  So the volume is built here from the finished
# rootfs (after the activation / guest-package / jailbreak edits, whose /private/var files then land on it too).

DATA_MIB = 512              # the data partition's size, as the empty volume had
VAR_REL = "private/var"     # the skeleton's place inside the rootfs


def seed_var_tree(src_root, dst_root, image=None, log=print):
    """Copy <src_root>/private/var into the directory dst_root (the root of the data volume): directories,
    files, symlinks; owner, group, mode and times kept; a decmpfs-compressed file (0 bytes through the driver)
    is decompressed on the way.  `image` is the raw volume behind src_root (see read_hfs_file).  Sockets, FIFOs
    and devices are skipped.  var/run (0755) and var/tmp (1777) are created if the skeleton lacks them.
    -> {"dirs": n, "files": n, "links": n, "decmpfs": n, "skipped": n}"""
    src = os.path.join(src_root, VAR_REL)
    if not os.path.isdir(src):
        raise FirmwareError("the rootfs has no /%s to seed the data volume from" % VAR_REL)
    n = {"dirs": 0, "files": 0, "links": 0, "decmpfs": 0, "skipped": 0}

    def meta(st, dp, link=False):
        try:
            os.lchown(dp, st.st_uid, st.st_gid)      # before chmod: chown clears set-user-ID
        except OSError:
            pass                                     # not root (tests): the mode and times still copy
        if not link:
            os.chmod(dp, stat.S_IMODE(st.st_mode))
        try:
            os.utime(dp, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False)
        except (OSError, NotImplementedError):
            pass

    meta(os.lstat(src), dst_root)
    for cur, dirs, files in os.walk(src):
        rel_dir = os.path.relpath(cur, src)
        out_dir = dst_root if rel_dir == "." else os.path.join(dst_root, rel_dir)
        for name in sorted(dirs + files):
            sp, dp = os.path.join(cur, name), os.path.join(out_dir, name)
            st = os.lstat(sp)
            if stat.S_ISLNK(st.st_mode):
                os.symlink(os.readlink(sp), dp)
                meta(st, dp, link=True)
                n["links"] += 1
            elif stat.S_ISDIR(st.st_mode):
                os.mkdir(dp)
                meta(st, dp)
                n["dirs"] += 1
            elif stat.S_ISREG(st.st_mode):
                if st.st_size == 0:
                    rel = os.path.normpath(os.path.join(VAR_REL, rel_dir, name))
                    try:
                        data, was_compressed = read_hfs_file(src_root, rel, image)
                    except (OSError, FirmwareError, ValueError) as e:
                        log("warning: /%s: could not read its compressed data (%s); copied as an empty file"
                            % (rel, e))
                        data, was_compressed = b"", False
                    with open(dp, "wb") as f:
                        f.write(data)
                    n["decmpfs"] += 1 if was_compressed else 0
                else:
                    shutil.copyfile(sp, dp)
                meta(st, dp)
                n["files"] += 1
            else:
                n["skipped"] += 1
    for d, mode in (("run", 0o755), ("tmp", 0o1777)):
        full = os.path.join(dst_root, d)
        if not os.path.isdir(full):
            os.makedirs(full, exist_ok=True)
            os.chmod(full, mode)
            n["dirs"] += 1
    return n


def seed_data_volume(system_img, work, size_mib=DATA_MIB, log=print):
    """A new case-sensitive HFS+ data volume image of size_mib MiB in `work`, filled from the /private/var of the
    rootfs image `system_img` (mounted read-only; it is left as it is).  Needs root, mkfs.hfsplus and the
    hfsplus module.  Not journaled: Linux cannot write a journaled volume (iOS mounts it fine).
    -> (image path, seed_var_tree's counts)"""
    require_root("seeding the data volume")
    if not shutil.which("mkfs.hfsplus"):
        raise FirmwareError("mkfs.hfsplus not found (apt-get install hfsprogs)")
    img = os.path.join(work, "data.img")
    with open(img, "wb") as f:
        f.truncate(size_mib << 20)            # sparse: mkfs and the copy write only what they need
    r = subprocess.run(["mkfs.hfsplus", "-s", "-v", "Data", img], capture_output=True, text=True)
    if r.returncode:
        raise FirmwareError("mkfs.hfsplus failed: " + (r.stderr.strip() or r.stdout.strip() or str(r.returncode)))
    mnt_data, mnt_sys = os.path.join(work, "mnt_data"), os.path.join(work, "mnt_sys")

    def into_data(dm):
        return with_mounted(system_img, mnt_sys, lambda sm: seed_var_tree(sm, dm, system_img, log), rw=False)
    try:
        counts = with_mounted(img, mnt_data, into_data)
    except OSError as e:
        raise FirmwareError("seeding the data volume failed (%s); the %d MiB volume may be full" % (e, size_mib))
    finally:
        for d in (mnt_sys, mnt_data):
            try:
                os.rmdir(d)
            except OSError:
                pass
    return img, counts


def guest_package_kboot_rootfs(system_img, work, args, board, log=print):
    """The guest-package seed inside the extracted rootfs image of a kboot board.  Needs root + hfsplus."""
    mnt = os.path.join(work, "mnt_gp")
    print("seeding the guest package (loader, agent, GL hook) in the rootfs...")
    try:
        return with_mounted(system_img, mnt, lambda m: seed_guest_package(m, args, board, log))
    except OSError as e:
        raise FirmwareError("the guest package seed failed (%s); the volume inside the image may be full" % e)
    finally:
        try:
            os.rmdir(mnt)
        except OSError:
            pass


def create_kboot(args, entry, ipsw, ri, out, work):
    """Build kboot.bin and NAND store for KBoot boards (n18, n88, n81, n90, k48)."""
    board = ri["board"]
    qemu_machine, tmp_prefix, _, _, _ = BOARD_META[board]
    dec_dir = os.path.join(work, "decrypted")
    os.makedirs(dec_dir, exist_ok=True)

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import ipad1_fw
    import ipad1_kboot
    import ipad1_nand
    import s5l8920_kboot

    # 1. Decrypt firmware components (kernelcache, devicetree, applelogo, iboot, rootfs)
    print("decrypting firmware components using catalog keys...")
    ipad1_fw.decrypt_catalog(args.ipsw, entry, dec_dir, rootfs=True)

    # 2. Synthesize identity
    board_tag = {"n90ap": "n90", "n81ap": "n81", "k48ap": "k48"}.get(board, "k48")
    ident = ipad1_kboot.synth_identity(args.seed or (args.id + "-default"), board=board_tag)
    if args.wifi_mac:
        ident["wifi-mac"] = args.wifi_mac
    ident_path = os.path.join(out, "identity.json")
    with open(ident_path, "w") as f:
        json.dump(ident, f, indent=1)

    # 3. Build kboot.bin
    print("building kboot.bin...")
    kboot_out = os.path.join(out, "kboot.bin")
    boot_args = ipad1_kboot.DEFAULT_BOOT_ARGS
    if getattr(args, "jailbreak", False):
        boot_args = jb_boot_args(boot_args)
    if board in ("n18ap", "n88ap"):
        s5l_b = "n18" if board == "n18ap" else "n88"
        s5l8920_kboot.main(s5l_b, dec_dir, kboot_out, boot_args=boot_args,
                           identity=ident_path, nor=(board == "n18ap"))
    else:
        ipad1_kboot.main(dec_dir, kboot_out, boot_args=boot_args, identity=ident_path)

    # 4. Extract decrypted rootfs volume
    dec_dmg = os.path.join(dec_dir, "rootfs.dmg")
    system_img = os.path.join(work, "system.img")
    print("extracting HFS+ volume from rootfs.dmg...")
    extract_rootfs(dec_dmg, system_img, work)

    # 4b. lockdownd activation (A4 boards, iOS 4.x/5.x): patch the signed lockdownd in the rootfs and
    #     re-sign it, like FirmwareKit's SystemEdits.activate.  Needs root + the Linux hfsplus module.
    ios_major = int((entry.get("version", "0").split(".")[0] or "0")) if entry.get("version", "0")[:1].isdigit() else 0
    if board in _ACTIVATED_KBOOT and ios_major >= 6 and not getattr(args, "skip_activation", False):
        print("note: iOS %s: lockdownd is left stock (the patch is for iOS 3.x-5.x; 6.x+ keeps activation state in "
              "data_ark.plist)" % entry.get("version"))
    elif board in _ACTIVATED_KBOOT and not getattr(args, "skip_activation", False):
        activate_kboot_rootfs(system_img, work)

    # 4b2. the guest package seed (loader, seed package, OpenGLES front end / AppSync hooks).  Needs root + hfsplus.
    if getattr(args, "guest_package", None):
        gp_rec = guest_package_kboot_rootfs(system_img, work, args, board)
        with open(os.path.join(out, "guest_package.json"), "w") as f:
            json.dump(gp_rec, f, indent=1)

    # 4c. the jailbreak option (afc2, Cydia, Substrate), after the activation edit.  Needs root + hfsplus.
    if getattr(args, "jailbreak", False):
        jailbreak_kboot_rootfs(system_img, int(entry.get("recipe", {}).get("system_mib", 1024)), work, args.jb_dir)

    # 4d. the data volume (/private/var), seeded from the finished rootfs's /private/var skeleton, after every
    #     rootfs edit above so their /private/var files land on it.  An empty volume does not boot (launchd cannot
    #     create /var/db/launchd.db and reboots), so a build that cannot seed says so loudly.
    data_img = None
    if getattr(args, "skip_data_seed", False):
        print("note: --skip-data-seed: the data volume is left empty (the device will NOT boot to SpringBoard)")
    elif not shutil.which("mkfs.hfsplus"):
        print("warning: mkfs.hfsplus not found: no data volume to seed (apt-get install hfsprogs)")
    elif hasattr(os, "geteuid") and os.geteuid() != 0:
        print("warning: not root: the data volume is left empty and the device will NOT boot to SpringBoard "
              "(rerun as root, or pass --skip-data-seed to silence this)")
    else:
        print("seeding the data volume from the rootfs's /private/var...")
        data_img, seeded = seed_data_volume(system_img, work)
        print("  /private/var: %(dirs)d directories, %(files)d files (%(decmpfs)d decompressed), %(links)d symlinks"
              % seeded + ("; %d special files skipped" % seeded["skipped"] if seeded["skipped"] else ""))

    # 5. Build NAND store
    print("building NAND store...")
    nand_dir = os.path.join(out, "nand")
    geo_name = "k48-16g-v1" if (board in ("n18ap", "n88ap") and entry.get("version", "").startswith("3.0")) else "k48-16g"
    geo = ipad1_nand.Geo(name=geo_name, **ipad1_nand.GEOMETRIES[geo_name])
    ipad1_nand.WHITENING = False if board in ("n18ap", "n88ap") else True

    recipe = entry.get("recipe", {})
    system_mib = int(recipe.get("system_mib", 1024))
    mbr_bytes = ipad1_nand.make_mbr(geo, system_mib)
    mbr_path = os.path.join(work, "mbr.bin")
    with open(mbr_path, "wb") as f:
        f.write(mbr_bytes)

    class NandArgs:
        pass
    na = NandArgs()
    na.geometry = geo_name
    na.mbr = mbr_path
    na.system = system_img
    na.kernelcache = os.path.join(dec_dir, "kernelcache.mach")
    na.kernel_version = None
    na.data = data_img or ("512m" if shutil.which("mkfs.hfsplus") else "none")
    na.s3 = None
    na.out = nand_dir
    na.force = True
    ipad1_nand.build(na)

    # 6. Writable NOR and keybag provisioning (iOS 4.x+ data protection)
    recipe_opts = recipe.get("options", {})
    writable_nor = recipe_opts.get("writable_nor", False)
    if board in ("n90ap", "n81ap", "k48ap") and entry.get("version", "").startswith(("4.", "5.")):
        writable_nor = True

    nor_path = os.path.join(out, "nor.bin")
    if writable_nor:
        if not os.path.exists(nor_path):
            print("creating blank 1 MiB nor.bin...")
            with open(nor_path, "wb") as f:
                f.write(b"\xff" * (1024 * 1024))

        skip_keybag = getattr(args, "skip_keybag", False)
        if not skip_keybag:
            helper = getattr(args, "helper", None)
            if not helper:
                helper = os.environ.get("IT_KEYBAG")
            if not helper:
                for cand in [
                    os.path.join(ROOT, "build", "ipad1-guest", "it_keybag"),
                    os.path.join(ROOT, "build", "ipod-guest", "it_keybag"),
                    os.path.join(ROOT, "contrib", "it-keybag", "it_keybag"),
                    os.path.join(ROOT, "build", "it_keybag"),
                    os.path.join(ROOT, "tools", "it_keybag"),
                ]:
                    if os.path.isfile(cand):
                        helper = os.path.abspath(cand)
                        break

            # Find restore ramdisk in dec_dir
            ramdisk_dmg = None
            keys_info = entry.get("keys", {})
            for rk in ("RestoreRamDisk", "UpdateRamDisk"):
                finfo = keys_info.get(rk)
                if finfo and finfo.get("file"):
                    cand = os.path.join(dec_dir, os.path.basename(finfo["file"])[:-4] + "-ramdisk.dmg")
                    if os.path.isfile(cand):
                        ramdisk_dmg = cand
                        break
            if not ramdisk_dmg:
                for f in sorted(os.listdir(dec_dir)):
                    if f.endswith("-ramdisk.dmg"):
                        ramdisk_dmg = os.path.join(dec_dir, f)
                        break

            if helper and os.path.isfile(helper) and ramdisk_dmg and os.path.isfile(ramdisk_dmg):
                print("provisioning system keybag and effaceable storage using helper %s..."
                      % os.path.basename(helper))
                run_keybag_provisioning(args, qemu_machine, dec_dir, ident_path,
                                        ramdisk_dmg, helper, nand_dir, nor_path, work)
            else:
                if not helper or not os.path.isfile(helper):
                    print("note: it_keybag helper binary not found. Blank nor.bin created.")
                    print("      To provision keybag automatically, pass --helper /path/to/it_keybag")
                elif not ramdisk_dmg or not os.path.isfile(ramdisk_dmg):
                    print("note: decrypted restore ramdisk not found; blank nor.bin created.")

    # 7. Generate run.sh
    run_body = SH_DIR_LINE
    run_body += _cleanup_trap(tmp_prefix)
    nor_arg = ',nor-rw="$D/nor.bin"' if writable_nor else ""
    run_body += """mkdir -p /tmp/%s-ovl
exec ${QEMU:-qemu-system-arm} \\
  -M %s,kboot="$D/kboot.bin",nand="$D/nand",nand-overlay=/tmp/%s-ovl%s \\
  -serial mon:stdio -display sdl,show-cursor=on -audio driver=none
""" % (tmp_prefix, qemu_machine, tmp_prefix, nor_arg)
    _write_run_sh(os.path.join(out, "run.sh"), run_body)

    nor_desc = "\n  - nor.bin (1 MiB writable NOR flash with effaceable storage)" if writable_nor else ""
    print("""
done: %s
Created bootable bundle:
  - kboot.bin (direct kernel boot bundle)
  - nand/ (offline YaFTL store with MBR + rootfs)%s
  - identity.json
  - run.sh
Run with ./run.sh (mouse cursor visible; /tmp/%s-* cleaned up automatically on exit)."""
          % (out, nor_desc, tmp_prefix))


def run_keybag_provisioning(args, qemu_machine, dec_dir, ident_path,
                            ramdisk_src, helper, nand_dir, nor_path, work):
    """Run restore ramdisk one-shot in QEMU to format effaceable storage in nor.bin
    and create /private/var/keybags/systembag.kb in the NAND store."""
    import ipad1_kboot
    import s5l8920_kboot

    rd_out = os.path.join(work, "ramdisk-helper.dmg")
    print("  preparing restore ramdisk with it_keybag...")
    shutil.copyfile(ramdisk_src, rd_out)

    room = 1 << 20
    new_bytes = (os.path.getsize(rd_out) + room + 4095) & ~4095
    hfs_grow(rd_out, new_bytes)

    mnt = os.path.join(work, "mnt_rd")
    def _install_helper(m):
        target_dir = os.path.join(m, "usr", "local", "bin")
        os.makedirs(target_dir, exist_ok=True)
        target = os.path.join(target_dir, "restored_external")
        # The stock file is HFS+-compressed (UF_COMPRESSED + com.apple.decmpfs). Overwriting its
        # data fork leaves that flag and attribute behind, and iOS then reads the stock binary
        # from the attribute. Unlink first so the new file is a plain uncompressed one.
        if os.path.lexists(target):
            os.unlink(target)
        shutil.copyfile(helper, target)
        os.chmod(target, 0o755)
        try:
            os.chown(target, 0, 0)
        except (PermissionError, AttributeError):
            pass        # not root: the helper stays owned by the user
    with_mounted(rd_out, mnt, _install_helper)
    try:
        os.rmdir(mnt)
    except OSError:
        pass

    kboot_restore = os.path.join(work, "kboot-restore.bin")
    if qemu_machine in ("n18", "n88"):
        s5l8920_kboot.main(qemu_machine, dec_dir, kboot_restore, identity=ident_path,
                           ramdisk=rd_out, nor=True)
    else:
        ipad1_kboot.main(dec_dir, kboot_restore, identity=ident_path, ramdisk=rd_out)

    qemu_bin = getattr(args, "qemu", None)
    if not qemu_bin:
        qemu_bin = os.environ.get("QEMU")
    if not qemu_bin:
        cand = os.path.join(ROOT, "build", "qemu-system-arm")
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            qemu_bin = os.path.abspath(cand)
    if not qemu_bin:
        qemu_bin = shutil.which("qemu-system-arm")
    if not qemu_bin:
        print("warning: QEMU binary not found; skipping keybag one-shot boot.")
        return False

    nand_snap = os.path.join(work, "nand_pre_keybag")
    if os.path.exists(nand_snap):
        shutil.rmtree(nand_snap)
    shutil.copytree(nand_dir, nand_snap)
    nor_orig = open(nor_path, "rb").read()

    timeout = getattr(args, "keybag_timeout", 300) or 300
    serial_log = os.path.join(work, "keybag_boot.log")
    attempts = 3
    done_msg = "it_keybag: effaceable formatted, system keybag created"
    success = False

    for attempt in range(1, attempts + 1):
        log = serial_log if attempt == 1 else f"{serial_log}.{attempt}"
        if os.path.exists(log):
            os.remove(log)

        print(f"  running keybag one-shot boot in QEMU (attempt {attempt}/{attempts})...")
        cmd = [
            qemu_bin,
            "-M", f"{qemu_machine},kboot={kboot_restore},nand={nand_dir},nor-rw={nor_path}",
            "-display", "none",
            "-audio", "driver=none",
            "-monitor", "none",
            "-serial", f"file:{log}",
            "-no-reboot",
        ]
        t0 = time.monotonic()
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=None)
        text = ""
        try:
            while p.poll() is None and (time.monotonic() - t0) < timeout:
                time.sleep(0.5)
                if os.path.exists(log):
                    with open(log, "r", errors="replace") as f:
                        text = f.read()
                    if "panic(" in text:
                        break
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()

        if os.path.exists(log):
            with open(log, "r", errors="replace") as f:
                text = f.read()

        for line in text.splitlines():
            if line.startswith("it_keybag:"):
                print(f"    {line}")

        if done_msg in text:
            success = True
            print(f"  keybag provisioning completed successfully after {time.monotonic() - t0:.1f}s")
            break

        why = "timeout" if p.poll() is None else "halted without expected confirmation"
        for line in text.splitlines():
            if "panic(" in line:
                why = line[line.index("panic("):][:120]
                break
        print(f"  keybag attempt {attempt}/{attempts} failed after {time.monotonic() - t0:.1f}s: {why}")

        if attempt < attempts:
            shutil.rmtree(nand_dir)
            shutil.copytree(nand_snap, nand_dir)
            with open(nor_path, "wb") as f:
                f.write(nor_orig)

    if not success:
        print(f"warning: keybag provisioning did not succeed; serial log in {serial_log}")
    return success


def cmd_provision_keybag(args):
    """Standalone keybag provisioning for an existing bundle directory."""
    bundle = os.path.abspath(args.bundle)
    if not os.path.isdir(bundle):
        raise FirmwareError(f"bundle directory not found: {bundle}")
    nand_dir = os.path.join(bundle, "nand")
    if not os.path.isdir(nand_dir):
        raise FirmwareError(f"bundle has no nand/ directory: {nand_dir}")

    nor_path = os.path.join(bundle, "nor.bin")
    if not os.path.exists(nor_path):
        print(f"creating 1 MiB nor.bin in {bundle}...")
        with open(nor_path, "wb") as f:
            f.write(b"\xff" * (1024 * 1024))

    machine = args.machine
    run_sh = os.path.join(bundle, "run.sh")
    if not machine and os.path.isfile(run_sh):
        content = open(run_sh).read()
        m = re.search(r"-M\s+([a-zA-Z0-9_\-]+)", content)
        if m:
            machine = m.group(1)
    if not machine:
        machine = "iPhone-4"

    helper = args.helper or os.environ.get("IT_KEYBAG")
    if not helper:
        for cand in [
            os.path.join(ROOT, "build", "ipad1-guest", "it_keybag"),
            os.path.join(ROOT, "build", "ipod-guest", "it_keybag"),
            os.path.join(ROOT, "contrib", "it-keybag", "it_keybag"),
            os.path.join(ROOT, "build", "it_keybag"),
            os.path.join(ROOT, "tools", "it_keybag"),
        ]:
            if os.path.isfile(cand):
                helper = os.path.abspath(cand)
                break
    if not helper or not os.path.isfile(helper):
        raise FirmwareError("it_keybag helper binary not found. Specify --helper /path/to/it_keybag")

    ramdisk = os.path.abspath(args.ramdisk)
    if not os.path.isfile(ramdisk):
        raise FirmwareError(f"restore ramdisk not found: {ramdisk}")

    work = tempfile.mkdtemp(prefix="keybag-prov-")
    try:
        ident_path = os.path.join(bundle, "identity.json")
        dec_dir = os.path.abspath(args.dec_dir) if args.dec_dir else work
        if not os.path.isdir(dec_dir):
            raise FirmwareError(f"dec-dir not found: {dec_dir}")

        ok = run_keybag_provisioning(args, machine, dec_dir, ident_path,
                                     ramdisk, helper, nand_dir, nor_path, work)

        if os.path.isfile(run_sh):
            sh_text = open(run_sh).read()
            if "nor-rw=" not in sh_text:
                sh_text = re.sub(r"(-M\s+[^\s\\]+)", r'\1,nor-rw="$D/nor.bin"', sh_text)
                with open(run_sh, "w") as f:
                    f.write(sh_text)
                print('updated run.sh with nor-rw="$D/nor.bin"')
        if ok:
            print(f"done: successfully provisioned nor.bin and keybag for {bundle}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------------------------
# create() dispatcher
# ---------------------------------------------------------------------------------------------

_BOARD_CREATORS = {
    "m68ap": create_img2,
    "n45ap": create_img2,
    "n72ap": create_img3,
    "n18ap": create_kboot,
    "n88ap": create_kboot,
    "k48ap": create_kboot,
    "n81ap": create_kboot,
    "n90ap": create_kboot,
}


def invoking_user():
    """(uid, gid) of the real user when running as root through sudo or pkexec, else None."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    try:
        if os.environ.get("SUDO_UID"):
            uid = int(os.environ["SUDO_UID"])
            return uid, int(os.environ.get("SUDO_GID") or uid)
        if os.environ.get("PKEXEC_UID"):
            import pwd
            uid = int(os.environ["PKEXEC_UID"])
            return uid, pwd.getpwuid(uid).pw_gid
    except (ValueError, KeyError):
        pass
    return None


def hand_back_ownership(path):
    """Give a bundle that was built as root (sudo/pkexec) to the user who asked for it.

    Several boards need root to loop-mount the HFS+ rootfs, which leaves nor.bin, nand/ and the rest
    root-owned; QEMU then fails with "Could not open '.../nor.bin': Permission denied" when the user
    starts the device.  Symlinks are re-owned themselves, never followed.  A no-op when not root or
    when the invoking user is unknown (a real root login).  Returns the number of paths changed."""
    who = invoking_user()
    if who is None or not os.path.isdir(path):
        return 0
    uid, gid = who
    n = 0
    for root, dirs, files in os.walk(path):
        for name in [""] + dirs + files:
            p = os.path.join(root, name) if name else root
            try:
                st = os.lstat(p)
                if st.st_uid != uid or st.st_gid != gid:
                    os.lchown(p, uid, gid)
                    n += 1
            except OSError:
                pass
    return n


def create(args):
    entry = catalog_entry(args.catalog, args.id)
    board = entry.get("board", "")
    if board not in _BOARD_CREATORS:
        raise FirmwareError("%s has board '%s'; supported boards: %s"
                            % (args.id, board, ", ".join(sorted(_BOARD_CREATORS))))
    args.bootrom_path = resolve_bootrom(board, getattr(args, "bootrom", None))
    src = entry["source"]
    ipsw_path = args.ipsw
    if not os.path.exists(ipsw_path):
        raise FirmwareError("%s not found; download it (%s, or a mirror) and pass --ipsw"
                            % (ipsw_path, src.get("url", "?")))
    want = src.get("sha1")
    if getattr(args, "skip_sha1", False):
        print("skipping IPSW SHA-1 verification (--skip-sha1)")
    else:
        got = sha1_file(ipsw_path)
        if want and got != want:
            raise FirmwareError("IPSW SHA-1 is %s, expected %s (use --skip-sha1 to bypass)" % (got, want))
        print("IPSW ok (sha1 %s)" % got)
    ipsw = IPSW(ipsw_path)
    ri = restore_info(ipsw)
    print("%s %s (%s), board %s" % (ri["product"], ri["version"], ri["build"], ri["board"]))
    out = os.path.abspath(args.out)
    if os.path.exists(out) and os.listdir(out):
        raise FirmwareError("%s exists and is not empty; refusing to overwrite" % out)
    if getattr(args, "guest_package", None):
        args.guest_package = os.path.abspath(os.path.expanduser(args.guest_package))
        if not os.path.isfile(args.guest_package):
            raise FirmwareError("--guest-package: %s not found" % args.guest_package)
        if BOARD_META[board][4] == "img3":
            raise FirmwareError("--guest-package: %s's create does not seed a guest package yet (the jailbreak "
                                "and activation edits are supported, this one is not)" % board)
        if getattr(args, "no_volume_edit", False):
            raise FirmwareError("--guest-package edits the volume; it can't be combined with --no-volume-edit")
    if getattr(args, "jailbreak", False):
        if BOARD_META[board][4] == "img3" and getattr(args, "skip_nand", False):
            raise FirmwareError("--jailbreak edits the system volume, which --skip-nand does not build for %s" % board)
        if getattr(args, "no_volume_edit", False):
            raise FirmwareError("--jailbreak edits the volume; it can't be combined with --no-volume-edit")
        if int(ri["version"].split(".")[0] or 0) < 2:
            raise FirmwareError("--jailbreak needs iPhone OS 2.0 or later (this IPSW is %s)" % ri["version"])
        args.jb_dir = jb_fetch(os.path.abspath(os.path.expanduser(getattr(args, "jailbreak_cache", None)
                                                                  or jb_default_cache())))
    os.makedirs(out, exist_ok=True)
    tmp_prefix = BOARD_META[board][1]
    work = args.work or tempfile.mkdtemp(prefix=tmp_prefix + "-", dir=args.tmpdir)
    os.makedirs(work, exist_ok=True)
    try:
        _BOARD_CREATORS[board](args, entry, ipsw, ri, out, work)
    finally:
        n = hand_back_ownership(out)       # also after a failure: no root-owned leftovers to clean up
        if n:
            print("ownership of %s returned to the invoking user (%d paths)" % (out, n))


# ---------------------------------------------------------------------------------------------
# synthetic lockdownd look-alikes (test helpers for selftest / difftest)
# ---------------------------------------------------------------------------------------------
SYN_BASE, SYN_TEXT_OFF, SYN_TEXT_SIZE = 0x1000, 0x100, 0x400


class _Synth:
    def __init__(self):
        self.text = bytearray(SYN_TEXT_SIZE)
        self.data = bytearray()

    # data (after the text, inside the same segment)
    def _dva(self, off):
        return SYN_BASE + SYN_TEXT_OFF + SYN_TEXT_SIZE + off

    def cstr(self, s):
        va = self._dva(len(self.data))
        self.data += s.encode() + b"\0"
        while len(self.data) % 4:
            self.data += b"\0"
        return va

    def cfstr(self, text):
        c = self.cstr(text)
        va = self._dva(len(self.data))
        self.data += struct.pack("<IIII", 0, 0x7C8, c, len(text))
        return va

    def tva(self, off):
        return SYN_BASE + SYN_TEXT_OFF + off

    def word(self, off, w):
        struct.pack_into("<I", self.text, off, w & 0xFFFFFFFF)

    def half(self, off, h):
        struct.pack_into("<H", self.text, off, h)

    def nops(self, lo, hi):
        for o in range(lo, hi, 4):
            if self.text[o:o + 4] == bytes(4):
                self.word(o, 0xE1A00000)

    def build(self):
        total = SYN_TEXT_OFF + SYN_TEXT_SIZE + len(self.data)
        hdr = struct.pack("<7I", 0xFEEDFACE, 12, 6, 2, 1, 124, 0)
        seg = struct.pack("<II16sIIIIIIII", 1, 124, b"__TEXT", SYN_BASE, total, 0, total, 7, 5, 1, 0)
        sec = struct.pack("<16s16sIIIIIIIII", b"__text", b"__TEXT", SYN_BASE + SYN_TEXT_OFF, SYN_TEXT_SIZE, SYN_TEXT_OFF, 2, 0, 0, 0, 0, 0)
        b = bytearray(total)
        b[0:len(hdr + seg + sec)] = hdr + seg + sec
        b[SYN_TEXT_OFF:SYN_TEXT_OFF + SYN_TEXT_SIZE] = self.text
        b[SYN_TEXT_OFF + SYN_TEXT_SIZE:] = self.data
        return bytes(b)


def _arm_ldr_lit(rd, instr_va, pool_va, cond=0xE):
    delta = pool_va - (instr_va + 8)
    return (cond << 28) | 0x051F0000 | (rd << 12) | (0x800000 if delta >= 0 else 0) | abs(delta)


def _arm_b(cond, from_va, to_va, link=False):
    off = ((to_va - (from_va + 8)) // 4) & 0xFFFFFF
    return (cond << 28) | 0x0A000000 | (0x01000000 if link else 0) | off


def _t_ldr_lit(rd, instr_va, pool_va):
    return 0x4800 | (rd << 8) | ((pool_va - ((instr_va + 4) & ~3)) // 4)


def _t_bl(from_va, to_va):
    d = to_va - (from_va + 4)
    s = 1 if d < 0 else 0
    i1, i2 = (d >> 23) & 1, (d >> 22) & 1
    j1, j2 = 1 ^ i1 ^ s, 1 ^ i2 ^ s
    return (0xF000 | (s << 10) | ((d >> 12) & 0x3FF), 0xD000 | (j1 << 13) | (j2 << 11) | ((d >> 1) & 0x7FF))


def _kind_conditional(flag=1, state=2, at=0x20):
    """iPhone OS 1.0: cmp r0,#0 ; moveq flag,#1 ; ldreq state,=Unactivated ; ... ; beq store."""
    s = _Synth()
    unact, act, notchg = s.cfstr("Unactivated"), s.cfstr("Activated"), s.cstr("The activation state has not changed.")
    pool = 0x200
    s.word(pool, unact), s.word(pool + 4, act), s.word(pool + 8, notchg)
    V = s.tva(at)
    s.word(at - 8, 0xE3500000)
    s.word(at - 4, 0x03A00001 | (flag << 12))
    s.word(at, _arm_ldr_lit(state, V, s.tva(pool), cond=0x0))
    dest = at + 0x40
    s.word(at + 4, _arm_b(0x0, V + 4, s.tva(dest)))
    s.word(dest, _arm_ldr_lit(3, s.tva(dest), s.tva(pool + 8)))
    s.nops(0, 0x180)
    return s.build()


def _kind_legacy_early(flag=1, state=2, at=0x80, s1=8, s2=12):
    s = _Synth()
    unact, act, fn = s.cfstr("Unactivated"), s.cfstr("Activated"), s.cstr("determine_activation_state")
    pool = 0x200
    s.word(pool, unact), s.word(pool + 4, act), s.word(pool + 8, fn)
    V = s.tva(at)
    s.word(at - 60, _arm_ldr_lit(5, s.tva(at - 60), s.tva(pool + 8)))  # names determine_activation_state, within 4096 before
    s.word(at - 12, 0xE3500000)
    s.word(at - 8, 0xE1A00001)
    s.word(at - 4, 0x1A000004)
    s.word(at, _arm_ldr_lit(state, V, s.tva(pool), cond=0xE))
    s.word(at + 4, 0xE3A00001 | (flag << 12))
    s.word(at + 8, 0xE58D0000 | (flag << 12) | s1)
    s.word(at + 12, 0xE58D0000 | (state << 12) | s2)
    dest = at + 0x40
    s.word(at + 16, _arm_b(0xE, V + 16, s.tva(dest)))
    s.word(dest, 0xE1A00000)
    s.nops(0, 0x180)
    return s.build()


def _kind_legacy_b(flag=1, state=2, at=0x80, s1=8, s2=12, s3=16):
    s = _Synth()
    unact, act, fn = s.cfstr("Unactivated"), s.cfstr("Activated"), s.cstr("determine_activation_state")
    pool = 0x200
    s.word(pool, unact), s.word(pool + 4, act), s.word(pool + 8, fn)
    V = s.tva(at)
    s.word(at - 60, _arm_ldr_lit(5, s.tva(at - 60), s.tva(pool + 8)))
    s.word(at - 8, 0xE3500000 | (flag << 16))
    s.word(at - 4, 0x1A000005)
    s.word(at, _arm_ldr_lit(state, V, s.tva(pool)))
    s.word(at + 4, 0xE58D0000 | (flag << 12) | s1)
    s.word(at + 8, 0xE58D0000 | (flag << 12) | s2)
    s.word(at + 12, 0xE2800001 | (flag << 12) | (flag << 16))
    s.word(at + 16, 0xE58D0000 | (state << 12) | s3)
    dest = at + 0x40
    s.word(at + 20, _arm_b(0xE, V + 20, s.tva(dest)))
    s.word(dest, 0xE1A00000)
    s.nops(0, 0x180)
    return s.build()


def _kind_shared(flag=1, state=2, at=0x80, s1=8, s2=12, s3=16):
    """2.x iPod: the no-record block jumps to a shared state store."""
    s = _Synth()
    unact, act = s.cfstr("Unactivated"), s.cfstr("Activated")
    fn, msg = s.cstr("determine_activation_state"), s.cstr("There is no activation record?")
    pool = 0x200
    s.word(pool, unact), s.word(pool + 4, act), s.word(pool + 8, fn), s.word(pool + 12, msg)
    V = s.tva(at)
    s.word(at - 60, _arm_ldr_lit(5, s.tva(at - 60), s.tva(pool + 8)))
    s.word(at - 36, 0xE3500000 | (flag << 16))
    s.word(at - 32, 0x1A000000)
    s.word(at - 28, _arm_ldr_lit(0, s.tva(at - 28), s.tva(pool + 8)))
    s.word(at - 24, _arm_ldr_lit(1, s.tva(at - 24), s.tva(pool + 12)))
    s.word(at - 20, 0xEB000000)
    s.word(at - 12, 0xEB000000)
    s.word(at - 8, 0xE3500000)
    s.word(at - 4, 0x1A000000)
    s.word(at, _arm_ldr_lit(state, V, s.tva(pool)))
    s.word(at + 4, 0xE58D0000 | (flag << 12) | s1)
    s.word(at + 8, 0xE58D0000 | (flag << 12) | s2)
    s.word(at + 12, 0xE2800001 | (flag << 12) | (flag << 16))
    dest = at + 0x40
    s.word(at + 16, _arm_b(0xE, V + 16, s.tva(dest)))
    s.word(dest, 0xE58D0000 | (state << 12) | s3)
    s.nops(0, 0x180)
    return s.build()


def _kind_thumb_dev(take=False):
    s = _Synth()
    fn, msg = s.cstr("dealwith_activation"), s.cfstr("x")
    mstr = s.cstr("Short circuiting activation state to Activated.")
    pool = 0x200
    s.word(pool, fn), s.word(pool + 4, mstr)
    at = 0x20
    s.half(at, 0x2800)  # cmp r0,#0
    s.half(at + 2, 0xD000 | 3)  # beq.n +6 -> at+0xC
    s.half(at + 4, _t_ldr_lit(0, s.tva(at + 4), s.tva(pool)))
    s.half(at + 6, _t_ldr_lit(1, s.tva(at + 6), s.tva(pool + 4)))
    h1, h2 = _t_bl(s.tva(at + 8), s.tva(0x100))
    s.half(at + 8, h1), s.half(at + 10, h2)
    s.nops(0, 0x180)
    return s.build()


def _kind_arm_dev():
    s = _Synth()
    fn = s.cstr("dealwith_activation")
    mstr = s.cstr("Short circuiting activation state to Activated.")
    pool = 0x200
    s.word(pool, fn), s.word(pool + 4, mstr)
    at = 0x20
    V = s.tva(at)
    s.word(at, 0xE3500000)  # cmp r0,#0
    s.word(at + 4, _arm_b(0x0, V + 4, s.tva(at + 0x20)))  # beq far
    s.word(at + 8, _arm_ldr_lit(0, s.tva(at + 8), s.tva(pool)))
    s.word(at + 12, _arm_ldr_lit(1, s.tva(at + 12), s.tva(pool + 4)))
    s.word(at + 16, _arm_b(0xE, s.tva(at + 16), s.tva(0x100), link=True))
    s.nops(0, 0x180)
    return s.build()


def _synth_signed(data, hash_type=1, cms=True, junk=0xAA):
    """A synthetic lockdownd with an LC_CODE_SIGNATURE: a SuperBlob holding one CodeDirectory (2 special
    slots, 4 KiB pages, deliberately wrong page hashes) and, with cms=True, a CMS blob.  -> (bytes, start, size)."""
    hsz = 20 if hash_type == 1 else 32
    start = len(data)
    nslots = (start + 4095) // 4096
    ident = b"lockdownd\0\0\0"  # 12 bytes
    hash_off = 44 + len(ident) + 2 * hsz
    cd = bytearray(hash_off + nslots * hsz)
    struct.pack_into(">IIIIIIIII", cd, 0, 0xFADE0C02, len(cd), 0x20001, 0, hash_off, 44, 2, nslots, start)
    cd[36], cd[37], cd[38], cd[39] = hsz, hash_type, 0, 12
    cd[44:44 + len(ident)] = ident
    for i in range(2 * hsz):
        cd[44 + len(ident) + i] = 0x5A  # special slots: must survive untouched
    for i in range(nslots * hsz):
        cd[hash_off + i] = junk
    n = 2 if cms else 1
    body = bytearray()
    index = [(0, 12 + n * 8)]
    body += cd
    if cms:
        index.append((0x10000, 12 + n * 8 + len(cd)))
        body += struct.pack(">II", 0xFADE0B01, 16) + bytes(8)
    sb = bytearray(struct.pack(">III", 0xFADE0CC0, 12 + n * 8 + len(body), n))
    for t, o in index:
        sb += struct.pack(">II", t, o)
    sb += body
    size = len(sb) + 16  # a little spare allocation, as the signer leaves
    b = bytearray(data)
    b[0x10:0x14] = struct.pack("<I", 2)           # ncmds
    b[0x14:0x18] = struct.pack("<I", 124 + 16)    # sizeofcmds
    b[152:168] = struct.pack("<IIII", 0x1D, 16, start, size)
    return bytes(b) + bytes(sb) + bytes(size - len(sb)), start, size


def _sig_pages_ok(b, start, hash_type=1):
    """Every code-directory page hash matches the bytes it covers (the synthetic layout above)."""
    hsz = 20 if hash_type == 1 else 32
    algo = hashlib.sha1 if hash_type == 1 else hashlib.sha256
    cd = start + _be32(b, start + 16)
    hash_off, nslots, limit = struct.unpack_from(">III", b, cd + 16)[0], struct.unpack_from(">I", b, cd + 28)[0], \
        struct.unpack_from(">I", b, cd + 32)[0]
    return all(bytes(b[cd + hash_off + i * hsz:cd + hash_off + (i + 1) * hsz])
               == algo(bytes(b[i * 4096:min(limit, (i + 1) * 4096)])).digest() for i in range(nslots))


SYNTH_KINDS = {
    "conditional": _kind_conditional, "legacy_early": _kind_legacy_early, "legacy_b": _kind_legacy_b,
    "shared": _kind_shared, "thumb_dev": _kind_thumb_dev, "arm_dev": _kind_arm_dev,
}


def difftest(args):
    """Compare activate_lockdownd with the C original on the synthetic binaries and on mutated copies."""
    import json as _json
    import random
    C = os.path.join(tempfile.mkdtemp(), "act_c")
    subprocess.run(["cc", "-O2", "-o", C, args.c_source], check=True)

    def run_c(data):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        r = subprocess.run([C, "--probe", path], capture_output=True, text=True)
        os.unlink(path)
        if r.returncode:
            return ("fail",)
        j = _json.loads(r.stdout)
        return ("ok", j["strategy"], j["isa"], j["file_offset"], j["size"], j["old"], j["new"])

    def run_py(data):
        try:
            _, rep = activate_lockdownd(data, resign=False)
            return ("ok", rep["strategy"], rep["isa"], rep["offset"], rep["width"], rep["original"], rep["replacement"])
        except ActivationError:
            return ("fail",)

    rnd = random.Random(args.seed)
    bad = 0
    for name, fn in SYNTH_KINDS.items():
        base = fn()
        c, p = run_c(base), run_py(base)
        print("%-14s base: %s" % (name, "MATCH" if c == p else "MISMATCH %s %s" % (c, p)))
        bad += c != p
        if p[0] == "ok":
            patched, _ = activate_lockdownd(base, resign=False)
            bad += run_c(patched) != run_py(patched)
        variants = [dict(flag=3, state=4), dict(flag=5, state=0), dict(at=0xA0)]
        for kw in variants if name in ("conditional", "legacy_early", "legacy_b", "shared") else []:
            d = fn(**kw)
            bad += run_c(d) != run_py(d)
        counts = {"ok": 0, "fail": 0}
        for _ in range(args.mutations):
            d = bytearray(base)
            for _ in range(rnd.choice([1, 1, 2, 3])):
                o = SYN_TEXT_OFF + rnd.randrange(0, 0xE0)
                d[o] = rnd.randrange(256) if rnd.random() < .7 else d[o] ^ (1 << rnd.randrange(8))
            c, p = run_c(bytes(d)), run_py(bytes(d))
            counts[c[0]] += 1
            if c != p:
                bad += 1
                if bad < 6:
                    print("  mutation mismatch:", c, p)
        print("   %d mutations: %s" % (args.mutations, counts))
    print("MISMATCHES:", bad)
    return 1 if bad else 0


# ---------------------------------------------------------------------------------------------
# self tests
# ---------------------------------------------------------------------------------------------


def selftest(_args):
    import random
    import shutil
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        print("%-62s %s %s" % (name, "ok" if cond else "FAIL", extra if not cond else ""))
        ok &= bool(cond)

    # AES: the pure-python round function against OpenSSL, using the ordinary key schedule
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    for klen in (16, 32):
        key = bytes(random.Random(klen).randrange(256) for _ in range(klen))
        blk = bytes(range(16))
        ref = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(blk)
        check("AES-%d core == OpenSSL (standard schedule)" % (klen * 8),
              bytes(AESCore(list(key), decrypt_schedule=False).encrypt_block(list(blk))) == ref)
    # FIPS-197 vector
    fk = hexb("000102030405060708090a0b0c0d0e0f")
    check("AES-128 FIPS-197 vector", bytes(AESCore(list(fk), False).encrypt_block(list(hexb("00112233445566778899aabbccddeeff"))))
          == hexb("69c4e0d86a7b0430d8cdb78070b4c55a"))

    # 8900 container, format 3 and 4, with a clear tail
    payload = bytes(range(200))
    for fmt in (3, 4):
        n = len(payload) & ~15
        body = aes_cbc(payload[:n], KEY_837, bytes(16), decrypt=False) + payload[n:] if fmt == 3 else payload
        hdr = bytearray(0x800)
        hdr[0:4], hdr[4:7], hdr[7] = b"8900", b"1.0", fmt
        put32(hdr, 0xC, len(payload))
        check("8900 format %d round trip" % fmt, apple8900_body(bytes(hdr) + body) == payload)

    # IMG2 + NOR signing structure
    def fake_img2(typ, n=0x30):
        b = bytearray(IMG2_HEADER + n)
        b[0:4] = b"2gmI"
        b[4:8] = typ.encode()[::-1]
        put32(b, 0xC, 0x18000000)
        put32(b, 0x10, n)
        put32(b, 0x14, n)
        return bytes(b)
    images = {t: fake_img2(t) for t in NOR_ORDER}
    ident = synthesize_iphone("selftest")
    nor = build_nor(ident, images)
    check("NOR is 1 MiB, SysCfg 'gfCS', IMG2 directory '2GMI'",
          len(nor) == NOR_SIZE and nor[0x4000:0x4004] == b"gfCS" and nor[NOR_DIR:NOR_DIR + 4] == b"2GMI")
    check("NOR directory CRC", le32(nor, NOR_DIR + 0x30) == crc(nor[NOR_DIR:NOR_DIR + 0x30]))
    first = NOR_FIRST_BLOCK * NOR_BLOCK
    check("first IMG2 in NOR is signed (header CRC valid, block count set)",
          le32(nor, first + 0x64) == crc(nor[first:first + 0x64]) and le32(nor, first + 0x18) == (IMG2_HEADER + 0x30) // 64 + 5)
    nv = bytes(nor[NOR_NVRAM:NOR_NVRAM + NOR_NVRAM_BANK])
    check("nvram carries boot-args, wifiaddr, btaddr, valid adler32",
          b"boot-args=" + BOOT_ARGS.encode() in nv and ("wifiaddr=" + ident["wifi-mac"].upper()).encode() in nv
          and b"btaddr=" in nv and le32(nv, 0x10) == zlib.adler32(nv[0x14:]) & 0xFFFFFFFF)
    try:
        build_nor(ident, {t: images[t] for t in NOR_ORDER[:-1]})
        check("NOR refuses a missing image type", False)
    except FirmwareError:
        check("NOR refuses a missing image type", True)
    ident_nobt = {k: v for k, v in ident.items() if k != "bt-mac"}
    check("NOR without bt-mac has no btaddr", b"btaddr" not in build_nor(ident_nobt, images)[NOR_NVRAM:NOR_NVRAM + NOR_NVRAM_BANK])

    # NAND (the Swift N45Tests ported)
    check("location(lpn 5, 4 banks)", location_lpn(5, 4) == (1, (201 + 23) * 128 + 1))
    d = tempfile.mkdtemp(prefix="m68-selftest-")
    try:
        ps = superblock(4)
        vol = os.path.join(d, "volume.img")
        with open(vol, "wb") as f:
            f.write(bytes((2 * ps - 3) * PAGE))
        out = os.path.join(d, "nand")
        written, _ = write_nand(vol, out, 0x43303030, 4, True)
        check("iPhone NAND: pages written == 2*ps-3", written == 2 * ps - 3)
        check("iPhone NAND: only bank0..3", sorted(os.listdir(out)) == ["bank0", "bank1", "bank2", "bank3"])
        bbt = open(os.path.join(out, "bank3", "%d.page" % (4095 * 128)), "rb").read()
        check("BBT: signature, length 0x200, good-block bitmap",
              bbt[:13] == b"DEVICEINFOBBT" and bbt[0x34] == 0 and bbt[0x35] == 2 and bbt[0x38] == 0xFF and bbt[0x38 + 511] == 0x7F)
        fil = open(os.path.join(out, "bank0", "0.page"), "rb").read()
        check("FIL id 'C000' (little-endian '000C')", fil[:4] == b"000C")
        n45 = metadata_pages(16, 0x43303032, 8, False)[(0, 4095 * 128)]
        check("8-bank BBT without bitmap", n45[0x34] == 0 and n45[0x38] == 0)
        # 8-bank, 3 superblocks
        ps8 = superblock(8)
        fs_pages = 3 * ps8 - 3
        vol8 = os.path.join(d, "v8.img")
        v = bytearray(fs_pages * PAGE)
        for i, val in [(0, 0x48), (2 * ps8, 0x11), (fs_pages - 1, 0x7F)]:
            v[i * PAGE:i * PAGE + 4] = bytes([val]) * 4
        open(vol8, "wb").write(v)
        out8 = os.path.join(d, "nand8")
        written, meta = write_nand(vol8, out8, 0x43303032, 8, False)
        check("8-bank NAND: written == 3*ps-3 and 82 metadata pages", written == 3 * ps8 - 3 and meta == 1 + 8 + 64 + 1 + 4 + 1 + 3, "meta=%d" % meta)
        absent = [l for l in range(3 * ps8) if not os.path.exists(os.path.join(out8, "bank%d" % location_lpn(l, 8)[0], "%d.page" % location_lpn(l, 8)[1]))]
        check("every logical page of the volume present, none beyond", not absent and not os.path.exists(
            os.path.join(out8, "bank%d" % location_lpn(3 * ps8, 8)[0], "%d.page" % location_lpn(3 * ps8, 8)[1])))
        maps = {}
        for bank in range(8):
            for bp in range(PAGES_PER_BLOCK):
                p = os.path.join(out8, "bank%d" % bank, "%d.page" % (FTL_START * PAGES_PER_BLOCK + bp))
                if os.path.exists(p):
                    raw = open(p, "rb").read()
                    if len(raw) == PAGE + SPARE and raw[PAGE + 9] == 0x46:
                        maps[raw[PAGE + 4] | raw[PAGE + 5] << 8] = raw[:PAGE]
        ent = lambda lbn: maps[lbn // 1024][2 * (lbn % 1024)] | maps[lbn // 1024][2 * (lbn % 1024) + 1] << 8
        check("FTL map pages 0-3; entries (23, 3822, 0xFFFF)", sorted(maps) == [0, 1, 2, 3] and ent(0) == 23 and ent(3799) == 3822 and ent(3800) == 0xFFFF and ent(4095) == 0xFFFF)
        lp = lambda l: open(os.path.join(out8, "bank%d" % location_lpn(l, 8)[0], "%d.page" % location_lpn(l, 8)[1]), "rb").read()
        check("volume data lands at lpn+3; spare carries the lpn",
              lp(3)[:4] == bytes([0x48]) * 4 and lp(2 * ps8 + 3)[:4] == bytes([0x11]) * 4 and le32(lp(3), PAGE) == 3)
        check("MBR/GPT pages (0xEE, 'EFI PART')", lp(0)[0x1BE + 4] == 0xEE and lp(1)[:8] == b"EFI PART")
        gpt = lp(1)
        check("GPT header CRC", le32(gpt, 0x10) == (lambda h: crc(h[:0x10] + bytes(4) + h[0x14:0x5C]))(gpt))
        back = os.path.join(d, "back.img")
        nand_extract(out8, back)
        check("nand-extract returns the volume that write_nand was given", open(back, "rb").read() == bytes(v))
        # filID
        ib = bytes(64)
        try:
            fil_id(ib)
            check("fil_id refuses an iBoot without a literal", False)
        except FirmwareError:
            check("fil_id refuses an iBoot without a literal", True)
        check("fil_id finds 'C002'", fil_id(bytes(16) + struct.pack("<I", 0x43303032) + bytes(8)) == 0x43303032)

        # kernelcache path
        kc = b"junk\0/System/Library/Caches/com.apple.kernelcaches/kernelcache.s5l8900x\0more"
        check("kernelcache path from iBoot", kernelcache_path(kc) == "System/Library/Caches/com.apple.kernelcaches/kernelcache.s5l8900x")
        check("daemons: kept set, iPhone keeps BTServer, iPod drops it",
              removed_daemons(["com.apple.BTServer.plist", "com.apple.iapd.plist", "com.apple.SpringBoard.plist"], True) == ["com.apple.iapd.plist"]
              and removed_daemons(["com.apple.BTServer.plist"], False) == ["com.apple.BTServer.plist"])

        # vfdecrypt
        key36 = bytes(range(36))
        plain = bytes(random.Random(5).randrange(256) for _ in range(10000 * 3 + 111))
        bs = 4096
        chunks = []
        for n, o in enumerate(range(0, len(plain), bs)):
            piece = plain[o:o + bs]
            pad = (-len(piece)) % 16
            iv = hmac.new(key36[16:], struct.pack(">I", n), hashlib.sha1).digest()[:16]
            chunks.append(aes_cbc(piece + bytes(pad), key36[:16], iv, decrypt=False))
        hdr = bytearray(0x1000)
        hdr[0:8] = b"encrcdsa"
        hdr[52:56] = struct.pack(">I", bs)
        hdr[56:64] = struct.pack(">Q", len(plain))
        hdr[64:72] = struct.pack(">Q", 0x1000)
        enc_path, dec_path = os.path.join(d, "enc"), os.path.join(d, "dec")
        open(enc_path, "wb").write(bytes(hdr) + b"".join(chunks))
        with open(enc_path, "rb") as s, open(dec_path, "wb") as t:
            vfdecrypt(s, t, key36)
        check("vfdecrypt round trip (data offset 0x1000, partial last chunk)", open(dec_path, "rb").read() == plain)

        # HFS+ grow, checked with the real fsck.hfsplus
        if shutil.which("mkfs.hfsplus") and shutil.which("fsck.hfsplus"):
            for label, mk, size_mb, new_mb in [("HFS+ 16M->64M (allocation file must move)", ["-b", "4096"], 16, 64),
                                               ("HFSX 64M->512M", ["-s", "-b", "4096"], 64, 512),
                                               ("HFS+ 300M->512M", ["-b", "4096"], 300, 512)]:
                img = os.path.join(d, "g.img")
                with open(img, "wb") as f:
                    f.truncate(size_mb << 20)
                subprocess.run(["mkfs.hfsplus"] + mk + ["-v", "T", img], check=True, capture_output=True)
                pre = subprocess.run(["fsck.hfsplus", "-fn", img], capture_output=True, text=True)
                hfs_grow(img, new_mb << 20)
                post = subprocess.run(["fsck.hfsplus", "-fn", img], capture_output=True, text=True)
                with open(img, "rb") as f:
                    f.seek(1024)
                    vh = f.read(512)
                check("grow %s" % label, pre.returncode == 0 and post.returncode == 0 and be32(vh, _O_TOTAL) * be32(vh, _O_BS) == new_mb << 20 and os.path.getsize(img) == new_mb << 20,
                      post.stdout[-300:] + post.stderr[-300:])
                os.remove(img)
        else:
            print("(mkfs.hfsplus/fsck.hfsplus not installed: HFS+ grow tests skipped)")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    # activation patch (the 1.0 conditional initializer), on a synthetic Mach-O
    if True:
        for kind in ("conditional", "legacy_early", "legacy_b", "shared"):
            data = SYNTH_KINDS[kind]()
            try:
                out, rep = activate_lockdownd(data, resign=False)
                good = rep["strategy"].endswith("no-record-initializer") and len(out) == len(data) and out != data
                if kind == "conditional":
                    o = rep["offset"]
                    w0, w1 = le32(out, o), le32(out, o + 4)
                    good = good and w0 == 0x03A01000 and w1 & 0xFF7FF000 == 0x051F2000 and rep["width"] == 8
                    good = good and not any(out[i] != data[i] for i in range(len(data)) if not o <= i < o + 8)
                ok_ = good
            except FirmwareError as e:
                ok_ = False
            check("activation: %s lockdownd patched in place" % kind, ok_)
        data = SYNTH_KINDS["conditional"]()
        out, _ = activate_lockdownd(data)
        try:
            activate_lockdownd(out)
            check("activation: refuses an already-patched lockdownd", False)
        except ActivationError:
            check("activation: refuses an already-patched lockdownd", True)
        for name, junk in [("a non-Mach-O", bytes(200)), ("a Mach-O with no activation path", _Synth().build())]:
            try:
                activate_lockdownd(junk)
                check("activation: refuses %s" % name, False)
            except ActivationError:
                check("activation: refuses %s" % name, True)
        try:
            activate_lockdownd(SYNTH_KINDS["thumb_dev"](), allow_signed_era=False)
            check("activation: signed-era match refused without allow_signed_era", False)
        except ActivationError:
            check("activation: signed-era match refused without allow_signed_era", True)
        # a bogus (empty) signature allocation is refused, never half-signed
        sig = bytearray(SYNTH_KINDS["conditional"]())
        sig[0x14:0x18] = struct.pack("<I", 124 + 16)           # sizeofcmds
        sig[0x10:0x14] = struct.pack("<I", 2)                  # ncmds
        sig[152:168] = struct.pack("<IIII", 0x1D, 16, 0, 0)    # LC_CODE_SIGNATURE, empty
        try:
            activate_lockdownd(bytes(sig))
            check("activation: refuses an unusable code signature", False)
        except ActivationError as e:
            check("activation: refuses an unusable code signature", "signature" in str(e), str(e))
        # signed-era firmware (iOS 4/5, the A4 boards): patched, then re-signed ad hoc
        for kind in ("conditional", "thumb_dev", "shared"):
            for ht in (1, 2):
                base = SYNTH_KINDS[kind]()
                signed, start, size = _synth_signed(base, hash_type=ht)
                try:
                    out, rep = activate_lockdownd(signed)
                except FirmwareError as e:
                    check("activation: %s signed (hash %d) is patched and re-signed" % (kind, ht), False, str(e))
                    continue
                o, w = rep["offset"], rep["width"]
                cd = start + _be32(out, start + 16)
                special = 44 + 12
                good = (len(out) == len(signed) and rep["resigned"]
                        and _sig_pages_ok(out, start, ht)                                  # hashes cover the patched pages
                        and out[o:o + w] == bytes.fromhex(rep["replacement"])              # the patch is in
                        and le32(out, 0) == 0xFEEDFACE
                        and struct.unpack_from(">I", out, cd + 12)[0] & 2                   # CS_ADHOC set
                        and struct.unpack_from(">I", out, start + 8)[0] == 1               # CMS entry dropped
                        and bytes(out[cd + special:cd + special + 2 * (20 if ht == 1 else 32)])
                        == bytes([0x5A]) * (2 * (20 if ht == 1 else 32))                  # special slots untouched
                        and out[:start] != signed[:start])
                check("activation: %s signed (hash %d) is patched and re-signed" % (kind, ht), good)
        base = SYNTH_KINDS["conditional"]()
        signed, start, size = _synth_signed(base, cms=False)
        out, rep = activate_lockdownd(signed)
        check("activation: a signature without a CMS blob is refreshed too",
              _sig_pages_ok(out, start) and struct.unpack_from(">I", out, start + 8)[0] == 1)
        out2, rep2 = activate_lockdownd(base)
        check("activation: unsigned 1.x lockdownd stays unsigned", not rep2["resigned"] and len(out2) == len(base))
        try:
            activate_lockdownd(SYNTH_KINDS["thumb_dev"]())
            check("activation: signed-era match with no signature allocation is refused", False)
        except ActivationError as e:
            check("activation: signed-era match with no signature allocation is refused", "signature" in str(e), str(e))
        bad, _, _ = _synth_signed(SYNTH_KINDS["conditional"]())
        mangled = bytearray(bad)
        mangled[len(SYNTH_KINDS["conditional"]()) + 4:len(SYNTH_KINDS["conditional"]()) + 8] = b"\xff\xff\xff\xff"
        try:
            activate_lockdownd(bytes(mangled))
            check("activation: a corrupt SuperBlob is refused", False)
        except ActivationError:
            check("activation: a corrupt SuperBlob is refused", True)

        # fat (universal) lockdownd, as iOS 4.x ships it: armv6 + armv7 slices
        def _fat(slices):
            hdr = struct.pack(">II", 0xCAFEBABE, len(slices))
            body, pos, ents = b"", 0x4000, b""
            for sub, blob in slices:
                ents += struct.pack(">5I", 12, sub, pos, len(blob), 14)
                body += bytes(pos - 0x4000 - len(body)) + blob
                pos = (pos + len(blob) + 0x3FFF) & ~0x3FFF
            raw = hdr + ents
            return raw + bytes(0x4000 - len(raw)) + body
        v7, start7, _ = _synth_signed(SYNTH_KINDS["conditional"]())
        v6 = _Synth().build()                       # a stock armv6 slice with no activation path
        fat = _fat([(6, v6), (9, v7)])
        try:
            out, rep = activate_lockdownd(fat)
            o7 = 0x4000 + (len(v6) + 0x3FFF & ~0x3FFF)
            sl = out[o7:o7 + len(v7)]
            good = (len(out) == len(fat) and rep["slice"] == "armv9" and len(rep["skipped_slices"]) == 1
                    and out[0x4000:0x4000 + len(v6)] == v6                              # armv6 untouched
                    and sl != v7 and _sig_pages_ok(sl, start7, 1)                       # armv7 patched, re-signed
                    and out[:0x4000] == fat[:0x4000]                                    # fat header intact
                    and rep["offset"] >= o7 and rep["resigned"])
        except FirmwareError as e:
            good = False
            print("    ", e)
        check("activation: fat lockdownd: armv7 slice patched and re-signed, armv6 left stock", good)
        try:
            activate_lockdownd(_fat([(6, v7), (9, v6)]))
            check("activation: fat lockdownd: unpatchable armv7 slice is refused", False)
        except ActivationError as e:
            check("activation: fat lockdownd: unpatchable armv7 slice is refused", "armv9" in str(e), str(e))
        out, rep = activate_lockdownd(_fat([(6, v7), (9, v7)]))
        check("activation: fat lockdownd: both slices patched when both can be", rep["skipped_slices"] == []
              and out.count(bytes.fromhex(rep["replacement"])) >= 2)
        try:
            activate_lockdownd(struct.pack(">II", 0xCAFEBABE, 0) + bytes(64))
            check("activation: refuses a fat header with no slices", False)
        except ActivationError:
            check("activation: refuses a fat header with no slices", True)

    # bootrom bundling: resolve, copy into the device folder, run.sh prefers the copy from any cwd
    d = tempfile.mkdtemp(prefix="bootrom-selftest-")
    try:
        src = os.path.join(d, "my dump.bin")
        open(src, "wb").write(b"ROM" * 100)
        check("resolve_bootrom: None when not given", resolve_bootrom("m68ap", None) is None)
        check("resolve_bootrom: kboot boards ignore it", resolve_bootrom("n88ap", src) is None)
        check("resolve_bootrom: absolute path for a real file", resolve_bootrom("n72ap", src) == src)
        for bad in (os.path.join(d, "missing"), d):
            try:
                resolve_bootrom("m68ap", bad)
                check("resolve_bootrom refuses %s" % os.path.basename(bad), False)
            except FirmwareError:
                check("resolve_bootrom refuses %s" % os.path.basename(bad), True)
        open(os.path.join(d, "empty"), "wb").close()
        try:
            resolve_bootrom("m68ap", os.path.join(d, "empty"))
            check("resolve_bootrom refuses an empty file", False)
        except FirmwareError:
            check("resolve_bootrom refuses an empty file", True)
        dev = os.path.join(d, "DEV")
        os.makedirs(dev)
        check("install_bootrom copies under the canonical name",
              install_bootrom(src, "n45ap", dev) == "bootrom_s5l8900"
              and open(os.path.join(dev, "bootrom_s5l8900"), "rb").read() == b"ROM" * 100)
        check("install_bootrom is idempotent on its own copy",
              install_bootrom(os.path.join(dev, "bootrom_s5l8900"), "n45ap", dev) == "bootrom_s5l8900")
        sh = os.path.join(dev, "run.sh")
        _write_run_sh(sh, SH_DIR_LINE + bootrom_guard("n45ap") + 'echo "$BOOTROM"\n')
        env = {k: v for k, v in os.environ.items() if k != "BOOTROM"}
        r = subprocess.run(["sh", sh], cwd="/", capture_output=True, text=True, env=env)
        check("run.sh (run from /) uses the bundled bootrom", r.stdout.strip() == os.path.join(dev, "bootrom_s5l8900"), r.stdout + r.stderr)
        env["BOOTROM"] = "/elsewhere/other"
        r = subprocess.run(["sh", sh], cwd="/", capture_output=True, text=True, env=env)
        check("run.sh: the bundled bootrom beats a stale $BOOTROM", r.stdout.strip() == os.path.join(dev, "bootrom_s5l8900"), r.stdout)
        os.remove(os.path.join(dev, "bootrom_s5l8900"))
        r = subprocess.run(["sh", sh], cwd="/", capture_output=True, text=True, env=env)
        check("run.sh: falls back to $BOOTROM, complains if it is missing", r.returncode == 1 and "bootrom not found" in r.stdout, r.stdout)
        del env["BOOTROM"]
        r = subprocess.run(["sh", sh], cwd="/", capture_output=True, text=True, env=env)
        check("run.sh: no bootrom anywhere -> clear error", r.returncode == 1 and "--bootrom" in r.stdout, r.stdout)

        # create_img3 end to end on a fake IPSW: the NOR with every all_flash image's SHSH wrapped under the
        # emulated UID, iBoot.bin from the (stubbed) decrypt, run.sh with the bootrom guard
        bn = _build_nor_module()
        shsh_plain = bytes(range(128))

        def fake_img3(typ):
            body = b"DATA-" + typ.encode() + bytes(11 - len(typ) + 3)
            data_tag = b"ATAD" + struct.pack("<II", 12 + len(body), len(body)) + body
            shsh_tag = b"HSHS" + struct.pack("<II", 12 + 128, 128) + shsh_plain
            tags = data_tag + shsh_tag
            hdr = b"3gmI" + struct.pack("<III", 0x14 + len(tags), len(tags), 0) + typ.encode()[::-1]
            return hdr + tags

        flash = "Firmware/all_flash/all_flash.n72ap.production/"
        fakes = {flash + "%s.n72ap.img3" % t: fake_img3(t) for t in bn.DEFAULT_ORDER}

        class FakeIPSW:
            def names(self):
                return list(fakes)
            def read(self, n):
                return fakes[n]
        class A: pass
        a = A()
        a.seed, a.id, a.wifi_mac, a.bootrom_path, a.ipsw = None, "n72ap-test", None, src, "unused.ipsw"
        a.skip_nand = True      # the NAND step needs a real rootfs, root and the hfsplus module
        out = os.path.join(d, "n72")
        os.makedirs(out)
        import contextlib, io
        import ipad1_fw
        real_decrypt = ipad1_fw.decrypt_catalog

        def fake_decrypt(ipsw_path, entry, dec, rootfs=True):
            os.makedirs(dec, exist_ok=True)
            for n in ("iBoot.bin", "kernelcache.mach", "DeviceTree.bin"):
                with open(os.path.join(dec, n), "wb") as f:
                    f.write(n.encode())
        ipad1_fw.decrypt_catalog = fake_decrypt
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                create_img3(a, {"recipe": {}}, FakeIPSW(),
                            {"board": "n72ap", "kernelcache": None, "version": "3.1.3"}, out, d)
        finally:
            ipad1_fw.decrypt_catalog = real_decrypt
        runsh = open(os.path.join(out, "run.sh")).read()
        check("n72ap bundle: bootrom_s5l8720 copied, run.sh guards on it",
              open(os.path.join(out, "bootrom_s5l8720"), "rb").read() == b"ROM" * 100
              and "bootrom_s5l8720" in runsh and "-M iPod-Touch,bootrom=$BOOTROM" in runsh and SH_DIR_LINE in runsh)
        check("n72ap bundle: run.sh selects the wrapped UID and iBoot.bin",
              "aes-uid=hardware" in runsh and 'direct-iboot="$D/iBoot.bin"' in runsh
              and open(os.path.join(out, "iBoot.bin"), "rb").read() == b"iBoot.bin")
        nor = open(os.path.join(out, "nor.bin"), "rb").read()
        check("n72ap NOR: 1 MiB, IMG2 superblock, LLB img3 at 0x8000",
              len(nor) == 0x100000 and nor[:4] == b"2GMI" and nor[0x8000:0x8004] == b"3gmI"
              and nor[0x8010:0x8014][::-1] == b"illb")
        o, wrapped_ok = 0x8000, True
        while nor[o:o + 4] == b"3gmI":
            full = struct.unpack_from("<I", nor, o + 4)[0]
            t = o + 0x14
            while nor[t:t + 4] != b"HSHS":
                t += struct.unpack_from("<I", nor, t + 4)[0]
            key = bn.shsh_wrap_key(bn.DEFAULT_UID_KEY, hardware=True)
            wrapped_ok &= nor[t + 12:t + 140] != shsh_plain and bn._aes_cbc(key, nor[t + 12:t + 140], False) == shsh_plain
            o += full
        check("n72ap NOR: every image's SHSH is wrapped under the UID-derived key", wrapped_ok and o > 0x8000)
        check("n72ap NOR: nvram carries the identity's Wi-Fi address",
              json.load(open(os.path.join(out, "identity.json")))["wifi-mac"].upper().encode() in nor[0xFC000:])

        # guest package seed: a synthetic itpack over a fake volume (loader, hook swap, baked copy, state, offer)
        import guest_package as gp
        gdir = os.path.join(d, "gp")
        man = {"format": 1, "serial": 14, "version": "1.1.14", "family": "n72-ios3", "arch": "armv6",
               "stub": False, "requires": {"boards": ["n72ap"], "builds": ["7E18", "5*"], "link": "modern"},
               "provides": [], "jobs": ["jobs/com.qemu.it-agent.plist"],
               "hooks": [{"file": "hooks/OpenGLES", "target": gp.OPENGLES, "respring": True}],
               "files": []}
        payloads = [("bin/it_agent", "755", b"AGENT"), ("jobs/com.qemu.it-agent.plist", "644", b"<plist/>"),
                    ("hooks/OpenGLES", "755", b"GLFRONT")]
        for n, m_, b_ in payloads:
            man["files"].append({"name": n, "mode": m_, "size": len(b_), "sha256": hashlib.sha256(b_).hexdigest()})
        ents = [("n72-ios3/manifest.json", json.dumps(man).encode())] \
            + [("n72-ios3/" + n, b_) for n, _, b_ in payloads] \
            + [("loader/it_boot", b"LOADER"), ("loader/com.qemu.it-boot.plist", b"<boot/>")]
        pk = os.path.join(d, "armv6.itpack")
        gp.write_itpack(pk, ents)
        check("itpack round trip", gp.read_itpack(pk) == ents)
        vol = os.path.join(gdir, "vol")
        for rel, data in ((gp.OPENGLES[1:], b"STOCKGL"), ("System/Library/LaunchDaemons/com.qemu.it-agent.plist", b"old")):
            os.makedirs(os.path.dirname(os.path.join(vol, rel)), exist_ok=True)
            open(os.path.join(vol, rel), "wb").write(data)
        os.makedirs(os.path.join(vol, "System/Library/CoreServices"))
        with open(os.path.join(vol, gp.SYSTEM_VERSION), "wb") as f:
            plistlib.dump({"ProductBuildVersion": "7E18"}, f)
        written, rec = gp.seed(vol, pk, gles=True, log=lambda *_: None)
        gl = os.path.join(vol, gp.OPENGLES[1:])
        check("guest seed: the GL front end replaces the stock engine, <target>.baked keeps it",
              open(gl, "rb").read() == b"GLFRONT" and open(gl + ".baked", "rb").read() == b"STOCKGL")
        check("guest seed: loader, package, current link and state",
              open(os.path.join(vol, gp.LOADER[0]), "rb").read() == b"LOADER"
              and os.readlink(os.path.join(vol, gp.ROOT, "current")) == "pkgs/14"
              and open(os.path.join(vol, gp.ROOT, "state")).read() == "seed 14\nhook 1 " + gp.OPENGLES + "\n"
              and not os.path.exists(os.path.join(vol, "System/Library/LaunchDaemons/com.qemu.it-agent.plist")))
        offer = open(os.path.join(vol, gp.ROOT, "pkgs/14/offer")).read().split("\n")
        check("guest seed: offer lines (ltpkg header, build, serial, file/job/hook)",
              offer[:3] == ["ltpkg 1", "build 7E18", "serial 14 1.1.14"] and offer[3].startswith("file 0 bin/it_agent 755 5 ")
              and offer[4].startswith("job 1 jobs/") and offer[5].endswith(gp.OPENGLES + " respring"))
        shutil.rmtree(os.path.join(vol, "usr"))
        os.remove(gl + ".baked")
        open(gl, "wb").write(b"STOCKGL")
        _, rec2 = gp.seed(vol, pk, gles=False, log=lambda *_: None)
        check("guest seed: --no-gles keeps the GL hook out", rec2["hooks"] == [] and open(gl, "rb").read() == b"STOCKGL")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # jailbreak option: the pure helpers, then Cydia's install over a fake volume
    check("jb_entry_path strips ./ and trailing /",
          jb_entry_path("./usr/bin/") == "usr/bin" and jb_entry_path("Applications") == "Applications")
    check("jb_boot_args appends once",
          jb_boot_args("a=1") == "a=1 " + JB_BOOT_ARG and jb_boot_args(jb_boot_args("a=1")) == "a=1 " + JB_BOOT_ARG)
    afcd = b"x\0/private/var/mobile/Media\0y\0com.apple.afcd\0z"
    patched = afc2_strings(afcd)
    check("afc2 strings: same length, root and service name replaced",
          len(patched) == len(afcd) and b"/\0" + bytes(24) + b"y" in patched and b"com.apple.afc2\0z" in patched)
    try:
        afc2_strings(b"no strings here")
        check("afc2 strings: a missing string is an error", False)
    except FirmwareError:
        check("afc2 strings: a missing string is an error", True)
    check("dpkg status: the patcyh paragraph goes",
          jb_drop_patcyh_packages("Package: a\nX: 1\n\nPackage: com.saurik.patcyh\nX: 2\n\nPackage: b\nX: 3\n")
          == "Package: a\nX: 1\n\nPackage: b\nX: 3\n")
    d = tempfile.mkdtemp(prefix="jbtest-")
    try:
        import io
        import tarfile
        pk = os.path.join(d, "pk")
        vol = os.path.join(d, "vol")
        os.makedirs(pk)
        os.makedirs(os.path.join(vol, "Applications"))
        with open(os.path.join(vol, "Applications", "keep"), "w") as f:
            f.write("stock")

        def member(t, name, data=b"", mode=0o644, typ=tarfile.REGTYPE, link=""):
            ti = tarfile.TarInfo(name)
            ti.size = len(data) if typ == tarfile.REGTYPE else 0
            ti.mode, ti.type, ti.linkname = mode, typ, link
            t.addfile(ti, io.BytesIO(data) if typ == tarfile.REGTYPE else None)
        status = b"Package: com.saurik.patcyh\nX: 1\n\nPackage: bash\nX: 2\n"
        with tarfile.open(os.path.join(pk, JB_FILES[0][0]), "w:gz") as t:
            member(t, "./Applications/Cydia.app/Cydia", b"cydia", 0o755)
            member(t, "./Applications/keep", b"bootstrap", 0o644)
            member(t, "./usr/libexec/cydia/cydo", b"cydo", 0o6755)
            member(t, "./private/var/Keychains/TrustStore.sqlite3", b"trust")
            member(t, "./private/var/mobile/Library/x", b"x")
            member(t, "./usr/lib/libpatcyh.dylib", b"p")
            member(t, "./private/var/lib/dpkg/status", status)
        for n in (JB_FILES[1][0], JB_FILES[2][0]):
            with tarfile.open(os.path.join(pk, n), "w") as t:
                member(t, "./Library/MobileSubstrate/MobileSubstrate.dylib", n.encode(), 0o755)
        check("jb_packages: Substrate on 3.x-6.x, HTTPatch on 3.x only",
              [os.path.basename(x) for x in jb_packages(pk, 3)] == [n for n, _ in JB_FILES]
              and len(jb_packages(pk, 5)) == 2 and len(jb_packages(pk, 7)) == 1)
        members = {m[0]: m for m in jb_members(os.path.join(pk, JB_FILES[0][0]))}
        check("jb_members: trust store out, set-user-ID mode kept",
              "private/var/Keychains/TrustStore.sqlite3" not in members
              and members["usr/libexec/cydia/cydo"][1] == 0o6755)
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            line = jb_install_cydia(vol, pk, 4)
        read = lambda rel: open(os.path.join(vol, rel), "rb").read()
        check("cydia: extracted, stock files kept, trust store and patcyh left out",
              read("Applications/Cydia.app/Cydia") == b"cydia" and read("Applications/keep") == b"stock"
              and not os.path.exists(os.path.join(vol, "private/var/Keychains"))
              and not os.path.exists(os.path.join(vol, "usr/lib/libpatcyh.dylib"))
              and os.path.exists(os.path.join(vol, "Library/MobileSubstrate/MobileSubstrate.dylib")),
              line)
        check("cydia: cydo is set-user-ID, dpkg status without patcyh",
              os.stat(os.path.join(vol, "usr/libexec/cydia/cydo")).st_mode & 0o7777 == 0o6755
              and read("private/var/lib/dpkg/status") == b"Package: bash\nX: 2\n")
        sb = plistlib.loads(read(JB_SB_PREFS))
        meta = plistlib.loads(read(JB_METADATA))
        check("cydia: SpringBoard shows it, no stash, sources seeded",
              sb.get("SBShowNonDefaultSystemApps") is True and os.path.exists(os.path.join(vol, JB_NO_STASH))
              and meta["Version"] == 1 and len(meta["Sources"]) == len(JB_SOURCES))
        # the bootstrap is SHA-1 pinned: other bytes are an error
        try:
            jb_fetch(os.path.join(d, "dl"), log=lambda *_: None, download=lambda u, dst: open(dst, "wb").write(b"bad"))
            check("jb_fetch: wrong bytes are rejected", False)
        except FirmwareError as e:
            check("jb_fetch: wrong bytes are rejected", "SHA-1" in str(e))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # data volume seeding: the /private/var copy, over plain directories (no mounts, so no root needed)
    d = tempfile.mkdtemp(prefix="fwk-seed-")
    try:
        root = os.path.join(d, "rootfs")
        var = os.path.join(root, VAR_REL)
        os.makedirs(os.path.join(var, "db/SystemConfiguration"))
        os.makedirs(os.path.join(var, "mobile/Library/Preferences"))
        os.makedirs(os.path.join(var, "empty"))
        open(os.path.join(var, "mobile/Library/Preferences/a.plist"), "wb").write(b"<plist/>")
        os.chmod(os.path.join(var, "mobile/Library/Preferences/a.plist"), 0o640)
        open(os.path.join(var, "db/zero"), "wb").close()
        os.symlink("db/zero", os.path.join(var, "link"))
        os.mkfifo(os.path.join(var, "fifo"))
        dst = os.path.join(d, "data")
        os.mkdir(dst)
        n = seed_var_tree(root, dst, log=lambda *_: None)
        read = lambda p: open(os.path.join(dst, p), "rb").read()
        check("seed var: directories, file bytes and mode, empty file, symlink",
              os.path.isdir(os.path.join(dst, "db/SystemConfiguration")) and os.path.isdir(os.path.join(dst, "empty"))
              and read("mobile/Library/Preferences/a.plist") == b"<plist/>"
              and stat.S_IMODE(os.stat(os.path.join(dst, "mobile/Library/Preferences/a.plist")).st_mode) == 0o640
              and read("db/zero") == b"" and os.readlink(os.path.join(dst, "link")) == "db/zero", str(n))
        check("seed var: FIFOs skipped, var/run 0755 and var/tmp 1777 created",
              n["skipped"] == 1 and not os.path.lexists(os.path.join(dst, "fifo"))
              and stat.S_IMODE(os.stat(os.path.join(dst, "run")).st_mode) == 0o755
              and stat.S_IMODE(os.stat(os.path.join(dst, "tmp")).st_mode) == 0o1777, str(n))
        try:
            seed_var_tree(os.path.join(d, "nowhere"), dst, log=lambda *_: None)
            check("seed var: a rootfs without /private/var is an error", False)
        except FirmwareError as e:
            check("seed var: a rootfs without /private/var is an error", "private/var" in str(e))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    print("\nALL OK" if ok else "\nFAILURES")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create",
                       help="IPSW -> output directory with nor.bin, iBoot.bin/kboot.bin, nand/, run.sh",
                       description="Prepare a firmware image for qemu-ios. Supported boards: "
                                   + ", ".join(sorted(_BOARD_CREATORS)))
    c.add_argument("--ipsw", required=True, help="path to the IPSW file")
    c.add_argument("--catalog", required=True,
                   help="path to firmware-catalog.json (iphone/firmware-catalog.json in qemu-ios)")
    c.add_argument("--id", required=True,
                   help="catalog entry ID, e.g. m68ap-1A543a, n72ap-5F138, k48ap-7B367")
    c.add_argument("--out", required=True, help="output directory (must be empty or not exist)")
    c.add_argument("--seed", help="seed string for synthesized identity (default: <id>-default)")
    c.add_argument("--imei", help="override synthesized IMEI (m68ap/n45ap only)")
    c.add_argument("--wifi-mac", help="override synthesized Wi-Fi MAC")
    c.add_argument("--work", help="work directory (needs ~2 GB; default: a temp dir)")
    c.add_argument("--tmpdir", help="parent for the auto-created work directory")
    c.add_argument("--keep-work", action="store_true", help="keep the work directory after create")
    c.add_argument("--no-volume-edit", action="store_true",
                   help="skip mount-and-edit (m68ap/n45ap only; image will NOT boot as-is)")
    c.add_argument("--skip-activation", action="store_true",
                   help="leave lockdownd unpatched (m68ap/n45ap, and k48ap/n81ap/n90ap)")
    c.add_argument("--skip-data-seed", action="store_true",
                   help="kboot boards: leave the data volume (/private/var) empty instead of seeding it from the "
                        "rootfs's /private/var (an empty one does not boot; for testing only)")
    c.add_argument("--jailbreak", action="store_true",
                   help="leave a jailbreak on the device: afc2 and Cydia with Substrate (iPhone OS 2.0+; needs root "
                        "and the hfsplus module; the K48 family and the other kboot boards boot with "
                        "amfi_get_out_of_my_way=1); the bootstrap is downloaded once (SHA-1 pinned)")
    c.add_argument("--jailbreak-cache", metavar="DIR",
                   help="where the Cydia bootstrap is kept (default: ~/.cache/firmwarekit/Jailbreak)")
    c.add_argument("--guest-package", metavar="ITPACK",
                   help="bake the guest-package loader and seed package from an .itpack (contrib/guest-package/"
                        "build.sh makes armv6.itpack / armv7.itpack; kboot boards and m68ap/n45ap; needs root "
                        "and the hfsplus module)")
    c.add_argument("--no-gles", action="store_true",
                   help="with --guest-package: leave the GL hooks (the OpenGLES front end, the MBX shim) out")
    c.add_argument("--skip-sha1", "--skip-sha1sum", dest="skip_sha1", action="store_true",
                   help="skip checking the IPSW SHA-1 hash against the catalog")
    c.add_argument("--bootrom", metavar="PATH",
                   help="bootrom file for boards that boot through one (m68ap/n45ap: S5L8900, n72ap: S5L8720); "
                        "copied into --out as bootrom_<soc> and used by run.sh. Ignored for the other boards")
    c.add_argument("--skip-nand", action="store_true",
                   help="n72ap: stop after nor.bin/iBoot.bin and do not build nand/ (the old behaviour)")
    c.add_argument("--qemu", help="path to qemu-system-arm binary")
    c.add_argument("--helper", help="path to it_keybag binary for iOS 4.x keybag provisioning")
    c.add_argument("--skip-keybag", action="store_true",
                   help="skip keybag one-shot provisioning even if writable_nor is set")
    c.add_argument("--keybag-timeout", type=int, default=300,
                   help="timeout in seconds for keybag one-shot boot (default: 300)")
    sub.add_parser("selftest", help="run built-in unit tests (no IPSW needed)")
    x = sub.add_parser("nand-extract",
                       help="rebuild the HFS+ volume image from a DEV/nand page directory")
    x.add_argument("nand_dir", help="path to the nand directory (contains bank0..3)")
    x.add_argument("out", help="output image path, e.g. volume.img")
    d = sub.add_parser("difftest",
                       help="compare the activation patcher against the C original (needs a C compiler)")
    d.add_argument("c_source",
                   help="path to FirmwareKit/Sources/CActivation/activation.c")
    d.add_argument("--seed", type=int, default=1)
    d.add_argument("--mutations", type=int, default=300,
                   help="mutated binaries per activation strategy (default: 300)")
    pk = sub.add_parser("provision-keybag",
                        help="provision effaceable nor.bin and systembag.kb for an existing device bundle")
    pk.add_argument("bundle", help="path to device bundle directory (e.g. /opt/DEV_n90ap_8B117)")
    pk.add_argument("--ramdisk", required=True, help="path to decrypted restore ramdisk DMG")
    pk.add_argument("--dec-dir", help="path to decrypted components directory (containing kernelcache.mach and DeviceTree.bin)")
    pk.add_argument("--machine", help="QEMU machine name (default: detected from run.sh)")
    pk.add_argument("--helper", help="path to it_keybag binary")
    pk.add_argument("--qemu", help="path to qemu-system-arm binary")
    pk.add_argument("--timeout", type=int, default=300, help="timeout in seconds (default: 300)")
    a = ap.parse_args()
    try:
        if a.cmd == "create":
            create(a)
        elif a.cmd == "nand-extract":
            print("%d pages written to %s" % (nand_extract(a.nand_dir, a.out), a.out))
        elif a.cmd == "difftest":
            sys.exit(difftest(a))
        elif a.cmd == "provision-keybag":
            cmd_provision_keybag(a)
        else:
            sys.exit(selftest(a))
    except FirmwareError as e:
        sys.exit("error: %s" % e)


if __name__ == "__main__":
    main()
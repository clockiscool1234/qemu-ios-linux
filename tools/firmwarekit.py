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

NOT ported from Swift: guest package / GL hook, SystemConfiguration (Wi-Fi/proxy) seeding,
HFS+ journaling, catalog date normalisation, re-signing of signed-era lockdownd, IMG3 decryption
(n72/n88/k48/n81/n90 need decryption keys from the catalog; those boards produce a stub run.sh).
Activation patch (1.x only) and rootfs decrypt/grow are fully ported for m68ap/n45ap.

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


def with_mounted(volume, mnt, fn):
    os.makedirs(mnt, exist_ok=True)
    r = subprocess.run(["mount", "-t", "hfsplus", "-o", "loop,rw,force", volume, mnt],
                       capture_output=True, text=True)
    if r.returncode:
        r = subprocess.run(["sudo", "mount", "-t", "hfsplus", "-o", "loop,rw,force", volume, mnt],
                           capture_output=True, text=True)
    if r.returncode:
        raise FirmwareError("mounting the volume read-write failed (need root and the Linux hfsplus "
                            "module; a journaled volume mounts read-only): " + r.stderr.strip())
    try:
        return fn(mnt)
    finally:
        subprocess.run(["sync"])
        subprocess.run(["umount", mnt], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "umount", mnt], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
# Scope: the 1.x (unsigned) paths.  A lockdownd that carries LC_CODE_SIGNATURE, or a match that is
# not a legacy initializer (signed-era firmware), is refused instead of re-signed.

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
        raise ActivationError("expected a thin little-endian 32-bit ARM Mach-O executable")
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
            raise ActivationError("lockdownd carries a code signature; re-signing is not ported (1.x is unsigned)")
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


def activate_lockdownd(data, allow_signed_era=False):
    """-> (patched bytes, report).  Raises ActivationError (the input is never modified in place)."""
    m = _Image(data)
    _act_parse(m)
    match = _act_locate(m)
    if not match.legacy and not allow_signed_era:
        raise ActivationError("matched a signed-era path (%s); this port patches 1.x only and does not re-sign"
                              % activation_strategy(match))
    out = bytearray(data)
    out[match.off:match.off + match.width] = match.replacement
    return bytes(out), {
        "strategy": activation_strategy(match), "isa": match.isa, "offset": match.off, "virtual_address": match.va,
        "width": match.width, "original": bytes(data[match.off:match.off + match.width]).hex(),
        "replacement": match.replacement.hex(),
        "input_sha256": hashlib.sha256(data).hexdigest(), "output_sha256": hashlib.sha256(bytes(out)).hexdigest(),
    }


LOCKDOWND = "usr/libexec/lockdownd"


def activate_volume(m, log=print):
    """SystemEdits.activate: patch lockdownd in place on the mounted volume `m` (owner/mode kept)."""
    path = os.path.join(m, LOCKDOWND)
    with open(path, "rb") as f:
        before = f.read()
    after, rep = activate_lockdownd(before)
    mode = os.stat(path).st_mode & 0o7777
    os.chmod(path, mode | 0o200)
    try:
        with open(path, "r+b") as f:  # in place: the catalog record, owner and mode stay
            f.write(after)
    finally:
        os.chmod(path, mode)
    log("activation: %s at file offset 0x%x (%s): %s -> %s" % (rep["strategy"], rep["offset"], rep["isa"],
                                                              rep["original"], rep["replacement"]))
    return rep


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


def _run_sh_header(out_var="$D"):
    """Common shell preamble: locate the script directory."""
    return 'D=$(cd "$(dirname \'$0\')" && pwd)\n'


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
        rep = with_mounted(vol, os.path.join(work, "mnt"),
                           lambda m: edit_volume(m, iboot, ipsw, ri["kernelcache"],
                                                 activate=not args.skip_activation))
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

    # bootrom is the S5L8900; it is external
    bootrom_env = {"m68ap": "S5L8900", "n45ap": "S5L8900"}.get(board, "BOOTROM")
    imei_str = ident.get("imei", "")
    wifi_str = ident.get("wifi-mac", "")
    run_body = 'D=$(cd "$(dirname \'$0\')" && pwd)\n'
    run_body += _cleanup_trap(tmp_prefix)
    run_body += """[ -n "$BOOTROM" ] || { echo "set BOOTROM to the %s bootrom"; exit 1; }
mkdir -p /tmp/%s-ovl
cp -n "$D/nor.bin" /tmp/%s-nor.bin
chmod u+w /tmp/%s-nor.bin
exec ${QEMU:-qemu-system-arm} \\
  -M %s,bootrom=$BOOTROM,iboot="$D/iBoot.bin",nand="$D/nand",nand-overlay=/tmp/%s-ovl,imei=%s,wifi-mac=%s \\
  -drive if=pflash,format=raw,file=/tmp/%s-nor.bin \\
  -serial mon:stdio -display sdl,show-cursor=on -audio driver=none \\
  -qmp unix:/tmp/%s-qmp.sock,server,nowait
""" % (bootrom_env, tmp_prefix, tmp_prefix, tmp_prefix,
       qemu_machine, tmp_prefix, imei_str, wifi_str,
       tmp_prefix, tmp_prefix)
    _write_run_sh(os.path.join(out, "run.sh"), run_body)

    bootrom_name = "bootrom_s5l8900"
    print("""
done: %s
Not done (the Swift firmwarekit handles these): guest package / OpenGLES hook, Wi-Fi + proxy
SystemConfiguration seeding, HFS+ journaling, catalog date normalisation.
Supply the %s bootrom (%s) via $BOOTROM."""
          % (out, board, bootrom_name))


# ---------------------------------------------------------------------------------------------
# IMG3 boards: n72ap (iPod Touch 2G/3G) -- NOR packed with img3s
# ---------------------------------------------------------------------------------------------

def create_img3(args, entry, ipsw, ri, out, work):
    """Build NOR+NAND for n72ap (IMG3, NOR packed at 0x8000, NAND 4-chip).
    IMG3 decryption requires catalog keys; this stub extracts available files."""
    board = ri["board"]
    qemu_machine, tmp_prefix, nand_banks, bbt_map, _ = BOARD_META[board]
    recipe = entry["recipe"]
    system_bytes = int(recipe.get("system_mib", 7168)) << 20

    # Extract all_flash img3s (encrypted; decryption keys needed from catalog)
    prefix = "Firmware/all_flash/all_flash.%s.production/" % board
    img3_files = {}
    iboot_member = None
    for n in ipsw.names():
        if n.startswith(prefix) and (n.endswith(".img3") or n.endswith(".img2")):
            img3_files[os.path.basename(n)] = n
            if "iBoot" in n:
                iboot_member = n

    print("all_flash members: %s" % ", ".join(sorted(img3_files)))

    # Write raw (encrypted) img3s for reference / manual decryption
    img3_dir = os.path.join(out, "img3")
    os.makedirs(img3_dir, exist_ok=True)
    for fname, member in sorted(img3_files.items()):
        with open(os.path.join(img3_dir, fname), "wb") as f:
            f.write(ipsw.read(member))
    print("wrote %d img3 files to img3/ (encrypted; need catalog keys to build NOR)" % len(img3_files))

    # Extract kernelcache and device tree for reference
    kc = ri.get("kernelcache")
    if kc and kc in ipsw.names():
        with open(os.path.join(out, "kernelcache.img3"), "wb") as f:
            f.write(ipsw.read(kc))
        print("kernelcache -> kernelcache.img3 (encrypted)")

    ident = synthesize_iphone(args.seed or args.id + "-default", model="MB528")
    if args.wifi_mac:
        ident["wifi-mac"] = args.wifi_mac
    with open(os.path.join(out, "identity.json"), "w") as f:
        json.dump(ident, f, indent=1)

    # run.sh: n72 uses a pre-built nor.bin and nand/ from the release
    run_body = 'D=$(cd "$(dirname \'$0\')" && pwd)\n'
    run_body += _cleanup_trap(tmp_prefix)
    run_body += """[ -n "$BOOTROM" ] || { echo "set BOOTROM to the S5L8720 bootrom"; exit 1; }
exec ${QEMU:-qemu-system-arm} \\
  -M %s,bootrom=$BOOTROM,nand="$D/nand",nor="$D/nor.bin" \\
  -serial mon:stdio -display sdl,show-cursor=on -audio driver=none
""" % qemu_machine
    _write_run_sh(os.path.join(out, "run.sh"), run_body)
    print("""
done: %s
n72ap requires IMG3 decryption keys (from the catalog's 'keys' section) to build a working NOR.
The raw encrypted img3s are in img3/. See the Swift FirmwareKit (N72NOR.swift) for the NOR layout.
Supply the S5L8720 bootrom via $BOOTROM.""" % out)


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
    na.data = "512m" if shutil.which("mkfs.hfsplus") else "none"
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
    run_body = 'D=$(cd "$(dirname \'$0\')" && pwd)\n'
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
        shutil.copyfile(helper, target)
        os.chmod(target, 0o755)
        try:
            os.chown(target, 0, 0)
        except (PermissionError, AttributeError):
            subprocess.run(["sudo", "chown", "0:0", target], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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


def create(args):
    entry = catalog_entry(args.catalog, args.id)
    board = entry.get("board", "")
    if board not in _BOARD_CREATORS:
        raise FirmwareError("%s has board '%s'; supported boards: %s"
                            % (args.id, board, ", ".join(sorted(_BOARD_CREATORS))))
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
    os.makedirs(out, exist_ok=True)
    tmp_prefix = BOARD_META[board][1]
    work = args.work or tempfile.mkdtemp(prefix=tmp_prefix + "-", dir=args.tmpdir)
    os.makedirs(work, exist_ok=True)
    _BOARD_CREATORS[board](args, entry, ipsw, ri, out, work)


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
            _, rep = activate_lockdownd(data, allow_signed_era=True)
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
            patched, _ = activate_lockdownd(base, allow_signed_era=True)
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
                out, rep = activate_lockdownd(data, allow_signed_era=True)
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
            activate_lockdownd(SYNTH_KINDS["thumb_dev"]())
            check("activation: signed-era match refused without allow_signed_era", False)
        except ActivationError:
            check("activation: signed-era match refused without allow_signed_era", True)
        sig = bytearray(SYNTH_KINDS["conditional"]())
        sig[0x14:0x18] = struct.pack("<I", 124 + 16)           # sizeofcmds
        sig[0x10:0x14] = struct.pack("<I", 2)                  # ncmds
        sig[152:168] = struct.pack("<IIII", 0x1D, 16, 0, 0)    # LC_CODE_SIGNATURE
        try:
            activate_lockdownd(bytes(sig))
            check("activation: refuses a signed lockdownd (no re-signing here)", False)
        except ActivationError as e:
            check("activation: refuses a signed lockdownd (no re-signing here)", "signature" in str(e), str(e))

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
                   help="leave lockdownd unpatched (m68ap/n45ap 1.x only)")
    c.add_argument("--skip-sha1", "--skip-sha1sum", dest="skip_sha1", action="store_true",
                   help="skip checking the IPSW SHA-1 hash against the catalog")
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
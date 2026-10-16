# QEMU-iOS-Linux

Built with use from agentic coding products.

QEMU-iOS emulates legacy Apple devices well enough to run their stock firmware: from the boot ROM or a
kernel bundle to the home screen, with touch, buttons, display, audio, Wi-Fi, USB (usbmux/AFC through
libimobiledevice), persistent storage, a fake cellular network on the iPhones, and OpenGL ES through a
host GL bridge. It is the emulator inside [Light Touch](https://github.com/samhenrigold/LightTouchMac).

| Machine (`-M`) | Device | SoC | Board docs |
|---|---|---|---|
| `iPod-Touch-1G` | iPod touch (1st gen, n45ap) | S5L8900 | `docs/ipod1g/README.md` |
| `iPhone-2G` | iPhone (m68ap) | S5L8900 | `docs/m68/README.md` |
| `iPod-Touch` | iPod touch (2nd gen, n72ap) | S5L8720 | `docs/capabilities.md`, `docs/ipod/` |
| `n18` | iPod touch (3rd gen, n18ap) | S5L8922 | `docs/n18/README.md` |
| `n88` | iPhone 3GS (n88ap) | S5L8920 | `docs/n88/README.md` |
| `iPod-Touch-4G` | iPod touch (4th gen, n81ap) | A4 (S5L8930) | `docs/n81/README.md` |
| `iPhone-4` | iPhone 4 GSM (n90ap) | A4 (S5L8930) | `docs/n90/README.md` |
| `ipad1` | iPad (k48ap) | A4 (S5L8930) | `docs/ipad1/README.md` |

Which firmware builds each board runs, and how well, is tracked in Light Touch's firmware catalog
(`LightTouchMac/Resources/firmware-catalog.json`, in this repo its at `tools/firmware-catalog.json`): every build is prepared from Apple's stock IPSW.

Shared between the boards: the host GL executor (`hw/arm/gles-host*.c`), the guest-service hypercalls
(`hw/arm/guest-services.c`, `guest-gles.c`, `guest-pasteboard.c`, `guest-package.c`), the typed guest
agent RPC (`hw/arm/ipod-agent.c`) and the baseband model (`hw/misc/ios_baseband*.c`, `docs/baseband/`).

## What is where

| Path | What |
|---|---|
| `hw/arm/`, `include/hw/arm/` | The three machines and their peripherals, plus the shared host pieces above |
| `contrib/it-*` | Guest helpers for the iPod (armv6, built with `contrib/armv6-toolchain`): `it-agent` (the guest agent), `it-gles` (MBX GL shim), `it-boot` (guest-package loader), `it-pasteboard`, `it-media`, `it-keybag`, `it-seal`, … each with its own README |
| `contrib/gles-public`, `contrib/ipad1-guest`, `contrib/appsync` | the GL front end (one OpenGLES.framework replacement for every 2.x-5.x firmware, iPad and iPod; `docs/ipad1/gles-public-seam.md`); iPad-side helpers: `ipad1-guest/build.sh` builds `it_pbd` (pasteboard bridge) and the other iPad helpers for armv7 from the shared sources; the AppSync interposer dylib |
| `contrib/guest-package` | `mkpkg.c` and `VERSION`: the versioned guest-tools package format the loader installs at boot |
| `contrib/macos-app` | `make-dylib-macos.sh` (the app's dylib), `entitlements.plist` (the app's helper entitlements), `ipod-helper.c` (the app's `ipa-chmod`) |
| `imgtools/lldb` | lldb scripting for guest debugging (`xnu.py`). Devices are made by LightTouchMac's Swift FirmwareKit: `firmwarekit create --catalog CATALOG --id BOARD-BUILD --ipsw IPSW --out OUT` (CATALOG: LightTouchMac's `LightTouchMac/Resources/firmware-catalog.json`; k48ap and 4.x n72ap also take `--helper` with the LightTouchDevice executable) |
| `tests/slice/`, `tests/ipod/`, `tests/ipad1/`, `tests/guest-package/` | The gates below |
| `scripts/ccninja`, `scripts/configure-patched-ffmpeg` | Build helpers |
| `tools/` | Linux Python port `firmwarekit.py` for creating device firmware bundles from IPSWs (see `tools/README.md`) |
| `docs/` | Ours are the `.md` files; the `.rst`/`.txt` tree is upstream QEMU's. See "Documentation" |

## Build
Installing dependencies
```sh
sudo apt install make ninja-build pkg-config libssl-dev libsdl2-dev libpixman-1-dev libpixman-1-0 libglib2.0-dev
```
Cloning the project:
```sh
git clone https://github.com/clockiscool1234/qemu-ios-linux
```
Building QEMU:
```sh
mkdir build && cd build
../configure --enable-sdl --enable-slirp --disable-cocoa --target-list=arm-softmmu --disable-capstone --extra-cflags=-I/usr/include/openssl --extra-ldflags='-lcrypto' --disable-werror --enable-pie
make -j$(nproc)
```

## Creating a device bundle (FirmwareKit)

On Linux, `tools/firmwarekit.py` unpacks Apple stock restore IPSWs, decrypts system images, and generates bootable device folders with offline NAND stores, patched kernel caches, synthesized device identities, and `run.sh` scripts.

```sh
# System dependencies
sudo apt-get install -y python3 hfsprogs libssl-dev
```



### Example: iPhone 4 GSM (`n90ap`)

For A4 devices on iOS 4.x/5.x (iPhone 4 `n90ap`, iPad 1 `k48ap`, iPod touch 4G `n81ap`), iOS requires Data Protection keybag provisioning (`/private/var/keybags/systembag.kb` and a formatted NOR effaceable storage). Without this provisioning, the guest loops in `keybagd: kb_load`.

1. **Obtain `it_keybag`**:
   - Build the armv7 helper using GitHub Actions ([`.github/workflows/build-guest-helpers.yml`](.github/workflows/build-guest-helpers.yml)) or via an Xcode/armv7 toolchain.
   - Place the compiled binary at `tools/it_keybag` and ensure it is executable (`chmod +x tools/it_keybag`).
   - `firmwarekit.py` automatically detects `tools/it_keybag` (or you can specify `--helper /path/to/it_keybag`).

2. **Generate the device folder**:
   ```sh
   python3 tools/firmwarekit.py create \
     --ipsw ~/Downloads/iPhone3,1_4.0_8A293_Restore.ipsw \
     --catalog iphone/firmware-catalog.json \
     --id n90ap-8A293 \
     --helper tools/it_keybag \
     --out /opt/DEV_n90ap_8A293
   ```

3. **Output bundle structure**:
   The generated `/opt/DEV_n90ap_8A293` folder contains:
   - `kboot.bin`: Direct kernel boot bundle (kernel cache, ramdisk, device tree, boot args).
   - `nand/`: YaFTL NAND store containing MBR partition table, rootfs, and data partition.
   - `nor.bin`: 1 MiB NOR image with formatted effaceable storage.
   - `identity.json`: Synthesized device identity (serial number, ECID, IMEI, Wi-Fi MAC).
   - `run.sh`: Automated QEMU launch script.

4. **Booting the device**:
   ```sh
   cd /opt/DEV_n90ap_8A293
   export QEMU=~/Documents/qemu-ios/build/qemu-system-arm
   ./run.sh
   ```

For all other supported boards (iPhone 2G `m68ap`, iPod touch 1G/2G/3G/4G, iPad 1 `k48ap`, iPhone 3GS `n88ap`), options, and controls, see [tools/README.md](tools/README.md).


## Gates

One command, three tiers:

```sh
tests/gate.sh --quick    # host only: every tests/slice/*.c, tests/*/*-test.sh and the GL name table check, in parallel
tests/gate.sh --models   # the device qtests and test-ios-baseband from the build next to QEMU
tests/gate.sh --all      # both
```

One line per check (PASS or FAIL with seconds); non-zero exit on any FAIL; every log under the printed
directory. `QEMU=` overrides the emulator (default `build/qemu-system-arm`).

| Gate | What it covers | Inputs |
|---|---|---|
| `tests/slice/run.sh tests/slice/<board>-<name>.c` | Host-only unit checks, one file each: the `SLICE` lines at the top name the code under test, compiled under ASan/UBSan | No emulator |
| `tests/*/*-test.sh` | Guest-package, toolchain and loader checks | No emulator |

Boots of prepared devices are LightTouchMac's: `swift run --package-path tests/sessions sessions single <BASE>`
(also `phone`, `local-network`, `proxy-trust`, `helper`), and its Release plan's prepare matrix (`firmwarekit
create` on each route, then a boot). Every headless boot passes `-audio driver=none`.

The export for the app (`contrib/export-guest-artifacts.sh`, "Build" above) is gated on the LightTouchMac side:
its `scripts/build-guest-tools.sh` runs the export from the commit pinned in `build-support/sources.json`
and `scripts/vendor` checks the staged tree against `manifest.json`; a pin bump is a LightTouchMac commit.

## Documentation

| Where | What |
|---|---|
| `docs/capabilities.md` | The iPod board: what works, where it stops, how to verify |
| `docs/ipad1/README.md` | The iPad board: Sam's principles (vanilla guest, IPSW-agnostic guest changes, Wi-Fi default), the definition of done, the audio and Bluetooth notes, and the index of `docs/ipad1/` (`iboot.md`, `wifi.md`, `usb-keyboard.md`, `ios4.md`, `location.md`, `guest-services.md`, `app-compat*.md`, `addresses-7B500.md`) |
| `docs/ipod/` | `from-ipsw.md` (the manifest pipeline for the iPod), the 7E18 hardware notes (`pmu-7e18.md`, `ipod-pke.md`, `ipod-clcd-irqs.md`, `ipod-native-halt.md`, `nor-transactions.md`), and `nand-current-new-verification.md` (the staged iPod image, kept until the image swap at the main merge) |
| `docs/configuration.md` | Typed machine properties and their `IT_*` aliases |
| `docs/tcp-usb-protocol.md` | The tcp_usb wire protocol shared with the usbmuxd fork |
| `docs/networking.md`, `docs/stock-service-protocol.md`, `docs/app-ledger.md` | Guest networking and the built-in proxy; the Weather/Stocks gateway; the iPod app ledger |
| `contrib/*/README.md`, `imgtools/README-appsync.md` | Per-tool notes |
| `docs/research/` | Research that preceded the code (the A4 gap/reference reports, the 7B500 userland and GL notes, the Bluetooth keyboard scoping, the iPod media investigation, the run-on-an-iPhone study). Each file starts with what superseded it |
| `docs/archive/` | Superseded plans still cited from code: the iPad milestone plan and the guest-services plan |

`docs/ipad1/*.tsv` and `docs/ipod/*.tsv` are GL dispatch tables, build inputs `contrib/export-guest-artifacts.sh`
stages for LightTouchMac (moving them out of `docs/` is on another track). `docs/ipad1/screens/`
holds the iPad evidence screenshots; put new evidence in `qemu-ios-files` instead.

## Upstream and license

QEMU-iOS is built on [QEMU](https://www.qemu.org) and grew out of devos50's
[qemu-ios](https://github.com/devos50/qemu-ios), the emulator for the iPod touch 1G and 2G. devos50's
write-ups are still the best introduction to the S5L8720 peripherals:
[running the iPod touch 1G](https://devos50.github.io/blog/2022/ipod-touch-qemu-pt2/) and
[the reverse-engineering process](https://devos50.github.io/blog/2022/ipod-touch-qemu/). `RUNNING.md`
is upstream's iPod touch 2G guide, kept with a note on what still applies.

Like QEMU, this repository is licensed under the GNU General Public License version 2 (`COPYING`); some
files carry other compatible licenses in their headers (`LICENSE` explains QEMU's licensing). No Apple
firmware is part of the repository.

# FirmwareKit CLI Reference (`tools/firmwarekit.py`)

`tools/firmwarekit.py` is the Linux-native Python utility for creating bootable firmware images, NOR binaries, NAND page trees, synthesized device identities, and runner scripts for `qemu-ios`. It unpacks Apple restore IPSWs, decrypts root filesystems using keys from `iphone/firmware-catalog.json`, patches activation and kernel caches where required, and generates ready-to-run environments.

---

## Table of Contents

- [Quick Reference Table](#quick-reference-table)
- [Prerequisites](#prerequisites)
- [Command Line Options](#command-line-options)
- [Device Commands & Examples](#device-commands--examples)
  - [1. iPhone 2G / 1st Gen (`m68ap`)](#1-iphone-2g--1st-gen-m68ap)
  - [2. iPod Touch 1st Gen (`n45ap`)](#2-ipod-touch-1st-gen-n45ap)
  - [3. iPod Touch 2nd Gen (`n72ap`)](#3-ipod-touch-2nd-gen-n72ap)
  - [4. iPod Touch 3rd Gen (`n18ap`)](#4-ipod-touch-3rd-gen-n18ap)
  - [5. iPhone 3GS (`n88ap`)](#5-iphone-3gs-n88ap)
  - [6. iPad 1st Gen (`k48ap`)](#6-ipad-1st-gen-k48ap)
  - [7. iPod Touch 4th Gen (`n81ap`)](#7-ipod-touch-4th-gen-n81ap)
  - [8. iPhone 4 GSM (`n90ap`)](#8-iphone-4-gsm-n90ap)
- [Running QEMU & Controls](#running-qemu--controls)
  - [Keyboard Shortcuts](#keyboard-shortcuts)
  - [Mouse & Touch](#mouse--touch)
  - [Temporary File Cleanup](#temporary-file-cleanup)

---

## Quick Reference Table

| Board ID | Device Name | Product Type | SoC | Bootrom | QEMU `-M` Machine | Needs `sudo`? |
|---|---|---|---|---|---|---|
| `m68ap` | iPhone (1st Gen / 2G) | `iPhone1,1` | S5L8900 | `bootrom_s5l8900` | `iPhone-2G` | **Yes** (HFS+ loop mount) |
| `n45ap` | iPod Touch (1st Gen) | `iPod1,1` | S5L8900 | `bootrom_s5l8900` | `iPod-Touch-1G` | **Yes** (HFS+ loop mount) |
| `n72ap` | iPod Touch (2nd Gen) | `iPod2,1` | S5L8720 | `bootrom_s5l8720` | `iPod-Touch` | No |
| `n18ap` | iPod Touch (3rd Gen) | `iPod3,1` | S5L8922 | None (kboot direct) | `n18` | No |
| `n88ap` | iPhone 3GS | `iPhone2,1` | S5L8920 | None (kboot direct) | `n88` | No |
| `k48ap` | iPad (1st Gen) | `iPad1,1` | S5L8930 (A4) | None (kboot direct) | `ipad1` | No |
| `n81ap` | iPod Touch (4th Gen) | `iPod4,1` | S5L8930 (A4) | None (kboot direct) | `iPod-Touch-4G` | No |
| `n90ap` | iPhone 4 GSM | `iPhone3,1` | S5L8930 (A4) | None (kboot direct) | `iPhone-4` | No |

---

## Prerequisites

Before running `tools/firmwarekit.py`, install the required system tools:

```bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y python3 hfsprogs libssl-dev
```

- **Root / `sudo` Privileges**: Required when generating images for `m68ap` (iPhone 2G) and `n45ap` (iPod Touch 1G). The tool decrypts the system DMG, grows the HFS+ volume, mounts it via a loop device to patch `fstab`, disable watchdog daemons, and inject the activation bypass into `lockdownd`.
- **Bootrom Files** (`m68ap`, `n45ap`, `n72ap` only): pass the raw SoC bootrom dump with `--bootrom <path>`. It is copied into the device folder (`bootrom_s5l8900` / `bootrom_s5l8720`) and `run.sh` uses that copy, so the device folder is self-contained and `$BOOTROM` is not needed. Without `--bootrom`, `run.sh` falls back to `$BOOTROM`.

---

## Command Line Options

```bash
python3 tools/firmwarekit.py create [OPTIONS]
```

### Required Parameters
- `--ipsw <path>`: Path to the Apple Restore IPSW file.
- `--catalog <path>`: Path to `firmware-catalog.json` (located at `iphone/firmware-catalog.json`).
- `--id <entry-id>`: Exact build entry ID from the catalog (e.g. `m68ap-1A543a`, `n72ap-5F138`).
- `--out <path>`: Destination directory for the generated images and `run.sh` (must be empty or not exist).

### Optional Parameters
- `--seed <string>`: Seed string used to synthesize deterministic serial numbers, Wi-Fi MACs, and ECIDs. (Default: `<id>-default`)
- `--imei <imei>`: Override the synthesized 15-digit IMEI for cellular devices (`m68ap`).
- `--wifi-mac <mac>`: Override the synthesized Wi-Fi MAC address (`XX:XX:XX:XX:XX:XX`).
- `--work <path>`: Custom temporary scratch directory (needs ~2 GB of free disk space).
- `--tmpdir <path>`: Parent directory where the auto-generated work directory should be created.
- `--keep-work`: Retain intermediate files in the work directory after completion.
- `--no-volume-edit`: Skip mount-and-edit step for `m68ap`/`n45ap` (useful for fast testing without root).
- `--skip-activation`: Do not patch `lockdownd` on iPhone OS 1.x.
- `--skip-sha1`, `--skip-sha1sum`: Skip checking the IPSW SHA-1 hash against the catalog entry. Useful for faster processing, testing slightly modified/re-packaged IPSWs, or when the hash in the catalog differs.
- `--bootrom <path>`: Bootrom for boards that boot through one (`m68ap`/`n45ap`: S5L8900, `n72ap`: S5L8720). Copied into `--out` as `bootrom_<soc>`; `run.sh` prefers that copy over `$BOOTROM`. Ignored (with a note) for boards that boot via kboot.
- `--helper <path>`: Path to `it_keybag` guest helper binary (armv7) for iOS 4.x/5.x effaceable storage and system keybag provisioning. If not specified, automatically looks for `tools/it_keybag`, `build/ipad1-guest/it_keybag`, `contrib/it-keybag/it_keybag`, `build/it_keybag`, or `$IT_KEYBAG`.
- `--skip-keybag`: Skip keybag provisioning on iOS 4.x/5.x (leaves blank `nor.bin`).

---

## Device Commands & Examples

### 1. iPhone 2G / 1st Gen (`m68ap`)

- **SoC**: S5L8900
- **Bootrom**: `bootrom_s5l8900`
- **QEMU Machine**: `-M iPhone-2G`
- **Requires Sudo**: **Yes**

#### Creation Command (iPhone OS 1.0)
```bash
sudo python3 tools/firmwarekit.py create \
  --ipsw ~/Downloads/iPhone1,1_1.0_1A543a_Restore.ipsw \
  --catalog iphone/firmware-catalog.json \
  --id m68ap-1A543a \
  --bootrom ~/bootroms/bootrom_s5l8900 \
  --out /opt/DEV_m68ap_1A543a
```

#### Other Verified Catalog IDs & IPSWs
- **iPhone OS 1.1.4**: `--id m68ap-4A102` (`iPhone1,1_1.1.4_4A102_Restore.ipsw`)
- **iPhone OS 2.0**: `--id m68ap-5A347` (`iPhone1,1_2.0_5A347_Restore.ipsw`)
- **iPhone OS 3.0**: `--id m68ap-7A341` (`iPhone1,1_3.0_7A341_Restore.ipsw`)
- **iPhone OS 3.1.3**: `--id m68ap-7E18` (`iPhone1,1_3.1.3_7E18_Restore.ipsw`)

#### Booting the Device
```bash
cd /opt/DEV_m68ap_1A543a
export QEMU=~/Documents/qemu-ios/build/qemu-system-arm
./run.sh
```

---

### 2. iPod Touch 1st Gen (`n45ap`)

- **SoC**: S5L8900
- **Bootrom**: `bootrom_s5l8900`
- **QEMU Machine**: `-M iPod-Touch-1G`
- **Requires Sudo**: **Yes**

#### Creation Command (iPhone OS 1.1)
```bash
sudo python3 tools/firmwarekit.py create \
  --ipsw ~/Downloads/iPod1,1_1.1_3A101a_Restore.ipsw \
  --catalog iphone/firmware-catalog.json \
  --id n45ap-3A101a \
  --bootrom ~/bootroms/bootrom_s5l8900 \
  --out /opt/DEV_n45ap_3A101a
```

#### Other Verified Catalog IDs & IPSWs
- **iPhone OS 1.1.4**: `--id n45ap-4A102` (`iPod1,1_1.1.4_4A102_Restore.ipsw`)
- **iPhone OS 2.0**: `--id n45ap-5A347` (`iPod1,1_2.0_5A347_Restore.ipsw`)
- **iPhone OS 3.0**: `--id n45ap-7A341` (`iPod1,1_3.0_7A341_Restore.ipsw`)
- **iPhone OS 3.1.3**: `--id n45ap-7E18` (`iPod1,1_3.1.3_7E18_Restore.ipsw`)

#### Booting the Device
```bash
cd /opt/DEV_n45ap_3A101a
export QEMU=~/Documents/qemu-ios/build/qemu-system-arm
./run.sh
```

---

### 3. iPod Touch 2nd Gen (`n72ap`)

- **SoC**: S5L8720
- **Bootrom**: `bootrom_s5l8720`
- **QEMU Machine**: `-M iPod-Touch`
- **Requires Sudo**: No

#### Creation Command (iPhone OS 2.1.1)
```bash
python3 tools/firmwarekit.py create \
  --ipsw ~/Downloads/iPod2,1_2.1.1_5F138_Restore.ipsw \
  --catalog iphone/firmware-catalog.json \
  --id n72ap-5F138 \
  --bootrom ~/bootroms/bootrom_s5l8720 \
  --out /opt/DEV_n72ap_5F138
```

#### Other Verified Catalog IDs & IPSWs
- **iPhone OS 3.0**: `--id n72ap-7A341` (`iPod2,1_3.0_7A341_Restore.ipsw`)
- **iPhone OS 3.1.3**: `--id n72ap-7E18` (`iPod2,1_3.1.3_7E18_Restore.ipsw`)
- **iOS 4.0**: `--id n72ap-8A293` (`iPod2,1_4.0_8A293_Restore.ipsw`)
- **iOS 4.2.1**: `--id n72ap-8C148` (`iPod2,1_4.2.1_8C148_Restore.ipsw`)

#### Booting the Device
```bash
cd /opt/DEV_n72ap_5F138
export QEMU=~/Documents/qemu-ios/build/qemu-system-arm
./run.sh
```

---

### 4. iPod Touch 3rd Gen (`n18ap`)

- **SoC**: S5L8922
- **Bootrom**: `bootrom_s5l8922`
- **QEMU Machine**: `-M n18`
- **Requires Sudo**: No

#### Creation Command (iPhone OS 3.1.1)
```bash
python3 tools/firmwarekit.py create \
  --ipsw ~/Downloads/iPod3,1_3.1.1_7C145_Restore.ipsw \
  --catalog iphone/firmware-catalog.json \
  --id n18ap-7C145 \
  --out /opt/DEV_n18ap_7C145
```

#### Other Verified Catalog IDs & IPSWs
- **iPhone OS 3.1.3**: `--id n18ap-7E18` (`iPod3,1_3.1.3_7E18_Restore.ipsw`)
- **iOS 4.0**: `--id n18ap-8A293` (`iPod3,1_4.0_8A293_Restore.ipsw`)
- **iOS 4.2.1**: `--id n18ap-8C148` (`iPod3,1_4.2.1_8C148_Restore.ipsw`)
- **iOS 5.1.1**: `--id n18ap-9B206` (`iPod3,1_5.1.1_9B206_Restore.ipsw`)

#### Booting the Device
```bash
cd /opt/DEV_n18ap_7C145
export QEMU=~/Documents/qemu-ios/build/qemu-system-arm
./run.sh
```

---

### 5. iPhone 3GS (`n88ap`)

- **SoC**: S5L8920
- **Boot Strategy**: Direct Kernel (`kboot.bin`, no Bootrom needed)
- **QEMU Machine**: `-M n88`
- **Requires Sudo**: No

#### Creation Command (iPhone OS 3.0)
```bash
python3 tools/firmwarekit.py create \
  --ipsw ~/Downloads/iPhone2,1_3.0_7A341_Restore.ipsw \
  --catalog iphone/firmware-catalog.json \
  --id n88ap-7A341 \
  --out /opt/DEV_n88ap_7A341
```

#### Other Verified Catalog IDs & IPSWs
- **iPhone OS 3.1.3**: `--id n88ap-7E18` (`iPhone2,1_3.1.3_7E18_Restore.ipsw`)
- **iOS 4.0**: `--id n88ap-8A293` (`iPhone2,1_4.0_8A293_Restore.ipsw`)
- **iOS 4.2.1**: `--id n88ap-8C148` (`iPhone2,1_4.2.1_8C148_Restore.ipsw`)
- **iOS 5.1.1**: `--id n88ap-9B206` (`iPhone2,1_5.1.1_9B206_Restore.ipsw`)

#### Booting the Device
```bash
cd /opt/DEV_n88ap_7A341
export QEMU=~/Documents/qemu-ios/build/qemu-system-arm
./run.sh
```

---

### 6. iPad 1st Gen (`k48ap`)

- **SoC**: S5L8930 (Apple A4)
- **Boot Strategy**: Direct Kernel (`kboot.bin`, no Bootrom needed)
- **QEMU Machine**: `-M ipad1`
- **Requires Sudo**: No

#### Creation Command (iPhone OS 3.2)
```bash
python3 tools/firmwarekit.py create \
  --ipsw ~/Downloads/iPad1,1_3.2_7B367_Restore.ipsw \
  --catalog iphone/firmware-catalog.json \
  --id k48ap-7B367 \
  --out /opt/DEV_k48ap_7B367
```

#### Other Verified Catalog IDs & IPSWs
- **iPhone OS 3.2.2**: `--id k48ap-7B500` (`iPad1,1_3.2.2_7B500_Restore.ipsw`)
- **iOS 4.2.1**: `--id k48ap-8C148` (`iPad1,1_4.2.1_8C148_Restore.ipsw`)
- **iOS 4.3.3**: `--id k48ap-8J3` (`iPad1,1_4.3.3_8J3_Restore.ipsw`)
- **iOS 5.1.1**: `--id k48ap-9B206` (`iPad1,1_5.1.1_9B206_Restore.ipsw`)

#### Booting the Device
```bash
cd /opt/DEV_k48ap_7B367
export QEMU=~/Documents/qemu-ios/build/qemu-system-arm
./run.sh
```

---

### 7. iPod Touch 4th Gen (`n81ap`)

- **SoC**: S5L8930 (Apple A4)
- **Boot Strategy**: Direct Kernel (`kboot.bin`, no Bootrom needed)
- **QEMU Machine**: `-M iPod-Touch-4G`
- **Requires Sudo**: No

#### Creation Command (iOS 4.1)
```bash
python3 tools/firmwarekit.py create \
  --ipsw ~/Downloads/iPod4,1_4.1_8B117_Restore.ipsw \
  --catalog iphone/firmware-catalog.json \
  --id n81ap-8B117 \
  --out /opt/DEV_n81ap_8B117
```

#### Other Verified Catalog IDs & IPSWs
- **iOS 4.2.1**: `--id n81ap-8C148` (`iPod4,1_4.2.1_8C148_Restore.ipsw`)
- **iOS 4.3.3**: `--id n81ap-8J2` (`iPod4,1_4.3.3_8J2_Restore.ipsw`)
- **iOS 5.1.1**: `--id n81ap-9B206` (`iPod4,1_5.1.1_9B206_Restore.ipsw`)

#### Booting the Device
```bash
cd /opt/DEV_n81ap_8B117
export QEMU=~/Documents/qemu-ios/build/qemu-system-arm
./run.sh
```

---

### 8. iPhone 4 GSM (`n90ap`)

- **SoC**: S5L8930 (Apple A4)
- **Boot Strategy**: Direct Kernel (`kboot.bin`, no Bootrom needed)
- **QEMU Machine**: `-M iPhone-4`
- **Requires Sudo**: No

#### Data Protection & `it_keybag` Provisioning
iOS 4.x and 5.x on the iPhone 4 require a writable NOR flash (`nor.bin`) containing formatted effaceable storage and the system keybag (`/private/var/keybags/systembag.kb`). Without this, the system will get stuck in a `keybagd` reboot loop (`keybagd: kb_load: ...`).

1. **Obtain `it_keybag`**:
   - Run the GitHub Actions workflow [`.github/workflows/build-guest-helpers.yml`](file:///home/pc/Documents/qemu-ios/.github/workflows/build-guest-helpers.yml) to compile `it_keybag` (armv7).
   - Download the `it_keybag-armv7` artifact and save it to `tools/it_keybag`.
   - Make it executable:
     ```bash
     chmod +x tools/it_keybag
     ```
   - `firmwarekit.py` will automatically detect `tools/it_keybag` (or you can explicitly pass `--helper tools/it_keybag`).

#### Creating the FirmwareKit Folder (iOS 4.0 / 4.1 / 4.2.1)
Run `firmwarekit.py create` pointing to your restore IPSW and catalog:

```bash
python3 tools/firmwarekit.py create \
  --ipsw ~/Downloads/iPhone3,1_4.0_8A293_Restore.ipsw \
  --catalog iphone/firmware-catalog.json \
  --id n90ap-8A293 \
  --helper tools/it_keybag \
  --out /opt/DEV_n90ap_8A293
```

During creation, `firmwarekit.py` will:
1. Extract the kernel cache, device tree, and ramdisk from the IPSW.
2. Decrypt the RootFS DMG using catalog keys and convert it into YaFTL NAND flash pages.
3. Patch `lockdownd` for offline activation and disable watchdogs.
4. Automatically boot QEMU headlessly with the restore ramdisk and `it_keybag` to format effaceable storage in `nor.bin` and write the system keybag to `/private/var/keybags/systembag.kb` in the NAND store.
5. Generate `kboot.bin` and the ready-to-run `run.sh` script.

#### Resulting Folder Structure
The destination folder (`/opt/DEV_n90ap_8A293`) will contain:
- `kboot.bin`: Staged kernel, ramdisk, device tree, and boot arguments.
- `nand/`: YaFTL NAND store containing MBR partition table, RootFS, and Data partition.
- `nor.bin`: 1 MiB writable NOR flash with effaceable storage keys.
- `identity.json`: Synthesized device parameters (serial number, ECID, IMEI, Wi-Fi MAC).
- `run.sh`: Automated QEMU launch script with overlay cleanup.

#### Other Verified Catalog IDs & IPSWs
- **iOS 4.0.1**: `--id n90ap-8A306` (`iPhone3,1_4.0.1_8A306_Restore.ipsw`)
- **iOS 4.0.2**: `--id n90ap-8A400` (`iPhone3,1_4.0.2_8A400_Restore.ipsw`)
- **iOS 4.1**: `--id n90ap-8B117` (`iPhone3,1_4.1_8B117_Restore.ipsw`)
- **iOS 4.2.1**: `--id n90ap-8C148` (`iPhone3,1_4.2.1_8C148_Restore.ipsw`)
- **iOS 4.3.3**: `--id n90ap-8J2` (`iPhone3,1_4.3.3_8J2_Restore.ipsw`)
- **iOS 5.1.1**: `--id n90ap-9B206` (`iPhone3,1_5.1.1_9B206_Restore.ipsw`)

> [!TIP]
> **Provisioning an Existing Folder**: If you previously created an `n90ap` folder without `it_keybag` and have a blank `nor.bin`, you can provision the keybag at any time using:
> ```bash
> python3 tools/firmwarekit.py provision-keybag /opt/DEV_n90ap_8A293 \
>   --ramdisk /path/to/decrypted-restore-ramdisk.dmg \
>   --helper tools/it_keybag
> ```

#### Booting the Device
```bash
cd /opt/DEV_n90ap_8A293
export QEMU=~/Documents/qemu-ios/build/qemu-system-arm
./run.sh
```

---

## Running QEMU & Controls

### Keyboard Shortcuts

When the QEMU SDL window has focus:

| Key | Button / Action |
|:---:|:---|
| <kbd>H</kbd> | **Home** button |
| <kbd>P</kbd> | **Power / Sleep / Wake** button |
| <kbd>=</kbd> | **Volume Up** |
| <kbd>-</kbd> | **Volume Down** |
| <kbd>Ctrl</kbd> + <kbd>Alt</kbd> + <kbd>G</kbd> | Release mouse cursor from QEMU window |

### Mouse & Touch
- **Left click and drag**: Simulates finger touch and gestures.
- The mouse cursor is permanently visible inside the emulator window via `-display sdl,show-cursor=on`.

### Temporary File Cleanup
Every generated `run.sh` contains an automated trap:
```sh
trap 'rm -rf /tmp/<board>-*' EXIT
```
When QEMU terminates (or is interrupted with `Ctrl+C`), any temporary overlay directories and NOR buffers created in `/tmp/` are cleaned up automatically.

# NOTE: this will soon be replaced, so do not follow these instructructions

## Running the iPod Touch 2G Emulator

This file contains the instructions on how to run the iPod Touch 2G emulator using QEMU.
Note that this is an experimental release and the functionality of the device is still limited.

**This file documents the generic build/run path and predates this fork's
current target.** This fork's day-to-day device is an iOS **3.1.3** image, run
headless by LightTouchMac (`sessions single`) — see the top-level
`README.md`. The build instructions, USB device mode and shutdown sections below
are still accurate; the specific example
output (`ProductVersion: 2.1.1`, `BuildVersion: 5F138`) reflects the 2.1.1
image they were captured against, not necessarily what a 3.1.3 boot reports.

### Getting the Source Code

Clone the repository using the following commands:

```
git clone https://github.com/devos50/qemu-ios.git
cd qemu-ios
```

Now you can proceed with the rest of the instructions for building and running the emulator.

### Building QEMU

Make sure you have the required libraries installed to compile QEMU:

```
# On MacOS
brew install glib ninja meson pixman pkg-config sdl2 openssl@3
```
Compile QEMU by running the following commands from the root directory:

```
mkdir build
cd build

# On Intel Macs
../configure --target-list=arm-softmmu --extra-cflags=-I/usr/local/opt/openssl@3/include --extra-ldflags='-L/usr/local/opt/openssl@3/lib -lcrypto'

# On Apple Silicon Macs
../configure --enable-sdl --target-list=arm-softmmu --disable-capstone --disable-pie --disable-slirp --disable-fuse --extra-cflags=-I/opt/homebrew/opt/openssl@3/include --extra-ldflags='-L/opt/homebrew/opt/openssl@3/lib -lcrypto'

make
```

Note that we’re explicitly enabling compilation of the SDL library which is used for interaction with the emulator (e.g., capturing keyboard and mouse events). Also, we only configure and build the ARM emulator.
We are also linking against OpenSSL as the AES/SHA1/PKE engines use some of the library’s cryptographic functions.
Remember to update the include and library paths to the OpenSSL library in case they are located elsewhere.
You can speed up the `make` command by passing the number of available CPU cores with the `-j` flag, e.g., use `make -j6` to compile using six CPU cores.
The compilation process should produce the `qemu-system-arm` binary in the `build/arm-softmmu` directory.

#### Troubleshooting the macOS build

On recent macOS (Sequoia/Tahoe) with an up-to-date Homebrew, a few things can trip up the build:

- **`configure` fails with `Ouch! ... found no usable distlib`.** QEMU builds a Python venv and needs `distlib` (or pip's vendored copy). Homebrew's newest Python may not ship it. Install a known-good Python and give it `distlib`:
  ```
  brew install python@3.12
  /opt/homebrew/opt/python@3.12/libexec/bin/python3 -m pip install --user --break-system-packages distlib
  ```
  Then re-run `../configure` with `--python=/opt/homebrew/opt/python@3.12/libexec/bin/python3` added to the flags above.
- **Build fails compiling `block/export/fuse.c`** (`incompatible function pointer types ... fuse_setattr`). Homebrew's `fuse-t`/`fuse3` headers don't match the current macOS SDK. FUSE isn't needed here — the Apple Silicon `configure` line above already passes `--disable-fuse`. If you configured without it, add it and reconfigure.
- Make sure `ninja` and `meson` are installed (they're in the `brew install` line above); older instructions omitted `meson`.

### Downloading the Required Files

We need a few files to successfully boot the iPod Touch emulator to the home screen, which I published [here](https://github.com/devos50/qemu-ios/releases/tag/n72ap_v1) for convenience. You can download all these files from here, and they include the following:
- The S5L8720 bootrom binary, which is started as the very first thing when booting.
- A NOR image that contains various auxillary files used by the bootloader. I provide some instructions on how to generate this image yourself [here](https://github.com/devos50/qemu-ios-generate-nor).
- A NAND image that contains the root file system. I provide some instructions on how to generate this image yourself [here](https://github.com/devos50/qemu-ios-generate-nand).

Download all the required files and save them to a convenient location. You should unzip the `nand_n72ap.zip` file, which contains a single directory named `nand`.

### Running the Emulator

We are now ready to run the emulator from the build directory with the following command:

```
./arm-softmmu/qemu-system-arm -M iPod-Touch,bootrom=<path to bootrom>,nand=<path to NAND directory>,nor=<path to NOR directory> -serial mon:stdio -cpu max -m 2G -d unimp -display sdl
```

The `nand` path is the directory that contains the `cs0`–`cs3` subdirectories (i.e. the `nand` folder produced by unzipping `nand_n72ap.zip`), and `nor` is the `nor_n72ap.bin` file. `-display sdl` opens the device screen; `-d unimp` logs accesses to unimplemented device registers and is safe to drop once things are working.

Interacting with the device (SDL window focused):

| Key | Button      |
| --- | ----------- |
| `H` | Home        |
| `P` | Power       |
| `=` | Volume up   |
| `-` | Volume down |

(These mappings are defined in `ipod_touch_key_event` in `hw/arm/ipod_touch_2g.c`.) Click and drag with the mouse to emulate touch input.

### USB device mode (appearing to the host as a real iPod)

Three machine options turn on USB device mode. All are off by default, so the
normal boot above is unaffected.

| Option | Meaning |
| --- | --- |
| `usb-attached=on` | Report a USB cable as present to the PMU. iOS leaves the entire USB device stack parked until it sees this. |
| `usb-tcp-addr=host:port` | Connect to a USB-over-TCP host bridge. Empty (the default) disables the link. |
| `usb-patch-mux-gate=on` | Patch the kernel so the USB stack goes on bus even though the PTP interface function never registers a driver. **Firmware-build-specific — verified only against 2.1.1 / build 5F138.** |

With a host bridge running (see `usbmuxd-qemu`, a fork of usbmuxd whose USB
backend speaks this transport), the emulated device appears to the standard
`libimobiledevice` tools:

```
./arm-softmmu/qemu-system-arm -M iPod-Touch,bootrom=<bootrom>,nand=<nand dir>,nor=<nor image>,\
    usb-attached=on,usb-patch-mux-gate=on,usb-tcp-addr=127.0.0.1:1235 \
    -serial mon:stdio -cpu max -m 2G -display sdl
```

```
$ USBMUXD_SOCKET_ADDRESS=127.0.0.1:27015 idevice_id -l
0f7085718094b779d89f56b4d62fd23f949897f9
$ USBMUXD_SOCKET_ADDRESS=127.0.0.1:27015 ideviceinfo
DeviceClass: iPod          ProductType: iPod2,1
ProductVersion: 2.1.1      BuildVersion: 5F138
...
```

#### The host bridge, and keeping the two halves in step

The host side is a fork of usbmuxd whose USB backend speaks this transport
instead of libusb: **[samhenrigold/usbmuxd](https://github.com/samhenrigold/usbmuxd), branch `qemu-backend`**.
Only the transport is replaced; the mux protocol itself is untouched upstream code.

The wire protocol between them is specified in **[docs/tcp-usb-protocol.md](docs/tcp-usb-protocol.md)**,
which is canonical for both repositories. The two sides exchange a version
handshake on connect and refuse to attach on a mismatch, so an out-of-step pair
fails at startup with a clear message rather than corrupting transfers.

Known-good pairs are recorded as matching tags in both repositories, so they
stay resolvable regardless of later rebases:

| qemu-ios tag | usbmuxd `qemu-backend` tag | Verified |
| --- | --- | --- |
| `usb-verified-2026-07-30` | `usb-verified-2026-07-30` | `idevice_id -l`, `ideviceinfo`, `idevicepair pair` |

`idevicepair pair` also succeeds. Note the guest needs roughly 100 seconds of
boot before it has programmed the USB core, so the host bridge should wait
before driving a USB reset.

If there are any issues running the above commands, please let me know by [opening an issue](https://github.com/devos50/qemu-ios/issues/new).

## Shutting the guest down cleanly (and making writes survive)

Start the emulator with a QMP monitor and shut it down with:

```
build/qemu-system-arm -M iPod-Touch,... -qmp unix:/tmp/it.sock,server,nowait
printf '{"execute":"qmp_capabilities"}{"execute":"system_powerdown"}' | nc -U /tmp/it.sock
```

**Do this before stopping the emulator if you care about anything the guest
wrote.** File *data* reaches flash promptly, but HFS+ keeps catalog (directory)
updates in memory and nothing forces them out on an idle device — measured, not
one page reaches flash in the three minutes after an `afcclient put`. Killing
QEMU therefore leaves every data block safely in the overlay with no directory
entry, and the file does not exist on the next boot. Unmounting the root volume
is what flushes the catalog, and only a real shutdown unmounts it.

`system_powerdown` means here what it means on a PC: the machine hands the guest
a power-button event and lets the OS shut itself down. iPhone OS 2.1.1 has no
remote shutdown at all — lockdownd has neither a reboot request nor a
diagnostics relay, and SpringBoard runs as `mobile`, so nothing in the guest can
call `reboot(2)` — so the "power-button event" is the real user gesture: the
machine holds the hold button until SpringBoard raises its power-off sheet and
then drags the slider across (`ipod_touch_powerdown_tick` in
`hw/arm/ipod_touch_2g.c`, timed on the virtual clock so it is not affected by
host load).

The guest ends its shutdown by clearing bit 6 of PMU register `0x10`, the power
latch that iBoot set on the way up. That is the model's cue to call
`qemu_system_shutdown_request()`, so QEMU exits by itself once the overlay is
complete. Pass `-no-shutdown` if you would rather it stop and stay stopped.

Guest-initiated *restart* is a different register: `AppleARMWatchDogTimer`'s
`PEHaltRestart` handler sets bit `0x100000` in the watchdog control register at
`0x3C800000`, and `hw/arm/ipod_touch_wdt.c` turns that into
`qemu_system_reset_request()`. The bootrom is re-staged on every reset, so the
machine reboots in place.

`IT_PWROFF_TRACE=1` logs the gesture; `IT_PMU_TRACE=1` logs every PMU register
access with the guest PC/LR that made it (noisy — the battery gauge is polled
continuously).

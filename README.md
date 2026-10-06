# T-Dongle: Wi-Fi to USB Ethernet

Firmware that turns a **LILYGO T-Dongle-S3** into a plug-in USB network adapter. The dongle joins a Wi-Fi network, and whatever it is plugged into sees an ordinary wired Ethernet port. No drivers are needed on macOS or Linux.

It is **one firmware with two modes**, chosen at runtime and remembered across restarts:

- **Wi-Fi bridge** (the default): the transparent adapter described below. The device on the USB side gets its address from your Wi-Fi network, as if it were on that network directly.
- **Tailnet gateway**: the dongle becomes a small router with its own USB subnet and joins one or more [Tailscale](https://tailscale.com) networks, so the host on the USB side can reach tailnet peers. It needs the Android companion app (see [Tailnet mode](#tailnet-mode)).

It was built for a Raspberry Pi running TeslaAndroid, where the Pi's own Wi-Fi is busy being an access point, but it works for anything that needs a wired port and only has Wi-Fi nearby.

```
phone hotspot / travel router / home Wi-Fi  (2.4 GHz)
                    │  Wi-Fi
              T-Dongle-S3
                    │  USB Ethernet
     Raspberry Pi, laptop, anything with USB
```

## What to buy

**[LILYGO T-Dongle-S3, the version with the 0.96" screen](https://amzn.to/4z7uQec)** (affiliate link).

Get the original with the 160×80 screen. The *Dual* and *Plus* variants are different boards and this firmware will not run on them.

## What to expect

| | |
|---|---|
| Speed | In bridge mode about **7 Mbit/s down, 5.5 Mbit/s up** with decent signal (measured on the v0.1 firmware). The chip's USB is USB 1.1 (12 Mbit/s), so it cannot go much faster. Fine for streaming, maps and apps; not a fast adapter. |
| Wi-Fi | **2.4 GHz only.** WPA2 and WPA3 personal, or open networks. No enterprise (EAP) or captive-portal hotel Wi-Fi. |
| Networks | Remembers up to 8, and joins the best one it can find. |
| Tested on | macOS, with one dongle. Linux and Raspberry Pi should work (standard CDC-NCM) but have not been tested yet. |

In Wi-Fi bridge mode the device plugged into the dongle gets its address straight from your Wi-Fi network, as if it were on that network directly. It is a bridge for one device, not a router.

## 1. Flash the firmware

Open **[muness.com/T-Dongle](https://muness.com/T-Dongle/)** in desktop Chrome or Edge.

1. Hold the dongle's button while you plug it into USB, then let go.
2. Click **Install**, pick the port, and allow erase.
3. Unplug the dongle and plug it back in without the button.
4. On the same page, enter your Wi-Fi name and password under **Add a Wi-Fi network** (see step 2 below).

To update later, use the same page: click **Prepare for update**, then **Install**, and decline erase to keep your saved networks and your chosen mode. No button needed. This also works when updating from the older bridge-only releases (v0.1.x): your saved networks are kept and the dongle starts in Wi-Fi bridge mode.

<details><summary>Build and flash from source instead</summary>

You need macOS or Linux with Git, Python 3.10+, CMake and Ninja, and a few GB of disk.

```sh
git clone https://github.com/muness/T-Dongle.git
cd T-Dongle
./tools/bootstrap.sh                                  # installs the pinned ESP-IDF toolchain
. "$HOME/.cache/tdongle/esp-idf-v5.5.5/export.sh"
./tools/build.sh          # builds, checks and packages dist/tdongle-VERSION/
./tools/flash.sh          # first time: hold the button while plugging in
```

Later updates need no button: run `./tools/build.sh` and `./tools/flash.sh` with the dongle running. The version comes from the `VERSION` file, or `TDONGLE_VERSION` if you set it.

</details>

## 2. Connect it to your Wi-Fi

The dongle has no Wi-Fi setup page of its own to join; you give it your network over USB, once. Pick whichever is easiest:

- **Flash page** (no app needed): with the dongle plugged in and running, open **[muness.com/T-Dongle](https://muness.com/T-Dongle/)** in desktop Chrome or Edge, enter the network name and password under **Add a Wi-Fi network**, and click **Save network to dongle**. Repeat for more networks (up to 8), such as home Wi-Fi, a travel router and your phone's hotspot.
- **Android companion app**: plug the dongle into the phone and add networks under *Networks*.
- **Serial console**: `scan`, then `profile {"slot":1,"priority":50,"name":"Home","ssid":"MyNetwork","password":"secret-pass"}` (slot 1 to 8; the next free slot adds a network). `python3 tools/provision.py --port PORT --provision` asks for the same details interactively without echoing the password.

The dongle joins the strongest saved network it can see. The screen shows **SET UP WI-FI** until one is saved, then **JOINING WI-FI**, then **WI-FI BRIDGE** once connected.

## 3. Manage networks later

Use the flash page card, the app, or the serial console: `list` shows what is saved, `use N` switches to network N now, and `del N` removes it.

## The screen

The screen is a status display with a title, two detail lines and the firmware version and USB state at the bottom: **SET UP WI-FI**, **JOINING WI-FI**, **WI-FI BRIDGE** (connected, with the USB host state), or in tailnet mode **TAILNET READY** and its sign-in and retry states. Green or "connected" means the dongle has joined Wi-Fi. It does not check whether that network actually reaches the internet.

The status light and the button menu of the older bridge-only releases (v0.1.x) are not in this firmware. The BOOT button is only for recovery: hold it while plugging in to enter the loader.

## Tailnet mode

Switch with the serial command `mode tailnet_gateway` (back with `mode wifi_bridge`), or from the companion app under **Help → Mode**. The dongle restarts into the chosen mode; if Android does not reconnect, unplug and replug it without the button. Saved Wi-Fi networks and tailnet identities are kept across switches and updates.

Tailnet mode needs:

- the **Android companion app** for tailnet sign-in and memberships (a computer can use the USB setup page at `http://192.168.77.1/` after the dongle's USB DHCP lease);
- a Wi-Fi network saved on the dongle, and a Tailscale account to sign in with (a browser approval or an auth key);
- a USB host that accepts a DHCP lease from the dongle. In this mode the dongle is a router on `192.168.77.0/24` and peers appear at `198.18.0.0/15` addresses; the host's address no longer comes from your Wi-Fi network.

Details and limits (8 peers per tailnet, IPv4 TCP/UDP from the USB side, no inbound tailnet traffic) are in [alternative/tailnet/README.md](alternative/tailnet/README.md).

## Troubleshooting

- **Screen stays on JOINING WI-FI.** Check the network is 2.4 GHz and the name and password are exact, including capitals. Phone hotspots often need "Maximize compatibility" (iPhone) or a 2.4 GHz band setting (Android).
- **Plugging it into a Mac takes over your internet.** macOS may rank the new Ethernet port above Wi-Fi. In System Settings, Network, use *Set Service Order* to drag Wi-Fi above **T-Dongle-S3 NCM**.
- **Connected, but slow or dropping.** It is a small antenna on a USB stick. Move it away from metal and closer to the router, or use a short USB extension cable.
- **Stuck, or will not flash.** Unplug it, hold the button, plug it back in, and run `./tools/flash.sh` again (or use the flash page). The chip's built-in loader always answers this way.

## For tinkerers

The dongle also has a serial console on its USB port, at 115200 baud. Type `help`; input is not echoed. `status` shows the mode, connection, signal, uptime, memory and firmware version. `list`, `use N`, `del N`, `scan` and `profile` manage networks, `mode` switches mode, and `bootloader` restarts into the loader for flashing.

Everything else lives in [docs/REFERENCE.md](docs/REFERENCE.md): build and release, flash layout, versioning, every console command, upgrade behaviour and design decisions. Measurements and test history are in [docs/VALIDATION.md](docs/VALIDATION.md).

Based on [DrWhax/esp32-usb-wifi](https://github.com/DrWhax/esp32-usb-wifi); see [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md) for credits and licenses.

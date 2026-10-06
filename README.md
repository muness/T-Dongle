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
| Networks | Remembers up to 8. It joins your preferred network if it can hear it, then the highest-priority one, then the strongest. |
| Tested on | macOS, with one dongle. Linux and Raspberry Pi should work (standard CDC-NCM) but have not been tested yet. |

In Wi-Fi bridge mode the device plugged into the dongle gets its address straight from your Wi-Fi network, as if it were on that network directly. It is a bridge for one device, not a router.

## 1. Flash the firmware

Open **[muness.com/T-Dongle](https://muness.com/T-Dongle/)** in desktop Chrome or Edge.

1. Hold the dongle's button while you plug it into USB, then let go.
2. Click **Install**, pick the port, and allow erase.
3. Unplug the dongle and plug it back in without the button.
4. Add your Wi-Fi network (see step 2 below): with your phone, on the dongle's own setup network, or from the same page.

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

1. Plug the dongle in. With no network saved yet it opens its own setup Wi-Fi: the screen shows **TDongle-XXXXXX** and **192.168.4.1**, and the light breathes blue.
2. On your phone, join the **TDongle-XXXXXX** Wi-Fi. It has no password. Stay connected when the phone says there is no internet.
3. The setup page usually opens on its own. If not, browse to **http://192.168.4.1**.
4. Tap your network in the list, type its password, and tap **Save network**.
5. Add more networks the same way if you like, such as home Wi-Fi, a travel router and your phone's hotspot.
6. Tap **Done**. The dongle restarts, the light turns amber while it joins, then **green** when it is connected and ready.

Setup closes by itself after 10 minutes. While it is open the dongle does not forward internet and no tailnet runs, and anyone nearby could join the setup Wi-Fi to add or delete saved networks, so finish and tap Done. The setup network can change Wi-Fi networks and nothing else.

Prefer not to use a phone? Any of these also works:

- **Flash page** (no app needed): with the dongle plugged in and running, open **[muness.com/T-Dongle](https://muness.com/T-Dongle/)** in desktop Chrome or Edge, enter the network name and password under **Add a Wi-Fi network**, and click **Save network to dongle**.
- **Android companion app**: plug the dongle into the phone and add networks under *Networks*.
- **Serial console**: `scan`, then `profile {"slot":1,"priority":50,"name":"Home","ssid":"MyNetwork","password":"secret-pass"}` (slot 1 to 8; the next free slot adds a network). `python3 tools/provision.py --port PORT --provision` asks for the same details interactively without echoing the password.

The screen shows **SET UP WI-FI** until one is saved, then **JOINING WI-FI**, then **WI-FI BRIDGE** once connected.

## 3. Add a network later

**Hold the button** for about 1.5 seconds to open the menu. Short presses step through it; hold again to choose.

- **Enter setup AP** reopens the setup network (step 2). It restarts the dongle for the few minutes setup takes.
- Choose a saved network to switch to it now. It also becomes the preferred network, kept across restarts.
- **Factory reset** forgets every saved network and the display settings. It asks twice: hold to choose it, then hold again within 10 seconds. Short press cancels. The routing mode and any tailnets are kept.

The setup page also lists what is saved, with a Delete button for each, and can set a name and a priority (0 to 100, default 50) per network. A higher priority wins over a stronger signal; the preferred network wins over both, unless it can barely be heard.

## The screen and light

A short press cycles the screen through **Connection**, **Traffic**, **Health** and **Setup**.

- **Connection**: the state (**WI-FI BRIDGE**, **TAILNET READY**, **JOINING WI-FI**, ...), the network and its signal strength in dBm, and the firmware version and USB state.
- **Traffic**: download and upload rate in Mbit/s, megabytes since start, frames, and a graph of the last 32 seconds.
- **Health**: uptime, time on Wi-Fi, joins and the last disconnect reason, USB resets; free and lowest heap; boots, watchdog resets and panics since power-up. The three views rotate every 4 seconds.
- **Setup**: the network in use, the mode, and how to open the menu.

The backlight dims after 60 seconds (the first press only wakes it). Change that with the serial command `display BRIGHTNESS ROTATION DIM_SECONDS` (brightness 5 to 100, rotation 0 or 1 for 180 degrees, dim time 10 to 3600 s); it is remembered.

| Light | Meaning |
|---|---|
| Breathing blue | Setup mode, or no network saved yet |
| Breathing amber | Joining Wi-Fi, waiting for the USB side (tailnet mode: or waiting for the tailnet) |
| Green | Connected to Wi-Fi and the USB link is ready (tailnet mode: and a tailnet is ready) |
| Two red blinks, repeating | Network not found or wrong password (tailnet mode: a tailnet failed to connect) |
| Breathing cyan | Tailnet mode: approve the sign-in in your browser |
| Slow red breathing | Recovery mode after repeated crashes: services are off, see Troubleshooting |

Green means the dongle has joined Wi-Fi. It does not check whether that network actually reaches the internet. The BOOT button is also the loader button: hold it while plugging in to enter the loader.

## Tailnet mode

Switch with the serial command `mode tailnet_gateway` (back with `mode wifi_bridge`), or from the companion app under **Help → Mode**. The dongle restarts into the chosen mode; if Android does not reconnect, unplug and replug it without the button. Saved Wi-Fi networks and tailnet identities are kept across switches and updates.

Tailnet mode needs:

- the **Android companion app** for tailnet sign-in and memberships (a computer can use the USB setup page at `http://192.168.77.1/` after the dongle's USB DHCP lease);
- a Wi-Fi network saved on the dongle, and a Tailscale account to sign in with (a browser approval or an auth key);
- a USB host that accepts a DHCP lease from the dongle. In this mode the dongle is a router on `192.168.77.0/24` and peers appear at `198.18.0.0/15` addresses; the host's address no longer comes from your Wi-Fi network.

Details and limits (8 peers per tailnet, IPv4 TCP/UDP from the USB side, no inbound tailnet traffic) are in [alternative/tailnet/README.md](alternative/tailnet/README.md).

## Troubleshooting

- **Screen stays on JOINING WI-FI, or the light stays amber or blinks red.** Check the network is 2.4 GHz and the name and password are exact, including capitals. Phone hotspots often need "Maximize compatibility" (iPhone) or a 2.4 GHz band setting (Android).
- **Plugging it into a Mac takes over your internet.** macOS may rank the new Ethernet port above Wi-Fi. In System Settings, Network, use *Set Service Order* to drag Wi-Fi above **T-Dongle-S3 NCM**.
- **Connected, but slow or dropping.** It is a small antenna on a USB stick. Move it away from metal and closer to the router, or use a short USB extension cable.
- **Stuck, or will not flash.** Unplug it, hold the button, plug it back in, and run `./tools/flash.sh` again (or use the flash page). The chip's built-in loader always answers this way.

## For tinkerers

The dongle also has a serial console on its USB port, at 115200 baud. Type `help`; input is not echoed. `status` shows the mode, connection, signal, uptime, memory and firmware version. `list`, `use N`, `del N`, `scan` and `profile` manage networks, `setup`, `reset` and `confirm-reset` do what the button menu does, `display` sets brightness, rotation and dim time, `mode` switches mode, and `bootloader` restarts into the loader for flashing.

Everything else lives in [docs/REFERENCE.md](docs/REFERENCE.md): build and release, flash layout, versioning, every console command, upgrade behaviour and design decisions. Measurements and test history are in [docs/VALIDATION.md](docs/VALIDATION.md).

Based on [DrWhax/esp32-usb-wifi](https://github.com/DrWhax/esp32-usb-wifi); see [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md) for credits and licenses.

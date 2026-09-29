# T-Dongle: Wi-Fi to USB Ethernet

Firmware that turns a **LILYGO T-Dongle-S3** into a plug-in USB network adapter. The dongle joins a Wi-Fi network, and whatever it is plugged into sees an ordinary wired Ethernet port. No drivers are needed on macOS or Linux.

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
| Speed | About **7 Mbit/s down, 5.5 Mbit/s up** with decent signal. The chip's USB is USB 1.1 (12 Mbit/s), so it cannot go much faster. Fine for streaming, maps and apps; not a fast adapter. |
| Wi-Fi | **2.4 GHz only.** WPA2 and WPA3 personal, or open networks. No enterprise (EAP) or captive-portal hotel Wi-Fi. |
| Networks | Remembers up to 8, and joins the best one it can find. |
| Tested on | macOS, with one dongle. Linux and Raspberry Pi should work (standard CDC-NCM) but have not been tested yet. |

The device plugged into the dongle gets its address straight from your Wi-Fi network, as if it were on that network directly. It is a bridge for one device, not a router.

## 1. Flash the firmware

Open **[muness.com/T-Dongle](https://muness.com/T-Dongle/)** in desktop Chrome or Edge.

1. Hold the dongle's button while you plug it into USB, then let go.
2. Click **Install**, pick the port, and allow erase.
3. Unplug the dongle and plug it back in without the button.

To update later, use the same page: click **Prepare for update**, then **Install**, and decline erase to keep your saved networks. No button needed.

<details><summary>Build and flash from source instead</summary>

You need macOS or Linux with Git, Python 3.10+, CMake and Ninja, and a few GB of disk.

```sh
git clone https://github.com/muness/T-Dongle.git
cd T-Dongle
./tools/bootstrap.sh                                  # installs the pinned ESP-IDF toolchain
. "$HOME/.cache/tdongle/esp-idf-v5.5.5/export.sh"
./tools/build.sh full
./tools/flash.sh          # first time: hold the button while plugging in
```

Later updates need no button: run `./tools/build.sh full` and `./tools/flash.sh` with the dongle running.

</details>

## 2. Connect it to your Wi-Fi

1. Plug the dongle in. The screen shows **TDongle-XXXXXX** and **192.168.4.1**, and the light breathes blue.
2. On your phone, join the **TDongle-XXXXXX** Wi-Fi. It has no password. Stay connected when the phone says there is no internet.
3. The setup page usually opens on its own. If not, browse to **http://192.168.4.1**.
4. Tap your network in the list, type its password, and tap **Save network**.
5. Add more networks the same way if you like, such as home Wi-Fi, a travel router and your phone's hotspot.
6. Tap **Done**. The dongle restarts, the light turns amber while it joins, then **green** when it is connected and ready.

Setup closes by itself after 10 minutes. While it is open the dongle does not forward internet, and anyone nearby could join the setup Wi-Fi, so finish and tap Done.

## 3. Add a network later

**Hold the button** for about 1.5 seconds to open the menu. Short presses step through it; hold again to choose.

- Choose an **(empty)** slot to reopen setup and add a network there. Then follow step 2.
- Choose a saved network to switch to it now.
- *Enter setup AP* opens setup without picking a slot.

The setup page also lists what is saved, with a Delete button for each.

## The screen and light

A short press cycles the screen through **Connection**, **Traffic**, **Health** and **Setup**.

| Light | Meaning |
|---|---|
| Breathing blue | Setup mode, or no network saved yet |
| Breathing amber | Joining Wi-Fi, or waiting for the USB side |
| Green | Connected to Wi-Fi and the USB link is ready |
| Two red blinks, repeating | Network not found, or wrong password |

Green means the dongle has joined Wi-Fi. It does not check whether that network actually reaches the internet.

## Troubleshooting

- **Light stays amber or blinks red.** Check the network is 2.4 GHz and the name and password are exact, including capitals. Phone hotspots often need "Maximize compatibility" (iPhone) or a 2.4 GHz band setting (Android).
- **Plugging it into a Mac takes over your internet.** macOS may rank the new Ethernet port above Wi-Fi. In System Settings, Network, use *Set Service Order* to drag Wi-Fi above **T-Dongle-S3 NCM**.
- **Connected, but slow or dropping.** It is a small antenna on a USB stick. Move it away from metal and closer to the router, or use a short USB extension cable.
- **Stuck, or will not flash.** Unplug it, hold the button, plug it back in, and run `./tools/flash.sh` again. The chip's built-in loader always answers this way.

## For tinkerers

The dongle also has a serial console on its USB port, at 115200 baud. Type `help`; input is not echoed. `status` shows the connection, signal, traffic counters and memory. `list`, `use N`, `del N` and `setup N` manage networks.

Everything else lives in [docs/REFERENCE.md](docs/REFERENCE.md): build variants, flash layout, every console command, the screen pages, security notes and design decisions. Measurements and test history are in [docs/VALIDATION.md](docs/VALIDATION.md).

Based on [DrWhax/esp32-usb-wifi](https://github.com/DrWhax/esp32-usb-wifi); see [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md) for credits and licenses.

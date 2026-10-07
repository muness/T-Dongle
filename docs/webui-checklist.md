# Web controller checklist

Run this by hand after flashing a build with the web controller. The page has two ways in, and both must behave the same:

- **Web Serial**: open `site/controller.html` (or the published copy) in Chrome or Edge, then press **Connect dongle (Web Serial)**. Works in both modes.
- **USB network (HTTP)**: with the dongle in tailnet gateway mode, open `http://192.168.77.1/` on the device it is plugged into.

On a laptop, run each section once over each transport. On a phone, use the USB network: plug the dongle into the phone, put it in tailnet mode, and open `http://192.168.77.1/`. If your phone's Chrome shows **Connect dongle**, run Web Serial too.

Write down the transport (S = Web Serial, H = HTTP) next to each tick.

## 0. Before you start

- [ ] The host tests pass: `cargo test -p tdongle-setup --test webui_contract --test usb` and `node rust/webui/test.mjs` (from the repo root).
- [ ] The header says **Connected · Web Serial** or **Connected · USB network**.

## 1. Status (polls every 3 s)

- [ ] Mode, Wi-Fi, Channel / PHY, USB, Free heap, Uptime and Firmware are filled in, and Uptime keeps going up.
- [ ] **Temperature** shows `NN.N °C (peak NN.N)`. On the current Rust firmware it shows `-`, because the reading is not wired in yet (see *Known gaps*). Write down which one you see.
- [ ] S and H show the same values, give or take one poll.

## 2. Wi-Fi networks

- [ ] The saved list matches what the Android app shows, including which one is **connected** and which is **preferred**.
- [ ] **Scan nearby** fills the dropdown within about 25 s, and picking a network fills in the SSID.
- [ ] Save a test network into a free slot. A reply starting with `OK` appears and the network shows up in the list.
- [ ] **Use & prefer** on another network switches to it. Expect the link to drop for a moment.
- [ ] **Delete** the test network. It disappears from the list.

## 3. Display

- [ ] Change brightness and press **Apply**. The screen changes, and the form shows the new value after the next poll.

## 4. Tailnets (tailnet mode only)

- [ ] The tailnet section is visible in tailnet mode and hidden in Wi-Fi bridge mode.
- [ ] Add a tailnet with no auth key. **Continue sign-in** appears, and its link goes to `https://login.tailscale.com/...`.
- [ ] **Disconnect** and then **Reconnect** a tailnet. The state line follows.
- [ ] **Devices** lists the peers, each marked direct or relay.
- [ ] **Remove** the test tailnet.

## 5. Things that must be refused over HTTP

From the laptop, with the dongle in tailnet mode:

```sh
for c in "selftest flash" bootloader reset "boot-status" temperature status; do
  printf '%-16s ' "$c"
  curl -s -o /dev/null -w '%{http_code}\n' -H 'Origin: http://192.168.77.1' \
    -H 'Content-Type: application/x-tdongle-command' --data-binary "$c" http://192.168.77.1/serial
done
```

- [ ] `selftest flash`, `bootloader`, `reset`, `boot-status` and `temperature` return **403**, and `status` returns **200**.
- [ ] Without the `Origin` header, `status` returns **403**. With `Content-Type: text/plain`, it returns **415**.
- [ ] Over Web Serial (a serial terminal, not the page), `selftest flash` prints `selftest flash: ... PASS`. This command is console-only on purpose. It erases and programs a flash sector, so run it only on a bench unit, and only on rust/port firmware.

## 6. Restart

- [ ] **Mode → Save and restart** switches the mode. The page says the dongle is restarting and not that something failed. Reconnect afterwards.
- [ ] **Reboot dongle** does the same.

## Known gaps (as of this checklist)

- No `temperature` command exists. Temperature is the `chip_temperature` line of `status`, and the Rust firmware currently always reports it as invalid (`valid=0`).
- `selftest flash` exists only on `rust/port`, not on `rust/webui`.
- The Android app reaches the USB network through `/command` and `/wifi-scan`. The Rust firmware serves `/serial` and `/status`, so the app's tailnet setup view gets 404 on those two paths.

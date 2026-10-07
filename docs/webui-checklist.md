# Web controller checklist

Run this after flashing a build. The desktop controller and Android-compatible USB setup page share firmware state, with different controls:

- **Web Serial**: open `site/controller.html` (or the published copy) in Chrome or Edge, then press **Connect dongle (Web Serial)**. Works in both modes.
- **USB network (HTTP)**: with the dongle in tailnet gateway mode, open `http://192.168.77.1/` on the device it is plugged into.

Run the desktop sections below over Web Serial. For the USB page, including Android’s in-app tailnet setup view, run the USB setup checks below. The USB setup page uses `/status`, `/wifi-scan` and `/command`; display settings, preferred-network selection and standalone reboot remain desktop controller controls.

## USB setup page (browser and Android in-app view)

- [ ] The heading says **Wi-Fi & tailnets**, and Wi-Fi connection status appears.
- [ ] **Find nearby Wi-Fi** fills the dropdown; saving a network and removing it update saved networks.
- [ ] Sign in to the single tailnet; its sign-in link, connection state and returned devices appear.
- [ ] Disconnect and reconnect the saved tailnet, preserving its identity.
- [ ] Switching routing mode saves and restarts; reconnect and confirm the new mode.
- [ ] Free memory and valid chip temperature appear in **About this preview**.
- [ ] Android’s in-app page completes these actions without denied `/serial` requests.

Write down the transport (S = Web Serial, H = USB browser, A = Android in-app) next to each tick.

## 0. Before you start

- [ ] The host tests pass: `cargo test -p tdongle-setup --test webui_contract --test usb` and `node rust/webui/test.mjs` (from the repo root).
- [ ] The desktop header says **Connected · Web Serial**.

## 1. Status (polls every 3 s)

- [ ] Mode, Wi-Fi, Channel / PHY, USB, Free heap, Uptime and Firmware are filled in, and Uptime keeps going up.
- [ ] **Temperature** shows `NN.N °C (peak NN.N)` when the sensor is valid; write down the reading.
- [ ] Desktop and USB setup pages agree on Wi-Fi, routing mode and tailnet state, give or take one poll.

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
- [ ] Over Web Serial (a serial terminal, not the page), `selftest flash` prints `selftest flash: ... PASS`. This command is console-only on purpose. It erases and programs a flash sector, so run it only on a bench unit, and only on the qualified Rust firmware for this dongle.

## 6. Restart

- [ ] **Mode → Save and restart** switches the mode. The page says the dongle is restarting and not that something failed. Reconnect afterwards.
- [ ] **Reboot dongle** does the same.

## Known gaps (as of this checklist)

- No `temperature` command exists. Temperature is the `chip_temperature` line of `status`.
- The USB page shows the devices returned in the status snapshot; peer pagination is not available in the Rust USB router.
- The desktop controller also supports `/serial` HTTP commands; the embedded USB setup page uses the Android-compatible JSON endpoints.

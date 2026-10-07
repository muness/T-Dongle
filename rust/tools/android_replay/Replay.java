package com.muness.tdongle.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The Android app's own management client (unmodified, compiled from its sources) driven against the Rust firmware's replies.
 * The replies are fixtures written by rust/crates/tdongle-serial/tests/android_app.rs from the functions the firmware's dispatcher calls.
 * Run by rust/tools/android_replay.sh.
 */
public final class Replay {
    /** A dongle that answers each line with the fixture for its current state; a write that changes something moves it to the next state. */
    static final class FakeDongle implements SerialTransport {
        final Map<String, String> replies;
        final String mode;
        String state = "base";
        byte[] pending = new byte[0];
        int at;
        FakeDongle(Map<String, String> replies, String mode) { this.replies = replies; this.mode = mode; }
        @Override public int read(byte[] destination, int timeoutMillis) {
            int n = Math.min(destination.length, pending.length - at);
            System.arraycopy(pending, at, destination, 0, n);
            at += n;
            return n;
        }
        @Override public void write(byte[] bytes, int timeoutMillis) throws IOException {
            String line = new String(bytes, StandardCharsets.US_ASCII);
            if (!line.endsWith("\n")) throw new IOException("unterminated line");
            line = line.substring(0, line.length() - 1);
            String reply = replies.get(mode + "/" + state + "\u0000" + line);
            if (reply == null) reply = replies.get(mode + "/base\u0000" + line);
            if (reply == null) throw new AssertionError("no Rust reply recorded for " + mode + "/" + state + " `" + line + "`");
            pending = reply.getBytes(StandardCharsets.ISO_8859_1);
            at = 0;
            if (line.startsWith("metadata ")) state = "metadata";
            if (line.startsWith("display ")) state = "display";
        }
        @Override public void close() { }
    }

    static Map<String, String> load(String path) throws IOException {
        byte[] all = Files.readAllBytes(Paths.get(path));
        String text = new String(all, StandardCharsets.ISO_8859_1);
        Map<String, String> out = new HashMap<>();
        int i = 0;
        while (i < text.length()) {
            int nl = text.indexOf('\n', i);
            String head = text.substring(i, nl);
            // @@@@ STATE LEN N LINE text
            String[] p = head.split(" ", 5);
            if (!p[0].equals("@@@@") || !p[2].equals("LEN")) throw new IOException("bad fixture head " + head);
            int len = Integer.parseInt(p[3]);
            String line = p[4].substring("LINE ".length());
            out.put(p[1] + "\u0000" + line, text.substring(nl + 1, nl + 1 + len));
            i = nl + 1 + len;
        }
        return out;
    }

    static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
        System.out.println("  ok  " + what);
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> replies = load(args[0]);
        for (String mode : new String[] {"bridge", "tailnet"}) {
            System.out.println(mode + ":");
            ManagementClient c = new ManagementClient(new FakeDongle(replies, mode));
            c.identify();
            check(true, "identify (help signature accepted)");
            Capabilities caps = c.capabilities();
            for (String f : new String[] {"boot_diagnostics", "mode_switch", "chip_temperature", "metadata", "display_readback", "automatic_display"})
                check(caps.supports(f), "capability " + f);
            check(caps.supports("tailnet_gateway") == mode.equals("tailnet"), "tailnet_gateway only in tailnet mode");
            DongleStatus st = c.status();
            check(st.mode.equals("adapter") && st.trial == 0 && st.activeSlot == 1 && st.associated(), "status first line");
            System.out.println("      chip temperature as the app shows it: " + st.chipTemperature);
            if (System.getProperty("expectNegativeTemperature") != null)
                check(st.chipTemperature.equals("Chip temperature · -5.2 °C · peak 61.5 °C"), "a reading below zero is shown");
            DisplaySettings d = c.displaySettings();
            check(d.brightness == 60 && d.rotation == 0 && d.dimSeconds == 60, "display-settings");
            c.display(d, new DisplaySettings(80, 1, 120));
            check(true, "display change confirmed by display-settings read-back");
            check(c.preferred() == 1, "preference");
            List<SavedNetwork> nets = c.networks();
            check(nets.size() == 2 && nets.get(1).name.equals("Corner cafe") && nets.get(1).priority == 40, "list");
            List<ScanNetwork> scan = c.scanNetworks();
            check(scan.size() == 2 && scan.get(0).ssid.equals("Cafe") && scan.get(0).rssi == -50, "scan");
            c.metadata(nets.get(1), "Cafe 2", 90, true);
            check(true, "metadata acknowledged and confirmed by list and preference read-back");
            c.retryStartup();
            check(true, "retry-startup acknowledged");
        }
        System.out.println("PASS: the app's ManagementClient accepts the Rust replies");
    }
}

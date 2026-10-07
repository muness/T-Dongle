# esp-hal 1.2.2, patched to leave the RTC watchdog armed across `init`

Vendored from crates.io and used through `[patch.crates-io]` in the no_std images. The only change (marked `PATCH` in `src/lib.rs`): `init()` no longer calls `rtc.rwdt.disable()`.
Everything else is the upstream source. Reason: the bootloader (`bootloader_components/tdongle_rescue`) arms the RTC watchdog (digital-core reset, about 30 s) and the app must not
switch it off; `tdongle_rescue::arm()` re-arms it with the app's own timeout as the first statement after `init`, and the progress supervisor feeds it.
Upstreamable as an `esp_hal::Config` option ("keep the RTC watchdog running").

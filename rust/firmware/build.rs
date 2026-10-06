fn main() {
    embuild::build::CfgArgs::output_propagated("ESP_IDF").expect("esp-idf cfg");
    embuild::build::LinkArgs::output_propagated("ESP_IDF").expect("esp-idf link args");
    // The USB transmit ring drains on every IN transfer completion and the receive statistics stamp every OUT NTB; TinyUSB has no hook for either,
    // so the NCM class driver's transfer-complete handler is wrapped at link time (usb/net.rs `__wrap_netd_xfer_cb`). Same mechanism as the C firmware's
    // components/esp_tinyusb/CMakeLists.txt.
    println!("cargo:rustc-link-arg=-Wl,--wrap=netd_xfer_cb");
}

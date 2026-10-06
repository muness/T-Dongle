//! The T-Dongle's USB identity, byte for byte what the C firmware enumerates with.
//!
//! The C firmware gets these from esp_tinyusb's `usb_descriptors.c` (CDC x1 + NCM, full speed) and the strings the project passes to
//! `tinyusb_driver_install` (`start_usb` in `alternative/tailnet/main/gateway_main.c`, `usb_identity.h`). A host that already knows the adapter
//! keeps its device identity, its service name and its position in the network service order only if the Rust firmware enumerates
//! identically, so the tests compare the built descriptors with bytes dumped from the C image's ELF (`tools/dump_c_descriptors.py`).
//!
//! The configuration descriptor is assembled from the same building blocks as TinyUSB's `TUD_*_DESCRIPTOR` macros, in a `const fn`, so it is a
//! checked read-only constant in flash and not a hand-typed table.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Espressif's USB vendor id (`TINYUSB_ESPRESSIF_VID`).
pub const VENDOR_ID: u16 = 0x303A;
/// `USB_TUSB_PID`: `0x4000 | CDC(1) << 0` with CDC x1 and every other class off.
pub const PRODUCT_ID: u16 = 0x4001;
/// `CONFIG_TINYUSB_DESC_BCD_DEVICE`.
pub const BCD_DEVICE: u16 = 0x0100;
/// Control endpoint size (`CFG_TUD_ENDPOINT0_SIZE`).
pub const EP0_SIZE: u8 = 64;
/// The NCM class's maximum segment size: one Ethernet frame (`CFG_TUD_NET_MTU`, 1,514 bytes).
pub const NET_MTU: u16 = 1514;

/// String descriptor indices (`STRID_*` of `usb_descriptors.c`, CDC + NCM only).
pub mod string_id {
    /// Language id table (index 0).
    pub const LANGID: u8 = 0;
    /// Manufacturer.
    pub const MANUFACTURER: u8 = 1;
    /// Product: what a Mac shows as the network service name.
    pub const PRODUCT: u8 = 2;
    /// Serial number: the Wi-Fi station MAC as 12 hex digits.
    pub const SERIAL: u8 = 3;
    /// The CDC-ACM interface ("Management").
    pub const CDC_INTERFACE: u8 = 4;
    /// The NCM interface ("USB network").
    pub const NET_INTERFACE: u8 = 5;
    /// The NCM `iMACAddress`: the MAC the host adopts, 12 hex digits.
    pub const MAC: u8 = 6;
    /// How many strings the table has.
    pub const COUNT: usize = 7;
}

/// Interface numbers.
pub mod interface {
    /// CDC-ACM control interface (data is the next one).
    pub const CDC: u8 = 0;
    /// NCM control interface (the NTB data interface is the next one).
    pub const NET: u8 = 2;
    /// Total interface count.
    pub const COUNT: u8 = 4;
}

/// Endpoint addresses (`EPNUM_*`: notification and data endpoints are numbered in the order of the C enum).
pub mod endpoint {
    /// CDC notification (IN, interrupt).
    pub const CDC_NOTIFICATION: u8 = 0x81;
    /// CDC data OUT.
    pub const CDC_OUT: u8 = 0x02;
    /// CDC data IN.
    pub const CDC_IN: u8 = 0x82;
    /// NCM notification (IN, interrupt).
    pub const NET_NOTIFICATION: u8 = 0x83;
    /// NCM data OUT: host to device (NTBs the class driver reassembles into datagrams).
    pub const NET_OUT: u8 = 0x04;
    /// NCM data IN: device to host.
    pub const NET_IN: u8 = 0x84;
}

/// `bcdUSB` 2.0.
const USB_VERSION: u16 = 0x0200;
/// Bulk endpoint size at full speed.
const BULK_SIZE: u16 = 64;

/// The device descriptor (18 bytes). `bDeviceClass` is Miscellaneous/Common/IAD, as required for a composite device with CDC.
pub const DEVICE: [u8; 18] = {
    let usb = USB_VERSION.to_le_bytes();
    let vendor = VENDOR_ID.to_le_bytes();
    let product = PRODUCT_ID.to_le_bytes();
    let device = BCD_DEVICE.to_le_bytes();
    [
        18, // bLength
        1,  // bDescriptorType: device
        usb[0],
        usb[1], // bcdUSB
        0xEF,   // bDeviceClass: miscellaneous
        0x02,   // bDeviceSubClass: common
        0x01,   // bDeviceProtocol: interface association descriptor
        EP0_SIZE,
        vendor[0],
        vendor[1],
        product[0],
        product[1],
        device[0],
        device[1],
        string_id::MANUFACTURER,
        string_id::PRODUCT,
        string_id::SERIAL,
        1, // bNumConfigurations
    ]
};

/// Total length of [`CONFIG_FS`].
pub const CONFIG_LEN: usize = 9 + CDC_LEN + NCM_LEN;
const CDC_LEN: usize = 8 + 9 + 5 + 5 + 4 + 5 + 7 + 9 + 7 + 7;
const NCM_LEN: usize = 8 + 9 + 5 + 5 + 13 + 6 + 7 + 9 + 9 + 7 + 7;

/// A cursor over a fixed array, for `const` assembly of descriptors.
struct Writer {
    bytes: [u8; CONFIG_LEN],
    at: usize,
}

impl Writer {
    const fn new() -> Self {
        Self { bytes: [0; CONFIG_LEN], at: 0 }
    }

    const fn put(mut self, data: &[u8]) -> Self {
        let mut i = 0;
        while i < data.len() {
            self.bytes[self.at + i] = data[i];
            i += 1;
        }
        self.at += data.len();
        self
    }

    /// `TUD_CONFIG_DESCRIPTOR(1, interfaces, 0, total, 0, 500)`: configuration 1, bus powered (attribute 0x80), 500 mA.
    const fn configuration(self) -> Self {
        let total = (CONFIG_LEN as u16).to_le_bytes();
        self.put(&[9, 2, total[0], total[1], interface::COUNT, 1, 0, 0x80, 250])
    }

    /// An interface association descriptor.
    const fn association(self, first: u8, count: u8, class: u8, subclass: u8) -> Self {
        self.put(&[8, 0x0B, first, count, class, subclass, 0, 0])
    }

    /// An interface descriptor.
    const fn interface(self, number: u8, alternate: u8, endpoints: u8, class: u8, subclass: u8, protocol: u8, string: u8) -> Self {
        self.put(&[9, 4, number, alternate, endpoints, class, subclass, protocol, string])
    }

    /// An endpoint descriptor (`transfer`: 2 bulk, 3 interrupt).
    const fn endpoint(self, address: u8, transfer: u8, size: u16, interval: u8) -> Self {
        let size = size.to_le_bytes();
        self.put(&[7, 5, address, transfer, size[0], size[1], interval])
    }

    /// `TUD_CDC_DESCRIPTOR(itf, str, 0x81, 8, 0x02, 0x82, 64)`.
    const fn cdc(self) -> Self {
        self.association(interface::CDC, 2, 2, 2)
            .interface(interface::CDC, 0, 1, 2, 2, 0, string_id::CDC_INTERFACE)
            .put(&[5, 0x24, 0x00, 0x20, 0x01]) // header functional descriptor: bcdCDC 1.20
            .put(&[5, 0x24, 0x01, 0x00, interface::CDC + 1]) // call management: no handling, data on the next interface
            .put(&[4, 0x24, 0x02, 0x06]) // abstract control management: line coding and serial state
            .put(&[5, 0x24, 0x06, interface::CDC, interface::CDC + 1]) // union
            .endpoint(endpoint::CDC_NOTIFICATION, 3, 8, 1)
            .interface(interface::CDC + 1, 0, 2, 0x0A, 0, 0, 0)
            .endpoint(endpoint::CDC_OUT, 2, BULK_SIZE, 0)
            .endpoint(endpoint::CDC_IN, 2, BULK_SIZE, 0)
    }

    /// `TUD_CDC_NCM_DESCRIPTOR(itf, str, mac, 0x83, 64, 0x04, 0x84, 64, 1514)`.
    const fn ncm(self) -> Self {
        let mtu = NET_MTU.to_le_bytes();
        self.association(interface::NET, 2, 2, 0x0D)
            .interface(interface::NET, 0, 1, 2, 0x0D, 0, string_id::NET_INTERFACE)
            .put(&[5, 0x24, 0x00, 0x10, 0x01]) // header functional descriptor: bcdCDC 1.10
            .put(&[5, 0x24, 0x06, interface::NET, interface::NET + 1]) // union
            // Ethernet networking functional descriptor: iMACAddress, no statistics, max segment size, no multicast or power filters.
            .put(&[0x0D, 0x24, 0x0F, string_id::MAC, 0, 0, 0, 0, mtu[0], mtu[1], 0, 0, 0])
            .put(&[6, 0x24, 0x1A, 0x00, 0x01, 0x21]) // NCM functional descriptor: bcdNcmVersion 1.00, capabilities
            .endpoint(endpoint::NET_NOTIFICATION, 3, 64, 50)
            .interface(interface::NET + 1, 0, 0, 0x0A, 0, 1, 0) // alternate 0: no endpoints (the host's default)
            .interface(interface::NET + 1, 1, 2, 0x0A, 0, 1, 0) // alternate 1: the NTB data endpoints
            .endpoint(endpoint::NET_IN, 2, BULK_SIZE, 0)
            .endpoint(endpoint::NET_OUT, 2, BULK_SIZE, 0)
    }
}

/// The full-speed configuration descriptor: CDC-ACM (interfaces 0 and 1) and CDC-NCM (interfaces 2 and 3).
pub const CONFIG_FS: [u8; CONFIG_LEN] = {
    let writer = Writer::new().configuration().cdc().ncm();
    assert!(writer.at == CONFIG_LEN);
    writer.bytes
};

/// The strings a host reads, with the two that depend on the device.
#[derive(Clone, Copy, Debug)]
pub struct Strings<'a> {
    /// Product string: `T-Dongle-S3 NCM` in bridge mode, `T-Dongle-S3 tailnet gateway` in tailnet mode (`gateway_usb_product`).
    pub product: &'a str,
    /// Serial number: the station MAC as 12 upper-case hex digits ([`mac_text`]).
    pub serial: &'a str,
    /// `iMACAddress`: the MAC the host adopts as its own, 12 upper-case hex digits.
    pub mac: &'a str,
}

/// The manufacturer string (`T-Dongle Adapter Project`).
pub const MANUFACTURER: &str = "T-Dongle Adapter Project";
/// The CDC-ACM interface string.
pub const CDC_INTERFACE: &str = "Management";
/// The NCM interface string.
pub const NET_INTERFACE: &str = "USB network";
/// The product string in Wi-Fi bridge mode: byte for byte what v0.1.x enumerated as, so a Mac or Pi that already knows the adapter keeps its
/// service name and its position in the service order across the upgrade.
pub const PRODUCT_BRIDGE: &str = "T-Dongle-S3 NCM";
/// The product string in tailnet gateway mode.
pub const PRODUCT_TAILNET: &str = "T-Dongle-S3 tailnet gateway";

/// `"%02X%02X%02X%02X%02X%02X"`.
#[must_use]
pub const fn mac_text(mac: [u8; 6]) -> [u8; 12] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = [0u8; 12];
    let mut i = 0;
    while i < 6 {
        out[2 * i] = HEX[(mac[i] >> 4) as usize];
        out[2 * i + 1] = HEX[(mac[i] & 15) as usize];
        i += 1;
    }
    out
}

/// The most UTF-16 code units a string descriptor carries (`MAX_DESC_BUF_SIZE` of esp_tinyusb's descriptors_control.c is 32 units including
/// the header; ASCII strings only).
pub const STRING_UNITS_MAX: usize = 32;

/// What the host asked for and cannot be given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringError {
    /// The index is outside the table (TinyUSB stalls the request).
    OutOfRange,
}

/// Build the string descriptor for `index` into `out` (UTF-16 code units, the first is the descriptor header), returning the number of units
/// used. The port of `tud_descriptor_string_cb`: index 0 is the language table (English, 0x0409); the others are the ASCII text widened to
/// UTF-16 and cut at [`STRING_UNITS_MAX`] - 1 characters.
///
/// # Errors
/// [`StringError::OutOfRange`] for an index that has no string.
pub fn string_descriptor(index: u8, strings: &Strings<'_>, out: &mut [u16; STRING_UNITS_MAX]) -> Result<usize, StringError> {
    let text: &str = match index {
        string_id::LANGID => {
            out[1] = 0x0409;
            out[0] = (3 << 8) | 4;
            return Ok(2);
        }
        string_id::MANUFACTURER => MANUFACTURER,
        string_id::PRODUCT => strings.product,
        string_id::SERIAL => strings.serial,
        string_id::CDC_INTERFACE => CDC_INTERFACE,
        string_id::NET_INTERFACE => NET_INTERFACE,
        string_id::MAC => strings.mac,
        _ => return Err(StringError::OutOfRange),
    };
    let count = text.len().min(STRING_UNITS_MAX - 1);
    for (unit, byte) in out[1..=count].iter_mut().zip(text.bytes()) {
        *unit = u16::from(byte);
    }
    out[0] = (3 << 8) | (2 * count as u16 + 2);
    Ok(count + 1)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;

    const C_DEVICE: &[u8] = include_bytes!("../tests/golden/c_device_descriptor.bin");
    const C_CONFIG: &[u8] = include_bytes!("../tests/golden/c_config_descriptor_fs.bin");

    #[test]
    fn device_descriptor_is_what_the_c_firmware_enumerates() {
        assert_eq!(DEVICE.as_slice(), C_DEVICE);
    }

    #[test]
    fn configuration_descriptor_is_what_the_c_firmware_enumerates() {
        assert_eq!(CONFIG_FS.as_slice(), C_CONFIG);
        assert_eq!(usize::from(u16::from_le_bytes([CONFIG_FS[2], CONFIG_FS[3]])), CONFIG_FS.len());
    }

    /// The structure, not just the bytes: every descriptor's length field chains exactly to the total, and the interface and endpoint
    /// numbers are the ones the rest of the firmware assumes.
    #[test]
    fn configuration_descriptor_is_well_formed() {
        let mut at = 0;
        let mut interfaces = Vec::new();
        let mut endpoints = Vec::new();
        while at < CONFIG_FS.len() {
            let length = usize::from(CONFIG_FS[at]);
            assert!(length >= 2 && at + length <= CONFIG_FS.len(), "descriptor at {at} overruns");
            match CONFIG_FS[at + 1] {
                4 => interfaces.push((CONFIG_FS[at + 2], CONFIG_FS[at + 3])),
                5 => endpoints.push(CONFIG_FS[at + 2]),
                _ => {}
            }
            at += length;
        }
        assert_eq!(at, CONFIG_FS.len());
        assert_eq!(interfaces, [(0, 0), (1, 0), (2, 0), (3, 0), (3, 1)]);
        assert_eq!(endpoints, [0x81, 0x02, 0x82, 0x83, 0x84, 0x04]);
        assert_eq!(CONFIG_FS[4], interface::COUNT);
    }

    #[test]
    fn mac_text_is_upper_case_hex() {
        assert_eq!(&mac_text([0x02, 0x1a, 0xff, 0x00, 0x7e, 0xb3]), b"021AFF007EB3");
    }

    #[test]
    fn string_descriptors() {
        let strings = Strings { product: PRODUCT_BRIDGE, serial: "021AFF007EB3", mac: "021AFF007EB3" };
        let mut out = [0u16; STRING_UNITS_MAX];
        assert_eq!(string_descriptor(0, &strings, &mut out), Ok(2));
        assert_eq!(&out[..2], &[0x0304, 0x0409]);
        let n = string_descriptor(string_id::PRODUCT, &strings, &mut out).unwrap();
        assert_eq!(n, 1 + PRODUCT_BRIDGE.len());
        assert_eq!(out[0], 0x0300 | (2 * PRODUCT_BRIDGE.len() as u16 + 2));
        let text: Vec<u8> = out[1..n].iter().map(|&u| u as u8).collect();
        assert_eq!(text, PRODUCT_BRIDGE.as_bytes());
        for index in 1..string_id::COUNT as u8 {
            assert!(string_descriptor(index, &strings, &mut out).is_ok(), "string {index}");
        }
        assert_eq!(string_descriptor(string_id::COUNT as u8, &strings, &mut out), Err(StringError::OutOfRange));
        assert_eq!(string_descriptor(255, &strings, &mut out), Err(StringError::OutOfRange));
    }

    #[test]
    fn long_strings_are_cut_like_the_c() {
        let long = "x".repeat(100);
        let strings = Strings { product: &long, serial: "S", mac: "M" };
        let mut out = [0u16; STRING_UNITS_MAX];
        let n = string_descriptor(string_id::PRODUCT, &strings, &mut out).unwrap();
        assert_eq!(n, STRING_UNITS_MAX);
        assert_eq!(out[0], 0x0300 | (2 * 31 + 2));
    }
}

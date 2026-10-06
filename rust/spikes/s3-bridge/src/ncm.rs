//! CDC-NCM function with the C firmware's descriptor layout, derived from embassy-usb 0.6.0
//! `class/cdc_ncm/mod.rs`. Differences from upstream are marked `// DIFF:`.
//!
//! The datapath keeps upstream's endpoint model (one 64-byte packet per `read()`), but the receiver
//! owns an NTB reassembly buffer and hands out datagrams one at a time so that hold/resume can be
//! datagram-granular.

use core::sync::atomic::{AtomicU32, Ordering};

use embassy_usb::Builder;
use embassy_usb::driver::{Direction, Driver, Endpoint, EndpointAddress, EndpointError, EndpointIn};
use embassy_usb::types::{InterfaceNumber, StringIndex};
use tdongle_usb_out::{NtbCollector, Step};

pub const USB_CLASS_CDC: u8 = 0x02;
const USB_CLASS_CDC_DATA: u8 = 0x0a;
const CDC_SUBCLASS_NCM: u8 = 0x0d;
const CDC_PROTOCOL_NONE: u8 = 0x00;
const CDC_PROTOCOL_NTB: u8 = 0x01;
const CS_INTERFACE: u8 = 0x24;

/// OUT NTB size advertised to the host and the size of the reassembly buffer (C: 3 x 3200 in TinyUSB).
pub const NTB_OUT_MAX: usize = 3200;
/// IN NTB size advertised (C: 2 x 3200). We only ever send one datagram per NTB (max 1514 + 28).
pub const NTB_IN_MAX: usize = 3200;
const SIG_NTH: u32 = 0x484d_434e;
const SIG_NDP_NO_FCS: u32 = 0x304d_434e;
const SIG_NDP_WITH_FCS: u32 = 0x314d_434e;
const OUT_HEADER_LEN: usize = 28;

// Class requests (CDC NCM 1.0, table 6-2)
pub const REQ_SEND_ENCAPSULATED_COMMAND: u8 = 0x00;
pub const REQ_SET_ETHERNET_PACKET_FILTER: u8 = 0x43;
pub const REQ_GET_NTB_PARAMETERS: u8 = 0x80;
pub const REQ_GET_NTB_FORMAT: u8 = 0x83;
pub const REQ_SET_NTB_FORMAT: u8 = 0x84;
pub const REQ_GET_NTB_INPUT_SIZE: u8 = 0x85;
pub const REQ_SET_NTB_INPUT_SIZE: u8 = 0x86;

/// Stats updated by the control handler (readable from `status`).
pub static NTB_IN_SIZE_SET: AtomicU32 = AtomicU32::new(NTB_IN_MAX as u32);
pub static PKT_FILTER: AtomicU32 = AtomicU32::new(0);
pub static RX_BAD_NTB: AtomicU32 = AtomicU32::new(0);
pub static RX_BAD_DGRAM: AtomicU32 = AtomicU32::new(0);
pub static RX_NTBS: AtomicU32 = AtomicU32::new(0);
pub static RX_NTB_BYTES: AtomicU32 = AtomicU32::new(0);
pub static RX_NTB_MAX: AtomicU32 = AtomicU32::new(0);
pub static TX_NTBS: AtomicU32 = AtomicU32::new(0);

/// Interface numbers and strings of the NCM function, needed by the control handler.
pub struct NcmIds {
    pub comm_if: InterfaceNumber,
    pub data_if: InterfaceNumber,
    pub iface_string: StringIndex,
    pub mac_string: StringIndex,
}

pub fn ntb_parameters(buf: &mut [u8]) -> &[u8] {
    // NTB Parameter Structure, 28 bytes (CDC NCM 1.0 table 6-3)
    let mut p = [0u8; 28];
    p[0..2].copy_from_slice(&28u16.to_le_bytes()); // wLength
    p[2..4].copy_from_slice(&1u16.to_le_bytes()); // bmNtbFormatsSupported: NTB-16 only
    p[4..8].copy_from_slice(&(NTB_IN_MAX as u32).to_le_bytes()); // dwNtbInMaxSize
    p[8..10].copy_from_slice(&4u16.to_le_bytes()); // wNdpInDivisor
    p[10..12].copy_from_slice(&0u16.to_le_bytes()); // wNdpInPayloadRemainder
    p[12..14].copy_from_slice(&4u16.to_le_bytes()); // wNdpInAlignment
    p[14..16].copy_from_slice(&0u16.to_le_bytes()); // reserved
    p[16..20].copy_from_slice(&(NTB_OUT_MAX as u32).to_le_bytes()); // dwNtbOutMaxSize
    p[20..22].copy_from_slice(&4u16.to_le_bytes()); // wNdpOutDivisor
    p[22..24].copy_from_slice(&0u16.to_le_bytes()); // wNdpOutPayloadRemainder
    p[24..26].copy_from_slice(&4u16.to_le_bytes()); // wNdpOutAlignment
    p[26..28].copy_from_slice(&0u16.to_le_bytes()); // wNtbOutMaxDatagrams: 0 = no limit (upstream: 1)
    buf[..28].copy_from_slice(&p);
    &buf[..28]
}

pub struct Ncm<'d, D: Driver<'d>> {
    comm_ep: D::EndpointIn,
    read_ep: D::EndpointOut,
    write_ep: D::EndpointIn,
    comm_if: InterfaceNumber,
}

/// Build the NCM function. `mac_string`/`iface_string` indices are returned for the control handler.
pub fn build<'d, D: Driver<'d>>(builder: &mut Builder<'d, D>, mps: u16) -> (NcmIds, Ncm<'d, D>) {
    let mut func = builder.function(USB_CLASS_CDC, CDC_SUBCLASS_NCM, CDC_PROTOCOL_NONE);

    // Control interface. DIFF: interface string "USB network" (C: idx 5), interrupt EP 0x83 mps 64 interval 50.
    let mut iface = func.interface();
    let iface_string = iface.string();
    let mac_string = iface.string();
    let comm_if = iface.interface_number();
    let mut alt = iface.alt_setting(USB_CLASS_CDC, CDC_SUBCLASS_NCM, CDC_PROTOCOL_NONE, Some(iface_string));
    alt.descriptor(CS_INTERFACE, &[0x00, 0x10, 0x01]); // Header, bcdCDC 1.10
    alt.descriptor(CS_INTERFACE, &[0x06, comm_if.into(), u8::from(comm_if) + 1]); // Union
    alt.descriptor(
        CS_INTERFACE,
        &[0x0f, mac_string.into(), 0, 0, 0, 0, 0xea, 0x05, 0, 0, 0], // Ethernet Networking, wMaxSegmentSize 1514
    );
    // DIFF: bmNetworkCapabilities 0x21 (C) instead of 0
    alt.descriptor(CS_INTERFACE, &[0x1a, 0x00, 0x01, 0x21]);
    let comm_ep = alt.endpoint_interrupt_in(Some(EndpointAddress::from_parts(3, Direction::In)), 64, 50);

    // Data interface: alt 0 no endpoints, alt 1 IN 0x84 then OUT 0x04 (C order and addresses).
    let mut iface = func.interface();
    let data_if = iface.interface_number();
    let _alt0 = iface.alt_setting(USB_CLASS_CDC_DATA, 0x00, CDC_PROTOCOL_NTB, None);
    let mut alt1 = iface.alt_setting(USB_CLASS_CDC_DATA, 0x00, CDC_PROTOCOL_NTB, None);
    let write_ep = alt1.endpoint_bulk_in(Some(EndpointAddress::from_parts(4, Direction::In)), mps);
    let read_ep = alt1.endpoint_bulk_out(Some(EndpointAddress::from_parts(4, Direction::Out)), mps);
    drop(func);

    (
        NcmIds { comm_if, data_if, iface_string, mac_string },
        Ncm { comm_ep, read_ep, write_ep, comm_if },
    )
}

impl<'d, D: Driver<'d>> Ncm<'d, D> {
    pub fn split(self, ntb: &'d mut [u8; NTB_OUT_MAX]) -> (Sender<'d, D>, Receiver<'d, D>) {
        (
            Sender { write_ep: self.write_ep, seq: 0, buf: [0; OUT_HEADER_LEN + MAX_DATAGRAM] },
            Receiver {
                comm_if: self.comm_if,
                comm_ep: self.comm_ep,
                read_ep: self.read_ep,
                ntb,
                ntb_len: 0,
                ndp: 0,
                entry: 0,
            },
        )
    }
}

pub struct Sender<'d, D: Driver<'d>> {
    write_ep: D::EndpointIn,
    seq: u16,
    buf: [u8; OUT_HEADER_LEN + MAX_DATAGRAM],
}

const MAX_DATAGRAM: usize = 1514;

impl<'d, D: Driver<'d>> Sender<'d, D> {
    /// Same NTB-16 framing as upstream: 12 B NTH + 16 B NDP (one datagram), data at offset 28. Upstream builds only
    /// the first 64-byte packet in a stack buffer; here the whole NTB is assembled in `buf` (1.5 KB) and handed to
    /// `EndpointIn::write_transfer`, the driver-level hook that a multi-packet-capable driver can override.
    /// Awaits until the IN endpoint FIFO has room for every 64 B packet, i.e. until the host polls IN.
    pub async fn write_packet(&mut self, data: &[u8]) -> Result<(), EndpointError> {
        if data.len() > MAX_DATAGRAM {
            return Err(EndpointError::BufferOverflow);
        }
        self.body_mut()[..data.len()].copy_from_slice(data);
        self.send_prepared(data.len()).await
    }

    /// The datagram area of the NTB under construction (S3: the Wi-Fi->host ring copies straight into it, no staging copy).
    pub fn body_mut(&mut self) -> &mut [u8; MAX_DATAGRAM] {
        (&mut self.buf[OUT_HEADER_LEN..OUT_HEADER_LEN + MAX_DATAGRAM]).try_into().unwrap()
    }

    /// Write the NTH/NDP for a datagram of `len` bytes already placed with [`body_mut`](Self::body_mut) and send the NTB.
    pub async fn send_prepared(&mut self, len: usize) -> Result<(), EndpointError> {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let total = len + OUT_HEADER_LEN;
        let h = &mut self.buf;
        h[0..4].copy_from_slice(&SIG_NTH.to_le_bytes());
        h[4..6].copy_from_slice(&12u16.to_le_bytes());
        h[6..8].copy_from_slice(&seq.to_le_bytes());
        h[8..10].copy_from_slice(&(total as u16).to_le_bytes());
        h[10..12].copy_from_slice(&12u16.to_le_bytes());
        h[12..16].copy_from_slice(&SIG_NDP_NO_FCS.to_le_bytes());
        h[16..18].copy_from_slice(&16u16.to_le_bytes());
        h[18..20].copy_from_slice(&0u16.to_le_bytes()); // next NDP
        h[20..22].copy_from_slice(&(OUT_HEADER_LEN as u16).to_le_bytes());
        h[22..24].copy_from_slice(&(len as u16).to_le_bytes());
        h[24..28].copy_from_slice(&[0; 4]); // terminator entry
        TX_NTBS.fetch_add(1, Ordering::Relaxed);
        // needs_zlp = true: a ZLP is added when the NTB length is a multiple of the max packet size.
        self.write_ep.write_transfer(&self.buf[..total], true).await
    }
}

/// What the class needs from an OUT endpoint that takes whole transfers (`embassy-usb-synopsys-otg` with the multi-packet patch): one completed hardware transfer and
/// whether it ended on a short packet.
#[allow(async_fn_in_trait)]
pub trait ReadTransfer {
    /// See `embassy_usb_synopsys_otg::Endpoint::read_chunk`.
    async fn read_chunk(&mut self, buf: &mut [u8]) -> Result<(usize, bool), EndpointError>;
}

impl<'d> ReadTransfer for embassy_usb_synopsys_otg::Endpoint<'d, embassy_usb_synopsys_otg::Out> {
    async fn read_chunk(&mut self, buf: &mut [u8]) -> Result<(usize, bool), EndpointError> {
        embassy_usb_synopsys_otg::Endpoint::read_chunk(self, buf).await
    }
}

pub struct Receiver<'d, D: Driver<'d>> {
    comm_if: InterfaceNumber,
    comm_ep: D::EndpointIn,
    read_ep: D::EndpointOut,
    ntb: &'d mut [u8; NTB_OUT_MAX],
    ntb_len: usize,
    /// Offset of the current NDP, and index of the next entry within it (0 = none pending).
    ndp: usize,
    entry: usize,
}

impl<'d, D: Driver<'d>> Receiver<'d, D> {
    /// Read one whole NTB from the OUT endpoint into the reassembly buffer, one hardware transfer (up to the whole NTB buffer, many packets) per `read_chunk`,
    /// until a chunk ends on a short packet or ZLP (`NtbCollector`, host-tested). Returns once the NTB is complete and validated. Does NOT hand out datagrams.
    pub async fn read_ntb(&mut self) -> Result<(), EndpointError>
    where
        D::EndpointOut: ReadTransfer,
    {
        let mps = self.read_ep.info().max_packet_size as usize;
        let mut collector = NtbCollector::new(mps, NTB_OUT_MAX);
        loop {
            self.ndp = 0;
            let len = loop {
                let room = collector.room();
                match self.read_ep.read_chunk(&mut self.ntb[room]).await {
                    Ok((n, short)) => {
                        if let Step::Complete(len) = collector.chunk(n, short) {
                            break len;
                        }
                    }
                    Err(EndpointError::BufferOverflow) => {
                        // NTB larger than we advertised: the endpoint dropped it.
                        let _ = collector.overflow();
                        RX_BAD_NTB.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => return Err(e),
                }
            };
            self.ntb_len = len;
            RX_NTBS.fetch_add(1, Ordering::Relaxed);
            RX_NTB_BYTES.fetch_add(len as u32, Ordering::Relaxed);
            RX_NTB_MAX.fetch_max(len as u32, Ordering::Relaxed);
            if self.begin_ntb() {
                return Ok(());
            }
            RX_BAD_NTB.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn begin_ntb(&mut self) -> bool {
        let ntb = &self.ntb[..self.ntb_len];
        if ntb.len() < 12 || u32::from_le_bytes(ntb[0..4].try_into().unwrap()) != SIG_NTH {
            return false;
        }
        let ndp = u16::from_le_bytes(ntb[10..12].try_into().unwrap()) as usize;
        if ndp < 12 || ndp + 16 > ntb.len() {
            return false;
        }
        let sig = u32::from_le_bytes(ntb[ndp..ndp + 4].try_into().unwrap());
        if sig != SIG_NDP_NO_FCS && sig != SIG_NDP_WITH_FCS {
            return false;
        }
        self.ndp = ndp;
        self.entry = ndp + 8;
        true
    }

    /// The next datagram of the current NTB, WITHOUT consuming it. Call [`advance`](Self::advance) once the
    /// datagram has been accepted downstream. Not advancing is the datagram-granular hold: the datagram and the rest
    /// of its NTB stay in the reassembly buffer and, as long as `read_ntb` is not called, the OUT endpoint is not
    /// re-armed (the host is NAKed). Same contract as TinyUSB `tud_network_recv_cb` returning false / `recv_renew`.
    /// Upstream embassy only ever decodes the first datagram of an NTB and silently drops the rest.
    pub fn peek_datagram(&mut self) -> Option<&[u8]> {
        while self.ndp != 0 {
            let e = self.entry;
            if e + 4 > self.ntb_len {
                self.ndp = 0;
                return None;
            }
            let idx = u16::from_le_bytes(self.ntb[e..e + 2].try_into().unwrap()) as usize;
            let len = u16::from_le_bytes(self.ntb[e + 2..e + 4].try_into().unwrap()) as usize;
            if idx == 0 || len == 0 {
                self.ndp = 0; // terminator entry
                return None;
            }
            if idx + len > self.ntb_len || len > MAX_DATAGRAM {
                RX_BAD_DGRAM.fetch_add(1, Ordering::Relaxed);
                self.entry += 4;
                continue;
            }
            return Some(&self.ntb[idx..idx + len]);
        }
        None
    }

    /// Consume the datagram last returned by [`peek_datagram`](Self::peek_datagram).
    pub fn advance(&mut self) {
        self.entry += 4;
    }

    /// NETWORK_CONNECTION + CONNECTION_SPEED_CHANGE once the host selected alt 1 (the OUT endpoint is enabled).
    pub async fn wait_connection(&mut self) -> Result<(), EndpointError> {
        loop {
            self.read_ep.wait_enabled().await;
            self.comm_ep.wait_enabled().await;
            let ci: u8 = self.comm_if.into();
            // DIFF: wIndex is the communications interface (spec), upstream uses the data interface.
            let nc = [0xA1, 0x00, 0x01, 0x00, ci, 0x00, 0x00, 0x00];
            match self.comm_ep.write(&nc).await {
                Ok(()) => {}
                Err(EndpointError::Disabled) => continue,
                Err(e) => return Err(e),
            }
            // DIFF: also send CONNECTION_SPEED_CHANGE (12 Mbit/s), as TinyUSB does.
            let mut sc = [0u8; 16];
            sc[..8].copy_from_slice(&[0xA1, 0x2A, 0x00, 0x00, ci, 0x00, 0x08, 0x00]);
            sc[8..12].copy_from_slice(&12_000_000u32.to_le_bytes());
            sc[12..16].copy_from_slice(&12_000_000u32.to_le_bytes());
            match self.comm_ep.write(&sc).await {
                Ok(()) | Err(EndpointError::Disabled) => {}
                Err(e) => return Err(e),
            }
            return Ok(());
        }
    }
}

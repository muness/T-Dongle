//! CDC-ACM function with the C firmware's descriptor layout (embassy-usb 0.6.0 `class/cdc_acm.rs` is the
//! reference; DIFFs: interface string, call-management descriptor, bcdCDC 1.20, ACM caps 0x06, EP 0x81 mps 8
//! interval 1, bulk OUT 0x02 / IN 0x82).

use embassy_usb::Builder;
use embassy_usb::driver::{Direction, Driver, Endpoint, EndpointAddress, EndpointError, EndpointIn, EndpointOut};
use embassy_usb::types::{InterfaceNumber, StringIndex};

pub const USB_CLASS_CDC: u8 = 0x02;
const USB_CLASS_CDC_DATA: u8 = 0x0a;
const CDC_SUBCLASS_ACM: u8 = 0x02;
const CS_INTERFACE: u8 = 0x24;

pub struct AcmIds {
    pub comm_if: InterfaceNumber,
    pub iface_string: StringIndex,
}

pub struct Acm<'d, D: Driver<'d>> {
    _comm_ep: D::EndpointIn,
    read_ep: D::EndpointOut,
    write_ep: D::EndpointIn,
}

pub fn build<'d, D: Driver<'d>>(builder: &mut Builder<'d, D>, mps: u16) -> (AcmIds, Acm<'d, D>) {
    let mut func = builder.function(USB_CLASS_CDC, CDC_SUBCLASS_ACM, 0x00);

    let mut iface = func.interface();
    let iface_string = iface.string(); // index 4: "Management"
    let comm_if = iface.interface_number();
    let data_if = u8::from(comm_if) + 1;
    let mut alt = iface.alt_setting(USB_CLASS_CDC, CDC_SUBCLASS_ACM, 0x00, Some(iface_string));
    alt.descriptor(CS_INTERFACE, &[0x00, 0x20, 0x01]); // Header, bcdCDC 1.20
    alt.descriptor(CS_INTERFACE, &[0x01, 0x00, data_if]); // Call Management (C has it, upstream does not)
    alt.descriptor(CS_INTERFACE, &[0x02, 0x06]); // ACM, bmCapabilities 0x06
    alt.descriptor(CS_INTERFACE, &[0x06, comm_if.into(), data_if]); // Union
    let comm_ep = alt.endpoint_interrupt_in(Some(EndpointAddress::from_parts(1, Direction::In)), 8, 1);

    let mut iface = func.interface();
    let mut alt = iface.alt_setting(USB_CLASS_CDC_DATA, 0x00, 0x00, None);
    let read_ep = alt.endpoint_bulk_out(Some(EndpointAddress::from_parts(2, Direction::Out)), mps);
    let write_ep = alt.endpoint_bulk_in(Some(EndpointAddress::from_parts(2, Direction::In)), mps);
    drop(func);

    (AcmIds { comm_if, iface_string }, Acm { _comm_ep: comm_ep, read_ep, write_ep })
}

impl<'d, D: Driver<'d>> Acm<'d, D> {
    pub async fn wait_connection(&mut self) {
        self.read_ep.wait_enabled().await;
    }

    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, EndpointError> {
        self.read_ep.read(buf).await
    }

    /// Write bytes in 64 B packets; a ZLP terminates a transfer that ends on a packet boundary.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), EndpointError> {
        // `tdongle_serial::out::packets` (host-tested for every length): 64-byte packets, the last one shorter, and the zero-length packet that ends a transfer that is a multiple of 64.
        for packet in tdongle_serial::out::packets(data, 64) {
            self.write_ep.write(packet).await?;
        }
        Ok(())
    }
}

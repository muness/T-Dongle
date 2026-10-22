//! C5 downstream selection is independent of the tailnet registry and identity keys.
//! Version 1 uses one atomic NVS byte: 0 = USB, 1 = wireless. Unknown values fail closed.
use crate::{Error, Flash, Nvs};
/// Separate namespace; never changes membership or identity records.
pub const NAMESPACE: &str = "c5_transport";
/// Downstream transport; both choices run the same routed tailnet engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Android USB Serial/JTAG VPN transport.
    Usb,
    /// Protected client-facing AP.
    Wireless,
}
impl Transport {
    /// Parse an exact owner command, rejecting whitespace and additional commands.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "usb" => Some(Self::Usb),
            "wireless" => Some(Self::Wireless),
            _ => None,
        }
    }
}
/// Read version 1. Missing means USB; corrupt or unknown values are errors.
/// # Errors
/// Storage errors or an unknown schema byte.
pub fn load<F: Flash>(nvs: &mut Nvs<F>) -> Result<Transport, Error<F::Error>> {
    match nvs.get_u8(NAMESPACE, "mode")? {
        None | Some(0) => Ok(Transport::Usb),
        Some(1) => Ok(Transport::Wireless),
        _ => Err(Error::Corrupt),
    }
}
/// Atomically replace only the transport byte.
/// # Errors
/// Propagates storage write errors; the caller must remount after failure.
pub fn save<F: Flash>(nvs: &mut Nvs<F>, mode: Transport) -> Result<(), Error<F::Error>> {
    nvs.set_u8(
        NAMESPACE,
        "mode",
        match mode {
            Transport::Usb => 0,
            Transport::Wireless => 1,
        },
    )
}

//! What the mux needs to know about the station's IPv4 configuration, which the stack (embassy-net, DHCP) owns.

/// The station's IPv4 configuration as the stack learned it. Addresses are numeric (`192.168.1.50` is `0xC0A8_0132`), as in `tdongle-tailnet-usbnet`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Cfg {
    /// The station's address.
    pub addr: u32,
    /// The default gateway (the next hop of everything off-link), if the lease has one.
    pub gateway: Option<u32>,
    /// Prefix length (24 for a /24); values above 32 are treated as 32.
    pub prefix: u8,
}

impl Ipv4Cfg {
    /// The netmask of [`Ipv4Cfg::prefix`].
    pub const fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else if self.prefix >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - self.prefix as u32)
        }
    }
    /// True when `ip` is on the station's subnet.
    pub const fn on_link(&self, ip: u32) -> bool {
        ip & self.mask() == self.addr & self.mask()
    }
}

/// A source of the stack's IPv4 configuration. The runtime pushes it into the mux with [`crate::InfoHandle::refresh`] whenever the stack's
/// configuration changes (DHCP bound, renewed with a new address, deconfigured).
pub trait StackInfo {
    /// The current configuration, `None` while unconfigured.
    fn ipv4(&self) -> Option<Ipv4Cfg>;
}

#[cfg(feature = "embassy-net")]
impl From<embassy_net::StaticConfigV4> for Ipv4Cfg {
    fn from(c: embassy_net::StaticConfigV4) -> Self {
        Ipv4Cfg { addr: u32::from(c.address.address()), gateway: c.gateway.map(u32::from), prefix: c.address.prefix_len() }
    }
}

#[cfg(feature = "embassy-net")]
impl StackInfo for embassy_net::Stack<'_> {
    fn ipv4(&self) -> Option<Ipv4Cfg> {
        self.config_v4().map(Ipv4Cfg::from)
    }
}

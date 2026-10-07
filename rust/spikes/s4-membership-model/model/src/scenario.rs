//! One whole membership, built in the order a join happens. Used by the host harness; the firmware runs the same component
//! `setup` functions from separate embassy tasks.
use crate::meter::Meter;
use crate::{coord, disco, tls, wg};

pub struct Membership {
    pub coord: coord::Coord,
    pub derp: tls::Derp,
    pub wg: wg::Wg,
    pub disco: disco::Disco,
    pub ok: bool,
}

#[derive(Clone, Copy)]
pub struct Cfg {
    pub coord: coord::CoordCfg,
    pub tls_read: usize,
    pub tls_write: usize,
    pub resident_peers: usize,
    pub inline_queues: bool,
    pub tcp: disco::NetCfg,
}
impl Cfg {
    /// The design we would build: streaming coord window, 16,640/4,096 TLS record buffers, 2 guaranteed WG slots, pointer queues.
    pub const DEFAULT: Cfg = Cfg { coord: coord::CoordCfg::STREAMING, tls_read: tls::READ_REC, tls_write: tls::WRITE_REC, resident_peers: 2, inline_queues: false, tcp: disco::NetCfg::C_WINDOW };
}

pub async fn bring_up(m: &impl Meter, c: &Cfg) -> Membership {
    let (coord, ok1) = coord::setup(m, &c.coord, 8);
    let mut derp = tls::setup(m, c.tls_read, c.tls_write).await;
    let ok2 = tls::app_data(m, &mut derp).await;
    let (wg, ok3) = wg::setup(m, c.resident_peers);
    let (disco, ok4) = disco::setup(m, c.inline_queues, c.resident_peers, &c.tcp);
    Membership { coord, derp, wg, disco, ok: ok1 && ok2 && ok3 && ok4 }
}

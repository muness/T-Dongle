//! Why the S3 spike's bridge wedged within a second on the board, as a model: esp-radio 1.0.0-beta.1 gates BOTH directions on one TX credit counter that only the
//! driver's tx-done callback gives back, and that nothing resets. The model follows esp-radio's source (`WIFI_TX_INFLIGHT`, `can_send`, `rx_token`, `tx_token`,
//! `WifiTxToken::consume_token`, `esp_wifi_send_data`); the second half shows the C firmware's budget (`WifiPins`: tx-done releases, a link change flushes, a lease
//! heals a lost completion) keeps TX alive through the same events, and that RX needs no credit at all because it is a callback.

use tdongle_wifi_budget::{GW_WTX_LEASE_MS, RawLock, WifiPins};

/// esp-radio's interface as a state machine: `inflight` counts frames handed to the driver and not completed.
struct CoupledInterface {
    inflight: usize,
    limit: usize,
    connected: bool,
    rx_queue: usize,
    /// frames the driver holds, each owed one tx-done
    driver_queue: usize,
}

impl CoupledInterface {
    fn new(limit: usize) -> Self {
        Self { inflight: 0, limit, connected: true, rx_queue: 0, driver_queue: 0 }
    }
    fn can_send(&self) -> bool {
        self.inflight < self.limit
    }
    /// `rx_token`: a frame is queued AND there is TX credit.
    fn receive(&mut self) -> bool {
        if self.rx_queue > 0 && self.can_send() {
            self.rx_queue -= 1;
            return true;
        }
        false
    }
    /// `tx_token` then `consume_token`.
    fn transmit(&mut self) -> bool {
        if !self.can_send() {
            return false;
        }
        self.inflight += 1; // increase_in_flight_counter
        if !self.connected {
            return true; // esp_wifi_send_data returns early: the credit is never given back
        }
        self.driver_queue += 1;
        true
    }
    /// The driver completes one frame: `esp_wifi_tx_done_cb` -> `decrement_inflight_counter`.
    fn tx_done(&mut self) {
        if self.driver_queue > 0 {
            self.driver_queue -= 1;
            self.inflight = self.inflight.saturating_sub(1);
        }
    }
    /// The link drops: the driver clears its queues without completing the frames in them.
    fn link_flap(&mut self) {
        self.driver_queue = 0;
    }
}

#[test]
fn one_link_flap_with_a_full_tx_queue_wedges_both_directions_for_good() {
    let mut i = CoupledInterface::new(6);
    // an upload saturating the radio keeps every credit in flight
    for _ in 0..6 {
        assert!(i.transmit());
    }
    assert!(!i.can_send());
    i.link_flap(); // the AP is marginal (-87 dBm): the driver drops its queue and completes nothing
    assert_eq!(i.driver_queue, 0);
    i.rx_queue = 100;
    assert!(!i.receive(), "RX is gated on TX credit: Wi-Fi to host stops (the board: bridge_to_host frames stuck at 176)");
    assert!(!i.transmit(), "and TX never gets a credit again (the board: tx_retries rising, wifi_room_no 788)");
    for _ in 0..1000 {
        i.tx_done(); // nothing is owed: every late completion finds an empty driver queue
    }
    assert!(!i.can_send(), "the credit is leaked for good: only a reboot clears it");
}

#[test]
fn smaller_leaks_add_up_across_flaps() {
    let mut i = CoupledInterface::new(6);
    for flap in 1..=3 {
        for _ in 0..2 {
            assert!(i.transmit());
        }
        i.link_flap();
        assert_eq!(i.inflight, 2 * flap);
    }
    assert!(!i.can_send(), "three flaps with two frames in flight each use all six credits");
}

#[test]
fn a_frame_sent_while_not_connected_leaks_its_credit() {
    let mut i = CoupledInterface::new(3);
    i.connected = false;
    for _ in 0..3 {
        assert!(i.transmit());
    }
    i.connected = true;
    assert!(!i.can_send(), "three frames dropped by `esp_wifi_send_data` while not Connected cost the whole queue");
}

struct Nop;
impl RawLock for Nop {
    fn lock(&self) {}
    fn unlock(&self) {}
}

#[test]
fn the_budget_survives_the_same_events() {
    let pins: WifiPins<Nop> = WifiPins::new(Nop);
    pins.set_tx_limit(6);
    let mut now = 1000u32;
    let free = 100_000usize;
    for _ in 0..4 {
        assert!(pins.admit(1500, free, now).admitted());
    }
    // the link flaps: the driver clears its queues; the bridge flushes the budget (`wifi_pins_link_changed`)
    assert_eq!(pins.flush(), 4);
    assert_eq!(pins.tx_outstanding(), 0);
    assert!(pins.room(now));
    for _ in 0..6 {
        assert!(pins.admit(1500, free, now).admitted());
    }
    assert!(!pins.admit(1500, free, now).admitted(), "the limit still holds");
    // a lost completion with no link event: the lease gives the credit back
    now += GW_WTX_LEASE_MS + 1;
    assert!(pins.room(now), "the worker's room check heals leaked charges");
    assert!(pins.admit(1500, free, now).admitted());
    // completions release in order and never go below zero
    for _ in 0..20 {
        pins.done();
    }
    assert_eq!(pins.tx_outstanding(), 0);
}

#[test]
fn rx_does_not_depend_on_tx_credit_in_the_callback_design() {
    // With `esp_wifi_internal_reg_rxcb` the driver calls us for every received frame; there is no `receive()` that could be refused. The only RX state the budget
    // keeps is the optional heap accounting, and it never reads the TX side.
    let pins: WifiPins<Nop> = WifiPins::new(Nop);
    pins.set_tx_limit(1);
    assert!(pins.admit(1500, 100_000, 0).admitted());
    assert!(!pins.admit(1500, 100_000, 0).admitted(), "TX is at its limit");
    assert!(pins.rx_admit(100_000), "and an RX frame is still admitted");
    pins.rx_release();
}

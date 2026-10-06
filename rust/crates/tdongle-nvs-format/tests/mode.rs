//! Ports of `components/tdongle_runtime/tests/test_mode_store.c` (the load rule) and the name helpers of `tdongle_mode.h`.
use tdongle_nvs_format::mode::{Mode, ModeError};

#[test]
fn load_rule() {
    // Upgrade from the original bridge firmware or a fresh install: no mode, no memberships -> bridge.
    assert_eq!(Mode::load(None, false), Ok(Mode::WifiBridge));
    // A tailnet install that predates the mode switch keeps running the gateway.
    assert_eq!(Mode::load(None, true), Ok(Mode::TailnetGateway));
    // A stored mode wins over the memberships heuristic.
    assert_eq!(Mode::load(Some(0), true), Ok(Mode::WifiBridge));
    assert_eq!(Mode::load(Some(1), false), Ok(Mode::TailnetGateway));
    assert_eq!(Mode::load(Some(1), true), Ok(Mode::TailnetGateway));
    assert_eq!(Mode::load(Some(0), false), Ok(Mode::WifiBridge));
    // Anything above 1 is an error, never a guess.
    for v in 2..=255u8 {
        assert_eq!(Mode::load(Some(v), false), Err(ModeError::InvalidStored(v)));
        assert_eq!(Mode::load(Some(v), true), Err(ModeError::InvalidStored(v)));
    }
}

#[test]
fn names_and_values() {
    assert_eq!(Mode::WifiBridge.name(), "wifi_bridge");
    assert_eq!(Mode::TailnetGateway.name(), "tailnet_gateway");
    assert_eq!(Mode::parse("wifi_bridge"), Some(Mode::WifiBridge));
    assert_eq!(Mode::parse("tailnet_gateway"), Some(Mode::TailnetGateway));
    for bad in ["", "Wifi_bridge", "wifi_bridge ", "tailnet", "wifi_bridge\0", "0", "1"] {
        assert_eq!(Mode::parse(bad), None, "{bad:?}");
    }
    assert_eq!((Mode::WifiBridge.to_u8(), Mode::TailnetGateway.to_u8()), (0, 1));
    assert_eq!(Mode::from_u8(0), Some(Mode::WifiBridge));
    assert_eq!(Mode::from_u8(1), Some(Mode::TailnetGateway));
    assert_eq!(Mode::from_u8(2), None);
    for m in [Mode::WifiBridge, Mode::TailnetGateway] {
        assert_eq!(Mode::parse(m.name()), Some(m));
        assert_eq!(Mode::from_u8(m.to_u8()), Some(m));
    }
}

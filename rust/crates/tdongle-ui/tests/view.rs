//! The poll's output through the LCD crate: what the panel is given.
use tdongle_lcd::{LAYOUT_ROWS, LAYOUT_STATUS};
use tdongle_traffic::Reading;
use tdongle_ui::settings::Settings;
use tdongle_ui::setup_boot::Session;
use tdongle_ui::ui::{Content, Inputs, Snapshot, Ui};

#[test]
fn menu_and_status_views() {
    let names = |_: u32| Some("Home");
    let snap = Snapshot { saved_wifi: true, wifi: true, usb: true, ssid: "Home", ..Snapshot::default() };
    let mk = |down: bool| Inputs {
        button_down: down,
        setup_active: false,
        setup_session: Session::inactive(),
        wifi_ready: true,
        saved_count: 1,
        display: Settings::default(),
        snapshot: Some(snap),
        traffic: Reading::default(),
        network_name: &names,
    };
    let mut ui = Ui::new(1000);
    let a = ui.tick(1000, &mk(false));
    let view = a.draw.unwrap().content.to_view("0.3.0");
    assert_eq!(view.layout, LAYOUT_STATUS);
    assert!(matches!(a.draw.unwrap().content, Content::Status(_)));
    // hold for 1.5 s opens the menu
    let mut t = 1020;
    let mut last = a;
    while t < 3000 {
        let a = ui.tick(t, &mk(t >= 1100));
        if a.draw.is_some() {
            last = a;
        }
        t += 20;
    }
    let d = last.draw.unwrap();
    let v = d.content.to_view("0.3.0");
    assert_eq!(v.layout, LAYOUT_ROWS);
    assert!(!v.attention);
    assert_eq!(v.row(0), b"SETUP MENU");
    assert_eq!(v.row(1), b"Enter setup AP");
    assert_eq!(v.row(3), b"Short: next  Hold: select");
}

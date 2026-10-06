//! Port of `tests/test_menu.c`, `tests/test_core.c` (buttons).
use tdongle_ui::button::{Button, ButtonEvent};
use tdongle_ui::menu::*;

const NAMES: [&str; 5] = ["", "Home", "Phone hotspot", "A network with a very long display name", "Car"];
fn name_of(slot: u32) -> &'static str {
    NAMES[slot as usize]
}
fn act(m: &mut Menu, c: &MenuContext, e: MenuEvent, now: u32) -> (bool, MenuAction) {
    m.handle(c, e, now)
}

#[test]
fn opening_and_stepping() {
    let mut m = Menu::new();
    let c = MenuContext { setup_active: false, saved_count: 3 };
    let (used, a) = act(&mut m, &c, MenuEvent::Short, 100);
    assert!(!used && !m.open && a == MenuAction::None); // short press, menu closed: the caller changes page
    let (used, a) = act(&mut m, &c, MenuEvent::Hold, 2000);
    assert!(used && m.open && m.item == 0 && a == MenuAction::None);
    assert_eq!(c.item_count(), 6); // setup, three networks, factory reset, exit
    for i in 1..=5 {
        let (used, _) = act(&mut m, &c, MenuEvent::Short, 2100 + i);
        assert!(used && m.item == i);
    }
    act(&mut m, &c, MenuEvent::Short, 3000);
    assert_eq!(m.item, 0); // wraps
}

#[test]
fn choosing_items() {
    let mut m = Menu::new();
    let mut c = MenuContext { setup_active: false, saved_count: 3 };
    act(&mut m, &c, MenuEvent::Hold, 0);
    let (_, a) = act(&mut m, &c, MenuEvent::Hold, 10);
    assert!(a == MenuAction::Setup && !m.open);
    c.setup_active = true;
    act(&mut m, &c, MenuEvent::Hold, 20);
    let (_, a) = act(&mut m, &c, MenuEvent::Hold, 30);
    assert!(a == MenuAction::CancelSetup && !m.open); // the same item cancels setup while it runs
    c.setup_active = false;
    for slot in 1..=3u32 {
        act(&mut m, &c, MenuEvent::Hold, 40);
        for _ in 0..slot {
            act(&mut m, &c, MenuEvent::Short, 41);
        }
        let (_, a) = act(&mut m, &c, MenuEvent::Hold, 50);
        assert!(a == MenuAction::Use(slot) && !m.open);
    }
    act(&mut m, &c, MenuEvent::Hold, 60);
    for _ in 0..5 {
        act(&mut m, &c, MenuEvent::Short, 61); // Exit menu
    }
    let (used, a) = act(&mut m, &c, MenuEvent::Hold, 70);
    assert!(a == MenuAction::None && !m.open && used);
}

#[test]
fn factory_reset_needs_a_second_hold() {
    let c = MenuContext { setup_active: false, saved_count: 1 };
    let mut m = Menu::new();
    act(&mut m, &c, MenuEvent::Hold, 0);
    act(&mut m, &c, MenuEvent::Short, 1);
    act(&mut m, &c, MenuEvent::Short, 2); // item 2 = Factory reset
    let (_, a) = act(&mut m, &c, MenuEvent::Hold, 1000);
    assert!(a == MenuAction::Reset && m.open && m.confirm && m.confirm_until_ms == 11000);
    let (_, a) = act(&mut m, &c, MenuEvent::Hold, 10999);
    assert!(a == MenuAction::ConfirmReset && !m.open && !m.confirm);
    // A short press cancels the confirmation and moves on.
    let mut m = Menu::new();
    act(&mut m, &c, MenuEvent::Hold, 0);
    act(&mut m, &c, MenuEvent::Short, 1);
    act(&mut m, &c, MenuEvent::Short, 2);
    act(&mut m, &c, MenuEvent::Hold, 3);
    let (_, a) = act(&mut m, &c, MenuEvent::Short, 4);
    assert!(a == MenuAction::None && !m.confirm && m.open && m.item == 3);
    // Ten seconds pass: the confirmation is gone and holding asks again instead of resetting.
    let mut m = Menu::new();
    act(&mut m, &c, MenuEvent::Hold, 0);
    act(&mut m, &c, MenuEvent::Short, 1);
    act(&mut m, &c, MenuEvent::Short, 2);
    act(&mut m, &c, MenuEvent::Hold, 100);
    m.tick(10099);
    assert!(m.confirm);
    m.tick(10100);
    assert!(!m.confirm && m.open && m.item == 2);
    let (_, a) = act(&mut m, &c, MenuEvent::Hold, 10200);
    assert!(a == MenuAction::Reset && m.confirm);
    // Expiry is noticed even without a tick, and across the 32 bit wrap.
    let mut m = Menu::new();
    act(&mut m, &c, MenuEvent::Hold, 0xffff_fff0);
    act(&mut m, &c, MenuEvent::Short, 0xffff_fff1);
    act(&mut m, &c, MenuEvent::Short, 0xffff_fff2);
    act(&mut m, &c, MenuEvent::Hold, 0xffff_fff3);
    let (_, a) = act(&mut m, &c, MenuEvent::Hold, 0xffff_fff3u32.wrapping_add(10001));
    assert!(a == MenuAction::Reset);
}

#[test]
fn the_list_changes_under_an_open_menu() {
    let mut m = Menu::new();
    let mut c = MenuContext { setup_active: false, saved_count: 4 };
    act(&mut m, &c, MenuEvent::Hold, 0);
    for _ in 0..4 {
        act(&mut m, &c, MenuEvent::Short, 1); // network 4
    }
    c.saved_count = 1; // deleted from the setup page meanwhile
    let (_, a) = act(&mut m, &c, MenuEvent::Hold, 2);
    assert_eq!(a, MenuAction::Setup); // never an action for a network that no longer exists: back to the first item
    c.saved_count = 0;
    let mut m = Menu::new();
    act(&mut m, &c, MenuEvent::Hold, 0);
    assert_eq!(c.item_count(), 3);
    act(&mut m, &c, MenuEvent::Short, 1);
    let (_, a) = act(&mut m, &c, MenuEvent::Hold, 2);
    assert_eq!(a, MenuAction::Reset); // with nothing saved the next item after setup is the reset
}

#[test]
fn text() {
    let mut m = Menu::new();
    let mut c = MenuContext { setup_active: false, saved_count: 3 };
    act(&mut m, &c, MenuEvent::Hold, 0);
    let rows = m.render(&c, name_of);
    assert!(rows[0].as_str() == "SETUP MENU" && rows[1].as_str() == "Enter setup AP" && rows[3].as_str() == "Short: next  Hold: select");
    assert!(rows[2].is_empty() && rows[4].is_empty());
    c.setup_active = true;
    assert_eq!(m.render(&c, name_of)[1].as_str(), "Cancel setup AP");
    c.setup_active = false;
    act(&mut m, &c, MenuEvent::Short, 1);
    assert_eq!(m.render(&c, name_of)[1].as_str(), "1 Home");
    act(&mut m, &c, MenuEvent::Short, 1);
    assert_eq!(m.render(&c, name_of)[1].as_str(), "2 Phone hotspot");
    act(&mut m, &c, MenuEvent::Short, 1);
    let r = m.render(&c, name_of);
    assert!(r[1].as_str().starts_with("3 A network with a very") && r[1].as_bytes().len() <= ROW_CHARS);
    assert_eq!(r[1].as_str(), "3 A network with a very ");
    act(&mut m, &c, MenuEvent::Short, 1);
    assert_eq!(m.render(&c, name_of)[1].as_str(), "Factory reset...");
    act(&mut m, &c, MenuEvent::Short, 1);
    assert_eq!(m.render(&c, name_of)[1].as_str(), "Exit menu");
    for _ in 0..5 {
        act(&mut m, &c, MenuEvent::Short, 1); // to Factory reset
    }
    act(&mut m, &c, MenuEvent::Hold, 5);
    let rows = m.render(&c, name_of);
    assert!(rows[0].as_str() == "CONFIRM FACTORY RESET" && rows[1].as_str() == "Release; hold again <10s" && rows[2].as_str() == "Short press cancels");
    for r in rows {
        assert!(r.as_bytes().len() <= ROW_CHARS);
    }
}

/// `tests/test_core.c`, `buttons`.
#[test]
fn button_debounce_hold_and_wake() {
    let mut b = Button::new();
    assert_eq!(b.update(true, false, 10), ButtonEvent::None);
    assert_eq!(b.update(false, false, 20), ButtonEvent::None);
    assert_eq!(b.update(true, false, 25), ButtonEvent::None);
    assert_eq!(b.update(true, false, 55), ButtonEvent::None);
    assert_eq!(b.update(false, false, 200), ButtonEvent::None);
    assert_eq!(b.update(false, false, 230), ButtonEvent::Short);
    assert_eq!(b.update(true, false, 1000), ButtonEvent::None);
    b.update(true, false, 1030);
    assert_eq!(b.update(true, false, 2530), ButtonEvent::Hold);
    assert_eq!(b.update(true, false, 5000), ButtonEvent::None);
    b.update(false, false, 5010);
    assert_eq!(b.update(false, false, 5040), ButtonEvent::None);
    b.update(true, true, 6000);
    assert_eq!(b.update(true, true, 6030), ButtonEvent::Wake);
    assert_eq!(b.update(true, false, 9000), ButtonEvent::None);
    b.update(false, false, 9010);
    assert_eq!(b.update(false, false, 9040), ButtonEvent::None);
}

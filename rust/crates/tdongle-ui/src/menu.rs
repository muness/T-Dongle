//! The button menu (v0.1.1 semantics, one button). Port of `main/menu.{h,c}` (test: `tests/test_menu.c`).
//!
//! * short press, menu closed: next screen page (the caller does that; the menu does not consume it);
//! * hold 1.5 s, menu closed: open the menu at its first item;
//! * short press, menu open: next item (wraps), and cancels a pending factory-reset confirmation;
//! * hold, menu open: run the item, then close the menu, except Factory reset, which asks for confirmation;
//! * hold again within [`CONFIRM_MS`]: confirm the factory reset (anything else, or the time running out, cancels it).
//!
//! Items in order: 0 Enter setup AP (Cancel setup AP while setup is running); 1..=N the saved networks; Factory reset; Exit menu.
//! The menu only decides: what an item does is a [`MenuAction`], which the UI turns into a serial command.

use crate::text::Text;
use core::fmt::Write;

/// How long a factory-reset confirmation stays open.
pub const CONFIRM_MS: u32 = 10_000;
/// Characters per menu row.
pub const ROW_CHARS: usize = 26;
/// Rows in the menu text (the first is the title).
pub const ROWS: usize = 5;

/// One row of menu text.
pub type Row = Text<ROW_CHARS>;

/// A button gesture as the menu sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuEvent {
    /// Short press.
    Short,
    /// Hold.
    Hold,
}

/// What an item does; the caller runs it through the serial command layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuAction {
    /// Nothing (including Exit menu).
    None,
    /// `setup`.
    Setup,
    /// `cancel`.
    CancelSetup,
    /// `use N` (1-based saved network).
    Use(u32),
    /// `reset` (step one of the factory reset).
    Reset,
    /// `confirm-reset`.
    ConfirmReset,
}

/// What the menu needs to know about the world.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MenuContext {
    /// A setup access point is running.
    pub setup_active: bool,
    /// Saved Wi-Fi networks, 0 to 8.
    pub saved_count: u8,
}

/// Menu state (`menu_state`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Menu {
    /// The menu is showing.
    pub open: bool,
    /// Selected item.
    pub item: u32,
    /// A factory-reset confirmation is pending.
    pub confirm: bool,
    /// When the confirmation lapses (32 bit ms clock).
    pub confirm_until_ms: u32,
}

impl MenuContext {
    /// Number of items: setup, the saved networks, factory reset, exit.
    pub fn item_count(&self) -> u32 {
        1 + self.saved_count as u32 + 2
    }
    fn reset_item(&self) -> u32 {
        1 + self.saved_count as u32
    }
}

impl Menu {
    /// Closed.
    pub const fn new() -> Self {
        Menu { open: false, item: 0, confirm: false, confirm_until_ms: 0 }
    }

    /// Feed a button event. Returns `(consumed, action)`: consumed is true when the menu was open or this event opened it, and false for a short press
    /// with the menu closed (the caller changes page).
    pub fn handle(&mut self, c: &MenuContext, event: MenuEvent, now_ms: u32) -> (bool, MenuAction) {
        let items = c.item_count();
        if self.open && self.item >= items {
            self.item = 0; // the list shrank while the menu was open
        }
        if self.confirm && (now_ms.wrapping_sub(self.confirm_until_ms) as i32) >= 0 {
            self.confirm = false;
        }
        if !self.open {
            if event != MenuEvent::Hold {
                return (false, MenuAction::None);
            }
            self.open = true;
            self.item = 0;
            self.confirm = false;
            return (true, MenuAction::None);
        }
        if event == MenuEvent::Short {
            self.item = (self.item + 1) % items;
            self.confirm = false;
            return (true, MenuAction::None);
        }
        let mut action = MenuAction::None;
        if self.confirm {
            action = MenuAction::ConfirmReset;
            self.confirm = false;
            self.open = false;
        } else if self.item == 0 {
            action = if c.setup_active { MenuAction::CancelSetup } else { MenuAction::Setup };
            self.open = false;
        } else if self.item <= c.saved_count as u32 {
            action = MenuAction::Use(self.item);
            self.open = false;
        } else if self.item == c.reset_item() {
            action = MenuAction::Reset;
            self.confirm = true;
            self.confirm_until_ms = now_ms.wrapping_add(CONFIRM_MS);
        } else {
            self.open = false; // Exit menu
        }
        (true, action)
    }

    /// Call regularly: a confirmation that was not given in time is cancelled (the menu stays open on Factory reset).
    pub fn tick(&mut self, now_ms: u32) {
        if self.confirm && (now_ms.wrapping_sub(self.confirm_until_ms) as i32) >= 0 {
            self.confirm = false;
        }
    }

    /// The text of the open menu: [`ROWS`] rows, the first is the title. `network_name(slot)` is the display name of saved network `slot` (1-based).
    pub fn render<'a>(&self, c: &MenuContext, network_name: impl Fn(u32) -> &'a str) -> [Row; ROWS] {
        let mut rows = [Row::new(); ROWS];
        if self.confirm {
            let _ = write!(rows[0], "CONFIRM FACTORY RESET");
            let _ = write!(rows[1], "Release; hold again <10s");
            let _ = write!(rows[2], "Short press cancels");
            return rows;
        }
        let _ = write!(rows[0], "SETUP MENU");
        let item = if self.item < c.item_count() { self.item } else { 0 };
        if item == 0 {
            let _ = write!(rows[1], "{}", if c.setup_active { "Cancel setup AP" } else { "Enter setup AP" });
        } else if item <= c.saved_count as u32 {
            let name = network_name(item).as_bytes();
            let _ = write!(rows[1], "{} ", item & 15);
            rows[1].push_bytes(&name[..name.len().min(22)]);
        } else if item == c.reset_item() {
            let _ = write!(rows[1], "Factory reset...");
        } else {
            let _ = write!(rows[1], "Exit menu");
        }
        let _ = write!(rows[3], "Short: next  Hold: select");
        rows
    }
}

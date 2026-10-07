//! The peer directory's flash: the `peerstore` partition (`0x420000`, 4 MB, the C's FAT volume; here raw) behind [`DirFlash`].
//!
//! Every operation goes to the ROM's SPI flash routines through `esp_storage::ll` (read, erase one sector, program), with absolute chip addresses: `esp-storage`'s own
//! `FlashStorage` refuses an offset beyond the capacity it detects, and on the board that check said `OutOfBounds` for an erase at `0x430000`. What the ROM thinks is
//! reported by `selftest flash` ([`selftest`]) next to the raw JEDEC id and the capacity `esp-storage` derived from it.
//! A sector erase masks interrupts for its ~45 ms, one call at a time (the directory erases in the background, a sector per call, with the executor running between).

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};
use esp_storage::ll;
use tdongle_tailnet_engine::flashdir::{DirFlash, SECTOR};

/// Start of the `peerstore` partition.
pub const PEERSTORE_OFFSET: u32 = 0x42_0000;
/// Size of the `peerstore` partition.
pub const PEERSTORE_SIZE: usize = 0x40_0000;

/// Flash operations that failed.
pub static ERRS: AtomicU32 = AtomicU32::new(0);
/// Flash operations that succeeded (erase and write).
pub static OKS: AtomicU32 = AtomicU32::new(0);
static LAST_OP: AtomicU32 = AtomicU32::new(0);
static LAST_RC: AtomicU32 = AtomicU32::new(0);
static LAST_ADDR: AtomicU32 = AtomicU32::new(0);
static UNLOCKED: AtomicU32 = AtomicU32::new(0);
/// Erase, write and unlock calls made (each masks interrupts while the ROM runs it): the supervisor's USB liveness check excuses a pending interrupt in a tick in which
/// this moved (`usb_watch::Sample::excused`).
pub static MASKED_OPS: AtomicU32 = AtomicU32::new(0);

fn note(op: u32, addr: u32, r: Result<(), i32>) -> bool {
    MASKED_OPS.fetch_add(1, Ordering::Relaxed);
    match r {
        Ok(()) => {
            OKS.fetch_add(1, Ordering::Relaxed);
            true
        }
        Err(rc) => {
            ERRS.fetch_add(1, Ordering::Relaxed);
            LAST_OP.store(op, Ordering::Relaxed);
            LAST_RC.store(rc as u32, Ordering::Relaxed);
            LAST_ADDR.store(addr, Ordering::Relaxed);
            false
        }
    }
}

/// `tn_dir` console line (flash side): operations done and the last failure, with the ROM's return code and the absolute address.
pub fn report(out: &mut impl Write) {
    let op = match LAST_OP.load(Ordering::Relaxed) {
        1 => "read",
        2 => "erase",
        3 => "write",
        4 => "unlock",
        _ => "-",
    };
    let _ = write!(
        out,
        "tn_dir_flash ok={} errs={} last_op={} rc={} addr=0x{:x} partition=0x{:x}+0x{:x}\r\n",
        OKS.load(Ordering::Relaxed),
        ERRS.load(Ordering::Relaxed),
        op,
        LAST_RC.load(Ordering::Relaxed) as i32,
        LAST_ADDR.load(Ordering::Relaxed),
        PEERSTORE_OFFSET,
        PEERSTORE_SIZE
    );
}

fn unlock() -> bool {
    if UNLOCKED.load(Ordering::Relaxed) != 0 {
        return true;
    }
    // SAFETY: the ROM's flash-unlock routine (clears the status register's protection bits), the call every esp-storage write makes first.
    let ok = note(4, 0, unsafe { ll::spiflash_unlock() });
    if ok {
        UNLOCKED.store(1, Ordering::Relaxed);
    }
    ok
}

/// A word-aligned scratch buffer for the ROM's routines (they need aligned pointers and lengths).
#[repr(align(4))]
struct Words([u8; 512]);

/// Read `buf.len()` bytes at absolute flash address `addr`.
fn read_abs(addr: u32, buf: &mut [u8]) -> bool {
    let mut at = addr;
    let mut done = 0;
    while done < buf.len() {
        let aligned = at & !3;
        let skip = (at - aligned) as usize;
        let take = (buf.len() - done).min(512 - skip);
        let words = (skip + take).div_ceil(4) * 4;
        let mut w = Words([0; 512]);
        // SAFETY: `w` is a word-aligned buffer of at least `words` bytes; the ROM fills `words` bytes from the aligned address.
        let r = unsafe { ll::spiflash_read(aligned, w.0.as_mut_ptr() as *mut u32, words as u32) };
        if !note(1, aligned, r) {
            return false;
        }
        buf[done..done + take].copy_from_slice(&w.0[skip..skip + take]);
        done += take;
        at += take as u32;
    }
    true
}

fn erase_abs(sector_addr: u32) -> bool {
    if !unlock() {
        return false;
    }
    // SAFETY: erases the 4 KB sector at `sector_addr`; the caller only passes sectors of the peer directory.
    note(2, sector_addr, unsafe { ll::spiflash_erase_sector(sector_addr / SECTOR as u32) })
}

fn write_abs(addr: u32, data: &[u8]) -> bool {
    if !unlock() || addr % 4 != 0 {
        return false;
    }
    let mut at = addr;
    for chunk in data.chunks(512) {
        let mut w = Words([0xFF; 512]);
        w.0[..chunk.len()].copy_from_slice(chunk);
        let words = chunk.len().div_ceil(4) * 4;
        // SAFETY: programs `words` bytes from the aligned buffer (the tail beyond `chunk` is 0xFF: programming ones changes nothing) at a word-aligned address.
        let r = unsafe { ll::spiflash_write(at, w.0.as_ptr() as *const u32, words as u32) };
        if !note(3, at, r) {
            return false;
        }
        at += chunk.len() as u32;
    }
    true
}

/// The directory's flash: a unit value, the chip is the ROM's.
#[derive(Clone, Copy, Debug, Default)]
pub struct EspDirFlash;

/// Whether `len` bytes at partition offset `offset` lie inside the `peerstore` partition. The ROM routines take absolute addresses and check nothing, so this is the
/// only bound between a directory offset and the rest of the chip (`FlashStorage` bounded by chip capacity, never by partition).
fn inside(offset: usize, len: usize) -> bool {
    len <= PEERSTORE_SIZE && offset <= PEERSTORE_SIZE - len
}

impl DirFlash for EspDirFlash {
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> bool {
        inside(offset, buf.len()) && read_abs(PEERSTORE_OFFSET + offset as u32, buf)
    }
    fn erase_sector(&mut self, sector: usize) -> bool {
        if !inside(sector.saturating_mul(SECTOR), SECTOR) {
            ERRS.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        crate::guard::op("dir_erase");
        let r = erase_abs(PEERSTORE_OFFSET + (sector * SECTOR) as u32);
        crate::guard::op("");
        r
    }
    fn write(&mut self, offset: usize, data: &[u8]) -> bool {
        inside(offset, data.len()) && write_abs(PEERSTORE_OFFSET + offset as u32, data)
    }
    fn size(&self) -> usize {
        PEERSTORE_SIZE
    }
}

/// The raw JEDEC id the way `esp-storage` reads it (manufacturer, type, capacity code in the low three bytes).
fn rdid() -> u32 {
    critical_section::with(|_| {
        let spi1 = esp_hal::peripherals::SPI1::regs();
        spi1.cmd().write(|w| w.flash_rdid().set_bit());
        while spi1.cmd().read().flash_rdid().bit_is_set() {}
        spi1.w(0).read().buf().bits() & 0x00FF_FFFF
    })
}

/// `selftest flash`: what the chip is, and whether erase, program and read work at the directory's addresses (above 4 MB). Uses the last sector of the partition,
/// which no directory layout reaches (a tailnet image's directory is under 2 MB), and refuses to write if the chip wraps at 4 MB (the sector beyond 4 MB would be the
/// app's). Returns the report text.
pub fn selftest(out: &mut impl Write) {
    let id = rdid();
    // what esp-storage believes: a second FlashStorage is only made to ask its capacity
    let cap = esp_storage::FlashStorage::new(unsafe { esp_hal::peripherals::FLASH::steal() }).capacity();
    let _ = write!(out, "selftest flash: jedec=0x{:06x} (manufacturer 0x{:02x} type 0x{:02x} capacity code 0x{:02x}) esp_storage_capacity={} B nvs_capacity={} B expected={} B\r\n", id, id & 0xFF, (id >> 8) & 0xFF, (id >> 16) & 0xFF, cap, crate::settings::NVS_CAPACITY.load(Ordering::Relaxed), crate::settings::EXPECTED_CAPACITY);
    let probe = PEERSTORE_OFFSET + (PEERSTORE_SIZE - SECTOR) as u32;
    // 1. does an address above 4 MB alias one below it? (the app starts at 0x20000)
    let mut hi = [0u8; 64];
    let mut lo = [0u8; 64];
    let a = read_abs(PEERSTORE_OFFSET, &mut hi);
    let b = read_abs(PEERSTORE_OFFSET - 0x40_0000, &mut lo);
    let _ = write!(out, "selftest flash: read 0x{:x} ok={} read 0x{:x} ok={}", PEERSTORE_OFFSET, a, PEERSTORE_OFFSET - 0x40_0000, b);
    if a && b && hi == lo && hi.iter().any(|&x| x != 0xFF) {
        let _ = write!(out, " ALIAS: the chip wraps at 4 MB, not writing\r\n");
        return;
    }
    let _ = write!(out, " no alias\r\n");
    // 2. erase, blank check, program, read back, erase
    let e1 = erase_abs(probe);
    let mut blank = [0u8; 256];
    let r1 = read_abs(probe, &mut blank);
    let _ = write!(out, "selftest flash: erase 0x{:x} ok={} blank={}\r\n", probe, e1, r1 && blank.iter().all(|&x| x == 0xFF));
    let mut pat = [0u8; 256];
    for (i, p) in pat.iter_mut().enumerate() {
        *p = (i as u8).wrapping_mul(7).wrapping_add(0x5A);
    }
    let w = write_abs(probe, &pat);
    let mut back = [0u8; 256];
    let r2 = read_abs(probe, &mut back);
    let _ = write!(out, "selftest flash: write ok={} read ok={} match={}\r\n", w, r2, back == pat);
    // an unaligned read in the middle (the directory reads records at any offset)
    let mut mid = [0u8; 7];
    let r3 = read_abs(probe + 13, &mut mid);
    let _ = write!(out, "selftest flash: unaligned read ok={} match={}\r\n", r3, mid == pat[13..20]);
    let e2 = erase_abs(probe);
    let r4 = read_abs(probe, &mut blank);
    let _ = write!(out, "selftest flash: erase again ok={} blank={}\r\n", e2, r4 && blank.iter().all(|&x| x == 0xFF));
    let pass = e1 && w && r2 && back == pat && r3 && mid == pat[13..20] && e2;
    // 3. NVS still answers (its own partition, esp-storage path): the first bytes of the nvs partition are a valid page header
    let mut nvs = [0u8; 4];
    let r5 = read_abs(0x9000, &mut nvs);
    let _ = write!(out, "selftest flash: nvs page header read ok={} first_bytes={:02x?}\r\n", r5, nvs);
    let _ = write!(out, "selftest flash: {}\r\n", if pass { "PASS" } else { "FAIL" });
    report(out);
}

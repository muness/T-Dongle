//! An in-memory NOR flash with power-loss injection (feature `sim`), for host tests, the fuzz target and the firmware's host builds.
//!
//! Every byte written and every erased sector costs "budget units" (1 per byte written, [`SimFlash::ERASE_UNITS`] per sector erase). When
//! the budget set with [`SimFlash::arm`] runs out in the middle of an operation the power is gone: the operation is applied only as far
//! as the budget reached (see [`Tear`]), it returns [`SimError::PowerLoss`], and so does everything after it. Take the bytes
//! ([`SimFlash::data`]) and build a fresh `SimFlash` from them to model the next power-up.

use std::vec;
use std::vec::Vec;

use crate::Flash;

/// How the operation that the power cut interrupts is left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tear {
    /// A write has programmed exactly the bytes the budget paid for; an erase has blanked exactly that many bytes from the start of the
    /// sector and left the rest as it was.
    Prefix,
    /// As [`Tear::Prefix`], but the byte the power went out in is half done (a random subset of the bits that were to be cleared are
    /// cleared), and an interrupted erase also leaves the rest of the sector with a few stray bits set (a sector in the middle of an erase
    /// is not "old bytes" any more). The number is the seed.
    Bits(u64),
}

/// A failed [`SimFlash`] operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimError {
    /// The power went out (during this operation, or earlier).
    PowerLoss,
    /// Access outside the partition.
    OutOfRange,
    /// A write that is not 4-byte aligned in offset and length (the alignment `esp-storage` needs).
    Misaligned,
}

/// The simulated flash. All fields that tests look at are public.
#[derive(Clone, Debug)]
pub struct SimFlash {
    /// The cells.
    pub data: Vec<u8>,
    /// Budget units spent so far (1 per byte written, [`SimFlash::ERASE_UNITS`] per sector erased).
    pub spent: u64,
    /// Number of sector erases issued.
    pub erases: u64,
    /// Erases per sector (wear).
    pub sector_erases: Vec<u32>,
    /// Number of write calls.
    pub write_calls: u64,
    /// Writes that tried to turn a 0 bit into a 1 (impossible on NOR; must stay 0).
    pub violations: u32,
    /// Writes that were not 4-byte aligned (must stay 0).
    pub misaligned: u32,
    fail_at: Option<u64>,
    tear: Tear,
    dead: bool,
    rng: u64,
}

impl SimFlash {
    /// Budget units one sector erase costs.
    pub const ERASE_UNITS: u64 = 4096;

    /// A blank flash of `size` bytes.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self::from_image(vec![0xff; size])
    }

    /// A flash holding `image` (a fresh power-up).
    #[must_use]
    pub fn from_image(image: Vec<u8>) -> Self {
        Self { sector_erases: vec![0; image.len() / 4096], data: image, spent: 0, erases: 0, write_calls: 0, violations: 0, misaligned: 0, fail_at: None, tear: Tear::Prefix, dead: false, rng: 0x9e37_79b9_7f4a_7c15 }
    }

    /// Cut the power after `budget` more units, leaving the interrupted operation as `tear` says.
    pub fn arm(&mut self, budget: u64, tear: Tear) {
        self.fail_at = Some(self.spent + budget);
        self.tear = tear;
        if let Tear::Bits(seed) = tear {
            self.rng = seed | 1;
        }
    }

    /// Stop cutting the power.
    pub fn disarm(&mut self) {
        self.fail_at = None;
    }

    /// Whether the power has gone out.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.dead
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    /// Units left before the cut, `None` when not armed.
    fn left(&self) -> Option<u64> {
        self.fail_at.map(|f| f.saturating_sub(self.spent))
    }
}

impl Flash for SimFlash {
    type Error = SimError;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), SimError> {
        if self.dead {
            return Err(SimError::PowerLoss);
        }
        let start = offset as usize;
        let src = self.data.get(start..start + buf.len()).ok_or(SimError::OutOfRange)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), SimError> {
        if self.dead {
            return Err(SimError::PowerLoss);
        }
        if offset % 4 != 0 || data.len() % 4 != 0 {
            self.misaligned += 1;
            return Err(SimError::Misaligned);
        }
        let start = offset as usize;
        if start + data.len() > self.data.len() {
            return Err(SimError::OutOfRange);
        }
        self.write_calls += 1;
        let paid = self.left().map_or(data.len() as u64, |l| l.min(data.len() as u64)) as usize;
        for (i, &b) in data.iter().enumerate().take(paid) {
            let old = self.data[start + i];
            if b & !old != 0 {
                self.violations += 1;
            }
            self.data[start + i] = old & b;
        }
        self.spent += paid as u64;
        if paid < data.len() {
            if let Tear::Bits(_) = self.tear {
                let old = self.data[start + paid];
                let clear = old & !data[paid];
                let r = self.rand() as u8;
                self.data[start + paid] = old & !(clear & r);
            }
            self.dead = true;
            return Err(SimError::PowerLoss);
        }
        Ok(())
    }

    fn erase_sector(&mut self, sector: u32) -> Result<(), SimError> {
        if self.dead {
            return Err(SimError::PowerLoss);
        }
        let start = sector as usize * 4096;
        if start + 4096 > self.data.len() {
            return Err(SimError::OutOfRange);
        }
        let paid = self.left().map_or(Self::ERASE_UNITS, |l| l.min(Self::ERASE_UNITS)) as usize;
        self.erases += 1;
        self.sector_erases[sector as usize] += 1;
        for b in &mut self.data[start..start + paid] {
            *b = 0xff;
        }
        self.spent += paid as u64;
        if paid < 4096 {
            if let Tear::Bits(_) = self.tear {
                for i in start + paid..start + 4096 {
                    let r = self.rand() & self.rand() & self.rand();
                    self.data[i] |= r as u8;
                }
            }
            self.dead = true;
            return Err(SimError::PowerLoss);
        }
        Ok(())
    }
}

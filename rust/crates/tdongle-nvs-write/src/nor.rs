//! [`Flash`] over an `embedded-storage` NOR flash (feature `embedded-storage`): what the firmware passes `esp_storage::FlashStorage`
//! through.

use embedded_storage::nor_flash::NorFlash;

use crate::Flash;

/// A partition of a NOR flash: offsets given to the engine are relative to `base`.
///
/// `base` must be a multiple of the flash's erase size (0x9000 for the `nvs` partition of this firmware). The inner flash's write size must
/// divide 4 (4 on the ESP32-S3) and its erase size must be 4096; reads of any offset and length are served from reads of the inner
/// flash's own read size (4 or 1 on the ESP32-S3 depending on the `esp-storage` version).
#[derive(Debug)]
pub struct NorPartition<T> {
    /// The flash.
    pub inner: T,
    /// Offset of the partition in the flash.
    pub base: u32,
}

impl<T: NorFlash> NorPartition<T> {
    /// A partition at `base` (the offset of the `nvs` entry of the partition table).
    pub fn new(inner: T, base: u32) -> Self {
        const { assert!(T::ERASE_SIZE == 4096 && 4 % T::WRITE_SIZE == 0 && T::READ_SIZE <= 64) };
        Self { inner, base }
    }
}

impl<T: NorFlash> Flash for NorPartition<T> {
    type Error = T::Error;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), T::Error> {
        let ra = T::READ_SIZE as u32;
        if ra == 1 {
            return self.inner.read(self.base + offset, buf);
        }
        // Round the request out to the read size and go through a small stack buffer.
        let mut at = offset;
        let end = offset + buf.len() as u32;
        let mut tmp = [0u8; 64];
        while at < end {
            let start = at - at % ra;
            let n = (((end - start).div_ceil(ra)) * ra).min(64);
            self.inner.read(self.base + start, &mut tmp[..n as usize])?;
            let from = at - start;
            let take = (n - from).min(end - at);
            buf[(at - offset) as usize..(at - offset + take) as usize].copy_from_slice(&tmp[from as usize..(from + take) as usize]);
            at += take;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), T::Error> {
        self.inner.write(self.base + offset, data)
    }

    fn erase_sector(&mut self, sector: u32) -> Result<(), T::Error> {
        let from = self.base + sector * 4096;
        self.inner.erase(from, from + 4096)
    }
}

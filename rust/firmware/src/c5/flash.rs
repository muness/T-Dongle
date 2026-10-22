//! Always stage NVS bytes in internal stack memory before ROM flash routines disable cache.
use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
pub struct Flash(pub esp_storage::FlashStorage<'static>);
impl ErrorType for Flash {
    type Error = esp_storage::FlashStorageError;
}
#[repr(align(4))]
struct Staging([u8; 512]);
impl ReadNorFlash for Flash {
    const READ_SIZE: usize = 1;
    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let mut staging = Staging([0; 512]);
        for (i, chunk) in bytes.chunks_mut(512).enumerate() {
            self.0.read(offset + (i * 512) as u32, &mut staging.0[..chunk.len()])?;
            chunk.copy_from_slice(&staging.0[..chunk.len()]);
        }
        Ok(())
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}
impl NorFlash for Flash {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = 4096;
    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        let mut staging = Staging([0; 512]);
        for (i, chunk) in bytes.chunks(512).enumerate() {
            staging.0[..chunk.len()].copy_from_slice(chunk);
            self.0.write(offset + (i * 512) as u32, &staging.0[..chunk.len()])?;
        }
        Ok(())
    }
    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.0.erase(from, to)
    }
}

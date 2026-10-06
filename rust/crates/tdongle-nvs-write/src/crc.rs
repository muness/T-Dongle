//! The CRC-32 ESP-IDF's NVS uses (`esp_rom_crc32_le`, reflected polynomial `0xEDB88320`), nibble-wise: 64 bytes of flash, not 1 KiB.

const NIBBLE: [u32; 16] = {
    let mut t = [0u32; 16];
    let mut i = 0;
    while i < 16 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 4 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// Incremental CRC-32; start a new sum from `0xffff_ffff` (that is `esp_rom_crc32_le(0xffffffff, ..)`, what NVS calls).
#[must_use]
pub fn crc32(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c ^= u32::from(b);
        c = (c >> 4) ^ NIBBLE[(c & 0xf) as usize];
        c = (c >> 4) ^ NIBBLE[(c & 0xf) as usize];
    }
    !c
}

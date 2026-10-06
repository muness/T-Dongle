//! C-string helpers for the fixed `char[N]` fields of the NVS blobs.
//!
//! The C firmware keeps SSIDs, passwords and names in fixed arrays that are NUL-terminated *inside* the array; bytes after the
//! terminator are unspecified and never read. These helpers give the same view of a byte slice, so a Rust slice and the C array it
//! mirrors compare equal exactly when `strcmp` would say so.

/// Length of the C string at the start of `bytes`: the index of the first NUL, or `bytes.len()` when there is none (the end of the
/// slice then acts as the terminator; for a full `char[N]` array without a NUL use [`is_terminated`] to tell the cases apart).
#[must_use]
pub fn c_len(bytes: &[u8]) -> usize {
    bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())
}

/// The C string at the start of `bytes`, without its terminator (C `strlen` / `strcmp` view).
#[must_use]
pub fn c_str(bytes: &[u8]) -> &[u8] {
    &bytes[..c_len(bytes)]
}

/// Whether `bytes` holds a NUL (C: `memchr(s, 0, cap) != NULL`), i.e. the string inside the array is terminated.
#[must_use]
pub fn is_terminated(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

/// Whether `byte` is printable ASCII, 32 to 126 inclusive (the C `(unsigned char)c >= 32 && <= 126` test).
#[must_use]
pub const fn is_printable(byte: u8) -> bool {
    byte >= 32 && byte <= 126
}

/// Copy the C string of `src` into the start of `dst`, at most `dst.len()` bytes, leaving the rest of `dst` untouched
/// (C `strncpy` into a zeroed array of `dst.len() + 1` bytes: pass the array without its final guaranteed NUL).
pub(crate) fn copy_str(dst: &mut [u8], src: &[u8]) {
    let s = c_str(src);
    let n = s.len().min(dst.len());
    dst[..n].copy_from_slice(&s[..n]);
}

/// Little-endian `u32` at `offset`.
pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_follow_strcmp() {
        assert_eq!(c_len(b"abc\0def"), 3);
        assert_eq!(c_len(b"abc"), 3);
        assert_eq!(c_str(b"\0abc"), b"");
        assert!(is_terminated(b"ab\0"));
        assert!(!is_terminated(b"abc"));
        assert!(is_printable(b' ') && is_printable(b'~') && !is_printable(31) && !is_printable(127) && !is_printable(0xc3));
    }

    #[test]
    fn copy_truncates_and_leaves_the_rest() {
        let mut dst = [9u8; 4];
        copy_str(&mut dst, b"ab\0zz");
        assert_eq!(dst, [b'a', b'b', 9, 9]);
        copy_str(&mut dst, b"abcdefg");
        assert_eq!(&dst, b"abcd");
    }
}

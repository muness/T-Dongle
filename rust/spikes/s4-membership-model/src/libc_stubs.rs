//! libc symbols mbedtls-rs-sys leaves to the platform that neither tinyrlibc nor the ROM linker scripts supply here.
//! They are only reached from debug/info printing (x509_crt_info, dn_gets, ssl debug), never on the handshake path.
//! Declared with fixed arity: on Xtensa a variadic call passes its first arguments exactly like a fixed-arity one.
use core::ffi::{c_char, c_int};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn snprintf(buf: *mut c_char, n: usize, _fmt: *const c_char) -> c_int {
    if n > 0 && !buf.is_null() {
        unsafe { *buf = 0 };
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vsnprintf(buf: *mut c_char, n: usize, _fmt: *const c_char, _ap: *mut u8) -> c_int {
    if n > 0 && !buf.is_null() {
        unsafe { *buf = 0 };
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn printf(_fmt: *const c_char) -> c_int {
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn puts(_s: *const c_char) -> c_int {
    0
}

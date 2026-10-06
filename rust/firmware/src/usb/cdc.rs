//! The CDC-ACM serial console's byte stream (TinyUSB `tud_cdc_*`), the port of `tinyusb_cdc_acm.c`'s read/write/flush and the two callbacks
//! `console.c` registers (receive and line state).

use esp_idf_svc::sys;

/// The CDC instance (the descriptor has exactly one).
const ITF: u8 = 0;

/// `tud_cdc_rx_cb`: bytes arrived. Reads them 64 at a time and hands them to the console's line reader (TinyUSB task context).
#[unsafe(no_mangle)]
pub extern "C" fn tud_cdc_rx_cb(itf: u8) {
    let mut buffer = [0u8; 64];
    loop {
        // SAFETY: `buffer` is 64 writable bytes; TinyUSB writes at most `bufsize`.
        let n = unsafe { sys::tud_cdc_n_read(itf, buffer.as_mut_ptr().cast(), buffer.len() as u32) } as usize;
        if n == 0 {
            break;
        }
        crate::console::feed(&buffer[..n]);
    }
}

/// `tud_cdc_line_state_cb`: the host opened or closed the port (DTR). The greeting is sent when DTR rises.
#[unsafe(no_mangle)]
pub extern "C" fn tud_cdc_line_state_cb(_itf: u8, dtr: bool, _rts: bool) {
    crate::console::on_line_state(dtr);
}

/// `tinyusb_cdcacm_write_queue`: queue as much of `data` as the transmit FIFO has room for; returns how many bytes were taken.
pub fn write_queue(data: &[u8]) -> usize {
    // SAFETY: `data` is readable for its length; TinyUSB copies it into its FIFO before returning.
    unsafe {
        let available = sys::tud_cdc_n_write_available(ITF) as usize;
        sys::tud_cdc_n_write(ITF, data.as_ptr().cast(), data.len().min(available) as u32) as usize
    }
}

/// `tinyusb_cdcacm_write_flush(itf, timeout_ticks)`: push the FIFO to the endpoint and wait up to `timeout_ms` for it to empty. Returns whether
/// everything was flushed.
pub fn write_flush(timeout_ms: u32) -> bool {
    let start = std::time::Instant::now();
    loop {
        // SAFETY: plain TinyUSB calls; flush is safe from any task (it takes the class driver's mutex).
        let (flushed, empty) = unsafe {
            sys::tud_cdc_n_write_flush(ITF);
            (true, sys::tud_cdc_n_write_available(ITF) as usize == crate::usb::cdc::TX_FIFO_BYTES)
        };
        if flushed && empty {
            return true;
        }
        if start.elapsed().as_millis() as u32 > timeout_ms {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// `CFG_TUD_CDC_TX_BUFSIZE`: the transmit FIFO (512 bytes; see `tusb_config.h`).
pub const TX_FIFO_BYTES: usize = 512;

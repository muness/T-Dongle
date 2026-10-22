//! C5 LEDC channel 0, timer 0. PAC register names follow ESP32-C5 LEDC/PCR; no S3 register assumptions.
use esp_hal::gpio::{AnyPin, Level, Output, OutputConfig, OutputSignal};
pub struct Backlight {
    _pin: Output<'static>,
}
impl Backlight {
    pub fn new(pin: AnyPin<'static>) -> Self {
        let pin = Output::new(pin, Level::High, OutputConfig::default());
        // SAFETY: this module is the sole LEDC owner, created once by the display task.
        let pcr = unsafe { &*esp32c5::PCR::PTR };
        pcr.ledc_conf().modify(|_, w| w.ledc_clk_en().set_bit().ledc_rst_en().clear_bit());
        pcr.ledc_sclk_conf().modify(|_, w| unsafe { w.ledc_sclk_en().set_bit().ledc_sclk_sel().bits(2) });
        let ledc = unsafe { &*esp32c5::LEDC::PTR };
        ledc.conf().modify(|_, w| w.clk_en().set_bit());
        // 80 MHz / (312.5 * 256) = 1 kHz; divider has eight fractional bits.
        ledc.timer(0).conf().write(|w| unsafe { w.duty_res().bits(8).clk_div().bits(80_000).tick_sel().set_bit().para_up().set_bit() });
        ledc.ch(0).conf0().write(|w| unsafe { w.timer_sel().bits(0).sig_out_en().set_bit().para_up().set_bit() });
        OutputSignal::LEDC_LS_SIG0.connect_to(&pin);
        let result = Self { _pin: pin };
        result.apply(0);
        result
    }
    pub fn apply(&self, percent: u32) {
        let duty = tdongle_lcd::backlight_duty(percent);
        // SAFETY: sole owner; duty uses the hardware's four fractional bits.
        let ledc = unsafe { &*esp32c5::LEDC::PTR };
        ledc.ch(0).duty().write(|w| unsafe { w.duty().bits(duty << 4) });
        ledc.ch(0).conf1().write(|w| w.duty_start().set_bit());
        ledc.ch(0).conf0().modify(|_, w| w.para_up().set_bit());
    }
}

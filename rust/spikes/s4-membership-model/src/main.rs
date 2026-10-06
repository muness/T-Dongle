#![no_std]
#![no_main]
esp_bootloader_esp_idf::esp_app_desc!();
use embassy_executor::Spawner;
use esp_backtrace as _;
use esp_hal::timer::timg::TimerGroup;

#[esp_rtos::main]
async fn main(_s: Spawner) {
    let p = esp_hal::init(esp_hal::Config::default());
    let t = TimerGroup::new(p.TIMG0);
    esp_rtos::start(t.timer0, p.FROM_CPU_INTR0);
    esp_println::println!("hi");
}

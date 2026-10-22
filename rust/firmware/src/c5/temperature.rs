//! C5 temperature is unavailable until the C5 sensor path is qualified; never read S3 registers.
pub fn snapshot() -> tdongle_serial::status::Temperature {
    Default::default()
}
#[embassy_executor::task]
pub async fn task() {}

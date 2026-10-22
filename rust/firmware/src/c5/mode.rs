//! Persisted downstream transport, orthogonal to the shared tailnet registry and identities.
use alloc::{format, string::String};
use core::sync::atomic::{AtomicBool, Ordering};
use esp_radio::wifi::{AuthenticationMethodConfig, Config, WifiController, ap::AccessPointConfig, sta::StationConfig};
pub static AP_READY: AtomicBool = AtomicBool::new(false);
static WIRELESS: AtomicBool = AtomicBool::new(false);
static PASSWORD: critical_section::Mutex<core::cell::Cell<[u8; 16]>> = critical_section::Mutex::new(core::cell::Cell::new([0; 16]));
const NS: &str = "c5_transport";
pub fn wireless() -> bool {
    WIRELESS.load(Ordering::Relaxed)
}
pub fn password() -> [u8; 16] {
    critical_section::with(|cs| PASSWORD.borrow(cs).get())
}
pub async fn load() {
    let mut g = crate::settings::STORE.lock().await;
    let Some(s) = g.as_mut() else { return };
    let selected = match tdongle_nvs_write::transport::load(s.nvs()) {
        Ok(tdongle_nvs_write::transport::Transport::Usb) => false,
        Ok(tdongle_nvs_write::transport::Transport::Wireless) => true,
        Err(_) => {
            crate::init_note("invalid C5 transport setting");
            return;
        }
    };
    let mut secret = [0; 17];
    match s.nvs().get_str(NS, "ap_pass", &mut secret) {
        Ok(Some(16)) if secret[..16].iter().all(u8::is_ascii_alphanumeric) => {}
        Ok(None) => {
            let mut random = [0; 16];
            esp_hal::rng::Rng::new().read(&mut random);
            for (out, byte) in secret.iter_mut().zip(random) {
                *out = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[usize::from(byte) % 31];
            }
            if s.nvs().set_str(NS, "ap_pass", core::str::from_utf8(&secret[..16]).unwrap()).is_err() {
                crate::init_note("AP secret save failed");
                return;
            }
        }
        _ => {
            crate::init_note("AP secret unreadable");
            return;
        }
    }
    critical_section::with(|cs| PASSWORD.borrow(cs).set(secret[..16].try_into().unwrap()));
    WIRELESS.store(selected, Ordering::Relaxed);
}
pub fn name() -> String {
    let m = esp_hal::efuse::base_mac_address();
    let b = m.as_bytes();
    format!("TDongle-C5-{:02X}{:02X}{:02X}", b[3], b[4], b[5])
}
pub fn configure(controller: &mut WifiController<'static>, station: StationConfig) -> bool {
    if wireless() {
        let name = name();
        let pass = password();
        if pass[0] == 0 {
            return false;
        }
        let ap = AccessPointConfig::default()
            .with_ssid(name.as_str().try_into().unwrap())
            .with_max_connections(4)
            .with_authentication(AuthenticationMethodConfig::Wpa2Personal(core::str::from_utf8(&pass).unwrap().try_into().unwrap()));
        let ready = controller.set_config(&Config::AccessPointStation(station, ap)).is_ok();
        AP_READY.store(ready, Ordering::Relaxed);
        crate::ALT.store(u8::from(ready), Ordering::Relaxed);
        crate::CONFIGURED.store(ready, Ordering::Relaxed);
        ready
    } else {
        controller.set_config(&Config::Station(station)).is_ok()
    }
}
pub async fn command(line: &str) -> Option<String> {
    if line == "gateway" {
        return Some(format!(
            "gateway mode={} memberships={} psram={} internal_free={}\r\n",
            if wireless() { "wireless" } else { "usb" },
            crate::tailnet::MEMBERS,
            super::memory::external_bytes(),
            esp_alloc::HEAP.free_caps(esp_alloc::MemoryCapability::Internal.into())
        ));
    }
    if line == "gateway ap" {
        // Deliberate local-owner request, never included in routine status or diagnostic exports.
        let pass = password();
        return Some(format!("gateway_ap ssid={} password={} url=http://192.168.77.1\r\n", name(), core::str::from_utf8(&pass).unwrap_or("unavailable")));
    }
    let value = line.strip_prefix("gateway ")?;
    let Some(choice) = tdongle_nvs_write::transport::Transport::parse(value) else {
        return Some(String::from("ERR use gateway usb|wireless|ap\r\n"));
    };
    let mut g = crate::settings::STORE.lock().await;
    let ok = match g.as_mut() {
        Some(s) => match tdongle_nvs_write::transport::save(s.nvs(), choice) {
            Ok(()) => true,
            Err(_) => {
                let _ = s.remount();
                false
            }
        },
        None => false,
    };
    // Reboot is separate so a complete acknowledgement precedes it; registry and identity namespaces are untouched.
    Some(String::from(if ok { "OK gateway saved; reboot to apply\r\n" } else { "ERR gateway not saved\r\n" }))
}

/// Temporary setup uses a fresh secret per boot after the radio entropy source is running.
pub fn fresh_setup_secret() {
    let mut random = [0; 16];
    esp_hal::rng::Rng::new().read(&mut random);
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    for byte in &mut random {
        *byte = ALPHABET[usize::from(*byte) % ALPHABET.len()];
    }
    critical_section::with(|cs| PASSWORD.borrow(cs).set(random));
}

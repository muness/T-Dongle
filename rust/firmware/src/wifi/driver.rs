//! The Wi-Fi driver calls (`esp_wifi_*`), each wrapped once with its reason to be sound.

use esp_idf_svc::sys::{self, EspError};
use tdongle_nvs_format::wifi_profiles::SavedProfile;
use tdongle_serial::wifi_link::{self, Info};

use super::Wifi;

/// `esp_wifi_init(WIFI_INIT_CONFIG_DEFAULT())`: the macro's fields, from the project's sdkconfig (the same values esp-idf-svc's `WifiDriver::new`
/// builds, which cannot be used here because it initialises NVS the way the C firmware refuses to, see `sys::nvs`). `nvs_enable` is on, as in C.
pub fn init() -> Result<(), EspError> {
    // SAFETY: `g_wifi_osi_funcs` and `g_wifi_default_wpa_crypto_funcs` are the driver's own tables, valid for the life of the program; the
    // configuration is copied by `esp_wifi_init`. All other fields are constants generated from the sdkconfig.
    unsafe {
        let config = sys::wifi_init_config_t {
            osi_funcs: core::ptr::addr_of_mut!(sys::g_wifi_osi_funcs),
            wpa_crypto_funcs: sys::g_wifi_default_wpa_crypto_funcs,
            static_rx_buf_num: sys::CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM as _,
            dynamic_rx_buf_num: sys::CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM as _,
            tx_buf_type: sys::CONFIG_ESP32_WIFI_TX_BUFFER_TYPE as _,
            static_tx_buf_num: sys::WIFI_STATIC_TX_BUFFER_NUM as _,
            dynamic_tx_buf_num: sys::WIFI_DYNAMIC_TX_BUFFER_NUM as _,
            rx_mgmt_buf_type: sys::CONFIG_ESP_WIFI_DYNAMIC_RX_MGMT_BUF as _,
            rx_mgmt_buf_num: sys::WIFI_RX_MGMT_BUF_NUM_DEF as _,
            cache_tx_buf_num: sys::WIFI_CACHE_TX_BUFFER_NUM as _,
            csi_enable: sys::WIFI_CSI_ENABLED as _,
            ampdu_rx_enable: sys::WIFI_AMPDU_RX_ENABLED as _,
            ampdu_tx_enable: sys::WIFI_AMPDU_TX_ENABLED as _,
            amsdu_tx_enable: sys::WIFI_AMSDU_TX_ENABLED as _,
            nvs_enable: sys::WIFI_NVS_ENABLED as _,
            nano_enable: sys::WIFI_NANO_FORMAT_ENABLED as _,
            rx_ba_win: sys::WIFI_DEFAULT_RX_BA_WIN as _,
            wifi_task_core_id: sys::WIFI_TASK_CORE_ID as _,
            beacon_max_len: sys::WIFI_SOFTAP_BEACON_MAX_LEN as _,
            mgmt_sbuf_num: sys::WIFI_MGMT_SBUF_NUM as _,
            feature_caps: sys::WIFI_FEATURE_CAPS as _,
            sta_disconnected_pm: sys::WIFI_STA_DISCONNECTED_PM_ENABLED != 0,
            espnow_max_encrypt_num: sys::CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM as i32,
            magic: sys::WIFI_INIT_CONFIG_MAGIC as _,
            tx_hetb_queue_num: sys::WIFI_TX_HETB_QUEUE_NUM as _,
            dump_hesigb_enable: sys::WIFI_DUMP_HESIGB_ENABLED != 0,
            ..Default::default()
        };
        sys::esp!(sys::esp_wifi_init(&config))
    }
}

/// `esp_wifi_set_storage(RAM)` (`tn_settings` owns the credentials), station mode, an empty station configuration, start.
pub fn start_radio() -> Result<(), EspError> {
    // SAFETY: ordinary driver calls after `esp_wifi_init`; the configuration is a zeroed union copied by the driver.
    unsafe {
        sys::esp!(sys::esp_wifi_set_storage(sys::wifi_storage_t_WIFI_STORAGE_RAM))?;
        sys::esp!(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        let mut empty: sys::wifi_config_t = core::mem::zeroed();
        sys::esp!(sys::esp_wifi_set_config(sys::wifi_interface_t_WIFI_IF_STA, &mut empty))?;
        sys::esp!(sys::esp_wifi_start())
    }
}

/// No Wi-Fi modem sleep. The IDF default (`WIFI_PS_MIN_MODEM`) wakes for every DTIM beacon and parks frames at the access point between them:
/// measured on the board 2026-10-05 it added about 80 ms to the median round trip (ping p50 126 ms against 48 ms with power save off) and changed
/// throughput not at all. The original bridge does the same. It costs radio idle current, not CPU frequency. Failure is not fatal: the link
/// works, only slower to answer.
pub fn power_save_off() {
    // SAFETY: a plain driver call after start.
    let code = unsafe { sys::esp_wifi_set_ps(sys::wifi_ps_type_t_WIFI_PS_NONE) };
    if code != sys::ESP_OK {
        log::warn!("esp_wifi_set_ps(NONE) failed ({code:#x}): modem sleep stays on");
    }
}

/// The v0.1.1 radio profile of the transparent bridge: 20 MHz channels (more sensitive than 40 MHz in a crowded 2.4 GHz band, and the USB 1.1 link
/// cannot use the extra rate anyway) and the highest transmit power the driver allows (it clamps to the regulatory limit). Not fatal.
pub fn radio_profile() {
    // SAFETY: plain driver calls after start.
    let (bandwidth, power) =
        unsafe { (sys::esp_wifi_set_bandwidth(sys::wifi_interface_t_WIFI_IF_STA, sys::wifi_bandwidth_t_WIFI_BW_HT20), sys::esp_wifi_set_max_tx_power(84)) };
    if bandwidth != sys::ESP_OK || power != sys::ESP_OK {
        log::warn!("bridge radio profile not fully applied (bandwidth {bandwidth:#x}, power {power:#x})");
    }
}

/// The station configuration for one saved network, the same for every way of joining it (the worker, `use N`):
///  - scan every channel and join the strongest AP of the SSID, not the first one the fast scan finds (v0.1.1);
///  - the bridge's v0.1.1 profile: WPA3 (SAE both methods) and protected management frames on, and an AP weaker than WPA2 refused for a network
///    with a password;
///  - 802.11k neighbour reports and 802.11v BSS transition requests, so the network can steer the dongle to a better AP: the roaming assist of
///    v0.1.1. Self-initiated roaming stays off (an RSSI-only rule ping-ponged between two similar access points).
pub fn fill_station(profile: &SavedProfile) -> sys::wifi_config_t {
    // SAFETY: an all-zero `wifi_config_t` is the "nothing set" value the C code starts from (`memset(c, 0, sizeof(*c))`).
    let mut config: sys::wifi_config_t = unsafe { core::mem::zeroed() };
    // SAFETY: the `sta` member of the union is the one the driver reads for the STA interface; all its fields are plain data.
    let sta = unsafe { &mut config.sta };
    let ssid = profile.ssid_bytes();
    let password = profile.password_bytes();
    sta.ssid[..ssid.len().min(32)].copy_from_slice(&ssid[..ssid.len().min(32)]);
    sta.password[..password.len().min(63)].copy_from_slice(&password[..password.len().min(63)]);
    sta.scan_method = sys::wifi_scan_method_t_WIFI_ALL_CHANNEL_SCAN;
    sta.sort_method = sys::wifi_sort_method_t_WIFI_CONNECT_AP_BY_SIGNAL;
    sta.sae_pwe_h2e = sys::wifi_sae_pwe_method_t_WPA3_SAE_PWE_BOTH;
    sta.pmf_cfg.capable = true;
    sta.threshold.authmode = if password.is_empty() { sys::wifi_auth_mode_t_WIFI_AUTH_OPEN } else { sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK };
    sta.set_rm_enabled(1);
    sta.set_btm_enabled(1);
    config
}

/// The association the driver reports now, or `None` when not associated (`esp_wifi_sta_get_ap_info`).
pub fn ap_info() -> Option<sys::wifi_ap_record_t> {
    // SAFETY: `record` is a valid out pointer for a `wifi_ap_record_t`.
    unsafe {
        let mut record: sys::wifi_ap_record_t = core::mem::zeroed();
        (sys::esp_wifi_sta_get_ap_info(&mut record) == sys::ESP_OK).then_some(record)
    }
}

/// `esp_wifi_sta_get_ap_info` is not enough for the link line; the rest is read here (`wifi_link_read`): every call is a documented public API,
/// and a failing one leaves its field unknown.
pub fn read_link_info(wifi: &Wifi) -> Info {
    let mut info = Info { phy: wifi_link::PHY_UNKNOWN, ps: wifi_link::PS_UNKNOWN, secondary: wifi_link::SECOND_UNKNOWN, ..Info::default() };
    // Selection state is plain ints written under the selection lock; a torn read can only show the previous value.
    if let Some(slot) = wifi.current() {
        info.selected_slot = (slot + 1) as u8;
    }
    {
        let selection = wifi.lock();
        info.pinned = selection.pin.slot.is_some();
        info.pin_failed_slot = selection.pin.failed_slot.map_or(0, |slot| (slot + 1) as u8);
    }
    let Some(ap) = ap_info() else { return info }; // not associated
    info.connected = true;
    info.rssi = ap.rssi;
    info.rssi_valid = true;
    // SAFETY: each call writes only its own out parameter.
    unsafe {
        let mut average = 0i32;
        if sys::esp_wifi_sta_get_rssi(&mut average) == sys::ESP_OK && (-128..=127).contains(&average) {
            info.rssi = average as i8;
        }
        info.channel = ap.primary;
        info.secondary = ap.second as u8;
        info.ap_bw_mhz = match ap.bandwidth {
            sys::wifi_bandwidth_t_WIFI_BW_HT40 => 40,
            sys::wifi_bandwidth_t_WIFI_BW_HT20 => 20,
            _ => 0,
        };
        info.ap_modes = (if ap.phy_11b() != 0 { wifi_link::AP_B } else { 0 })
            | (if ap.phy_11g() != 0 { wifi_link::AP_G } else { 0 })
            | (if ap.phy_11n() != 0 { wifi_link::AP_N } else { 0 })
            | (if ap.phy_11ax() != 0 { wifi_link::AP_AX } else { 0 });
        let mut phy: sys::wifi_phy_mode_t = 0;
        if sys::esp_wifi_sta_get_negotiated_phymode(&mut phy) == sys::ESP_OK && (phy as u32) < wifi_link::PHY_COUNT {
            info.phy = phy as u8;
        }
        let mut bandwidth: sys::wifi_bandwidth_t = 0;
        if sys::esp_wifi_get_bandwidth(sys::wifi_interface_t_WIFI_IF_STA, &mut bandwidth) == sys::ESP_OK {
            info.bw_cfg_mhz = match bandwidth {
                sys::wifi_bandwidth_t_WIFI_BW_HT40 => 40,
                sys::wifi_bandwidth_t_WIFI_BW_HT20 => 20,
                _ => 0,
            };
        }
        let mut ps: sys::wifi_ps_type_t = 0;
        if sys::esp_wifi_get_ps(&mut ps) == sys::ESP_OK && ps <= sys::wifi_ps_type_t_WIFI_PS_MAX_MODEM {
            info.ps = ps as u8;
        }
        let mut power = 0i8;
        if sys::esp_wifi_get_max_tx_power(&mut power) == sys::ESP_OK {
            info.tx_power_valid = true;
            info.tx_power_qdbm = power;
        }
    }
    info
}

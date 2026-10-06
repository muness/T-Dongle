// Extra headers whose declarations the Rust glue uses; esp-idf-sys generates the bindings (BUILD-OPTIONS.md, extra_components).
//
// TinyUSB: the device stack, the CDC and NCM class driver APIs, and usbd_defer_func (device/usbd_pvt.h), which esp_tinyusb's C glue uses to run
// work in the TinyUSB task.
#include "tusb.h"
#include "device/usbd_pvt.h"
// The USB PHY (esp_tinyusb installs it before the stack starts).
#include "device/dcd.h"
#include "esp_private/usb_phy.h"
// The raw 802.11 station data path of the transparent bridge: esp_wifi_internal_tx / _reg_rxcb / _free_rx_buffer, esp_wifi_set_tx_done_cb.
#include "esp_private/wifi.h"
// The CPU clock the status line reports (`pm` command).
#include "esp_private/esp_clk.h"
// Power management and the temperature sensor.
#include "esp_app_desc.h"
#include "esp_pm.h"
#include "driver/temperature_sensor.h"

#pragma once
#include "esp_err.h"
#include <stdint.h>
esp_err_t tinyusb_net_tx_ring_send(const void *, uint16_t);
void tinyusb_net_tx_ring_flush(void);
#define TUSB_NET_RX_HOLD ((esp_err_t)0x10C)

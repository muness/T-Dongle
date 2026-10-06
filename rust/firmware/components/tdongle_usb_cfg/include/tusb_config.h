/* TinyUSB configuration of the T-Dongle Rust firmware.
 *
 * The same TinyUSB (espressif/tinyusb 0.21.0~2) and the same settings the C firmware gets from esp_tinyusb's tusb_config.h and the project's
 * sdkconfig (CDC x1 plus NCM, three 3,200 byte OUT NTBs, two 3,200 byte IN NTBs, DMA mode), written down here as constants instead of
 * Kconfig indirection: the Rust firmware has no esp_tinyusb. */
#pragma once

#include "tusb_option.h"
#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CFG_TUD_ENABLED                 1
#define CFG_TUD_MAX_SPEED               OPT_MODE_FULL_SPEED     /* the S3's OTG controller is full speed only */
#define CFG_TUSB_OS                     OPT_OS_FREERTOS

/* DWC2 in DMA mode, as the C image runs it (CONFIG_TINYUSB_MODE_DMA=y): buffers handed to the controller are cache-line aligned and in DRAM. */
#define CFG_TUD_DWC2_SLAVE_ENABLE       1
#define CFG_TUD_DWC2_DMA_ENABLE         1
#if CONFIG_CACHE_L1_CACHE_LINE_SIZE
#   define CFG_TUD_MEM_DCACHE_ENABLE    1
#   define CFG_TUD_MEM_DCACHE_LINE_SIZE CONFIG_CACHE_L1_CACHE_LINE_SIZE
#   define CFG_TUSB_MEM_SECTION         __attribute__((aligned(CONFIG_CACHE_L1_CACHE_LINE_SIZE))) DRAM_ATTR
#else
#   define CFG_TUD_MEM_CACHE_ENABLE     0
#   define CFG_TUSB_MEM_SECTION         TU_ATTR_ALIGNED(4) DRAM_ATTR
#endif
#ifndef CFG_TUSB_MEM_ALIGN
#   define CFG_TUSB_MEM_ALIGN           TU_ATTR_ALIGNED(4)
#endif

#define CFG_TUD_ENDPOINT0_SIZE          64

#define CFG_TUSB_DEBUG                  1                       /* errors only (CONFIG_TINYUSB_DEBUG_LEVEL=1 in the C image) */
#define CFG_TUSB_DEBUG_PRINTF           esp_rom_printf          /* TinyUSB prints from ISR context: only the ROM printf is safe there */

/* Class drivers: one CDC-ACM (the serial console), one CDC-NCM (the network). Nothing else is linked in. */
#define CFG_TUD_CDC                     1
#define CFG_TUD_CDC_RX_BUFSIZE          512
#define CFG_TUD_CDC_TX_BUFSIZE          512
#define CFG_TUD_CDC_EP_BUFSIZE          512
#define CFG_TUD_MSC                     0
#define CFG_TUD_HID                     0
#define CFG_TUD_MIDI                    0
#define CFG_TUD_VENDOR                  0
#define CFG_TUD_ECM_RNDIS               0
#define CFG_TUD_NCM                     1
#define CFG_TUD_DFU                     0
#define CFG_TUD_DFU_RUNTIME             0
#define CFG_TUD_BTH                     0
#define CFG_TUD_BTH_ISO_ALT_COUNT       0

/* NCM transfer blocks (ADR 0023: three OUT NTBs are the host -> device backpressure window; two 3,200 byte IN NTBs, ADR 0015). */
#define CFG_TUD_NCM_OUT_NTB_N           3
#define CFG_TUD_NCM_IN_NTB_N            2
#define CFG_TUD_NCM_OUT_NTB_MAX_SIZE    3200
#define CFG_TUD_NCM_IN_NTB_MAX_SIZE     3200

#ifdef __cplusplus
}
#endif

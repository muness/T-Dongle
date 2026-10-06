// SPDX-License-Identifier: MIT
#include <stdint.h>
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/reset_reasons.h"
#include "tdongle_rescue.h"

void bootloader_hooks_include(void) {}

void bootloader_after_init(void)
{
    const soc_reset_reason_t reason = esp_rom_get_reset_reason(0);
    const uint32_t word = REG_READ(RTC_CNTL_STORE0_REG);
    if (reason == RESET_REASON_CHIP_POWER_ON || (word >> 16) != TDONGLE_RESCUE_MAGIC) {
        if ((word >> 16) == TDONGLE_RESCUE_MAGIC) REG_WRITE(RTC_CNTL_STORE0_REG, 0);
        return; // not opted in, or a fresh power-up: nothing to judge
    }
    const uint32_t state = (word >> 8) & 0xFFu;
    uint32_t count = word & 0xFFu;
    count = state == TDONGLE_RESCUE_HEALTHY ? 0 : count + 1;
    if (count >= TDONGLE_RESCUE_LIMIT) {
        ESP_LOGW("rescue", "%u boots in a row never became healthy (last reset %d): entering ROM download mode",
                 (unsigned)count, (int)reason);
        REG_WRITE(RTC_CNTL_STORE0_REG, 0); // the next boot after a flash runs the app normally
        REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
        esp_rom_software_reset_system();
    }
    // Hand the count to the app; it re-arms (keeping the count) and later reports HEALTHY.
    REG_WRITE(RTC_CNTL_STORE0_REG, TDONGLE_RESCUE_WORD(0u, count));
    if (count) ESP_LOGW("rescue", "previous boot never became healthy (%u in a row, reset %d)", (unsigned)count, (int)reason);
}

// SPDX-License-Identifier: MIT
#include <stdint.h>
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/reset_reasons.h"
#include "tdongle_rescue.h"
#include "hal/wdt_hal.h"
#include "soc/rtc.h"

void bootloader_hooks_include(void) {}

/* Re-arm the RTC watchdog for the app start, on EVERY boot (not only when the opt-in magic was seen).
 *
 * Why always: the first boot after a flash has no magic (esptool's reset wipes the RTC domain), and that is exactly when a broken image is most likely, so an opt-in-only
 * guard would leave the dangerous boot unprotected. Why that is safe for the C firmware: the IDF bootloader already arms this watchdog on every boot (9 s,
 * CONFIG_BOOTLOADER_WDT_ENABLE, action "reset the RTC domain too"), and every IDF app disables it in its own start-up (esp_system init_disable_rtc_wdt, priority 999,
 * unless CONFIG_BOOTLOADER_WDT_DISABLE_IN_USER_CODE) before app_main. All that changes here is the timeout (30 s, so a slow app start is not cut off) and the action:
 * stage 0 = 3, reset the main system but NOT the RTC domain, so RTC_CNTL_STORE0 (the rescue count) survives a watchdog reset (action 4 wipes it: reset reason 16).
 * The Rust apps leave it armed through esp_hal::init (vendored esp-hal) and re-arm it with their own timeout as their first statement. */
static void rescue_disarm_rtc_wdt(void)
{
    wdt_hal_context_t ctx = RWDT_HAL_CONTEXT_DEFAULT();
    wdt_hal_write_protect_disable(&ctx);
    wdt_hal_disable(&ctx);
    wdt_hal_write_protect_enable(&ctx);
}

static void rescue_arm_rtc_wdt(void)
{
    wdt_hal_context_t ctx = RWDT_HAL_CONTEXT_DEFAULT();
    wdt_hal_init(&ctx, WDT_RWDT, 0, false);
    const uint32_t ticks = (uint32_t)((uint64_t)TDONGLE_RESCUE_WDT_MS * rtc_clk_slow_freq_get_hz() / 1000);
    wdt_hal_write_protect_disable(&ctx);
    wdt_hal_config_stage(&ctx, WDT_STAGE0, ticks, WDT_STAGE_ACTION_RESET_SYSTEM); /* 3: digital core only, RTC (STORE0) survives */
    wdt_hal_set_flashboot_en(&ctx, false);
    wdt_hal_enable(&ctx);
    wdt_hal_write_protect_enable(&ctx);
}

void bootloader_after_init(void)
{
    rescue_arm_rtc_wdt();
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
        rescue_disarm_rtc_wdt(); // the ROM loader must not be reset by a watchdog armed for the app
        REG_WRITE(RTC_CNTL_STORE0_REG, 0); // the next boot after a flash runs the app normally
        REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
        esp_rom_software_reset_system();
    }
    // Hand the count to the app; it re-arms (keeping the count) and later reports HEALTHY.
    REG_WRITE(RTC_CNTL_STORE0_REG, TDONGLE_RESCUE_WORD(0u, count));
    if (count) ESP_LOGW("rescue", "previous boot never became healthy (%u in a row, reset %d)", (unsigned)count, (int)reason);
}

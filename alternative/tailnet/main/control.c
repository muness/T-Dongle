#include "esp_rom_sys.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "gateway.h"
#include "boot_health.h"
#include "lcd.h"
#include "soc/rtc_cntl_reg.h"
#include "tusb.h"
#include "tdongle_pm.h"
extern void mgmt_write(const char *s);
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
#define MEMORY_COMMANDS "memory [guard N|bench], members, cpu, wifistats [reset|dump], "
#define MEMORY_FEATURE ",memory_diagnostics,wifi_stats"
#else
#define MEMORY_COMMANDS ""
#define MEMORY_FEATURE ""
#endif
extern bool gateway_online(void);
/* wireguard_lwip: ChaCha20-Poly1305 self-test + cycle benchmark (writes lines through the callback). */
extern int wg_crypto_bench_run(void (*write)(const char *line));
/* The `pm` command: the clock now, the scaling state and every CPU-max lock, then IDF's own lock table (heap buffer, truncated). An idle
 * gateway reports cpu_mhz=80 here; after a transfer the held_us counters have moved. See ADR 0016. */
static void pm_report(void) {
    tdongle_pm_status_t pm;
    char line[200];
    tdongle_pm_status(&pm);
    snprintf(line, sizeof(line), "power scaling=%d cpu_mhz=%lu max_mhz=%lu min_mhz=%lu configure_error=%d lock_create_failures=%lu\r\n", pm.scaling,
             (unsigned long)pm.cpu_mhz, (unsigned long)pm.max_mhz, (unsigned long)pm.min_mhz, pm.configure_error, (unsigned long)pm.lock_create_failures);
    mgmt_write(line);
    for (unsigned i = 0; i < pm.bursts; i++) {
        const tdongle_pm_burst_stats_t *b = &pm.burst[i];
        snprintf(line, sizeof(line), "pm_lock name=%s depth=%lu acquires=%lu releases=%lu held_us=%lu max_depth=%lu underflows=%lu forced_releases=%lu backend_failures=%lu isr_rejects=%lu\r\n",
                 b->name, (unsigned long)b->depth, (unsigned long)b->acquires, (unsigned long)b->releases, (unsigned long)b->held_us, (unsigned long)b->max_depth,
                 (unsigned long)b->underflows, (unsigned long)b->forced_releases, (unsigned long)b->backend_failures, (unsigned long)b->isr_rejects);
        mgmt_write(line);
    }
    /* On the heap, briefly: the 4 KB command stack has no room for 1 KB of table next to the formatting. */
    enum { DUMP_BYTES = 1024 };
    char *dump = malloc(DUMP_BYTES);
    if (dump && tdongle_pm_dump_locks(dump, DUMP_BYTES)) {
        mgmt_write("esp_pm_dump_locks:\r\n");
        /* The dump is LF terminated text: send it in console-sized pieces. */
        for (char *p = dump; *p;) {
            char *eol = strchr(p, '\n');
            size_t n = eol ? (size_t)(eol - p) : strlen(p);
            char part[120];
            if (n > sizeof(part) - 3) n = sizeof(part) - 3;
            memcpy(part, p, n);
            memcpy(part + n, "\r\n", 3);
            mgmt_write(part);
            p += n + (eol ? 1 : 0);
            if (!eol) break;
        }
    }
    free(dump);
}
static QueueHandle_t commands;
static StaticQueue_t command_queue;
static uint8_t command_bytes[2*512];
static StaticTask_t command_tcb;
static StackType_t command_stack[4096];
static int boot_sink(void *context,const char *data,size_t n) {
    char part[128];
    while(n){size_t take=n<127?n:127;memcpy(part,data,take);part[take]=0;mgmt_write(part);data+=take;n-=take;}
    return 0;
}
bool control_submit(const char *line) {
    char buffer[512] = {0};
    if (strlen(line) >= sizeof(buffer))
        return false;
    strlcpy(buffer, line, sizeof(buffer));
    return commands && xQueueSend(commands, buffer, 0) == pdTRUE;
}
static void command_task(void *arg) {
    char line[512];
    for (;;) {
        gateway_display_tick();
        if (xQueueReceive(commands, line, pdMS_TO_TICKS(UI_POLL_MS)) != pdTRUE)
            continue;
        if (!strcmp(line, "help"))
            mgmt_write(gateway_tailnet_mode()?
                       "T-Dongle tailnet gateway protocol=1\r\nCommands: status, list, use N, del N, scan, profile JSON, display BRIGHTNESS ROTATION DIM_SECONDS, setup [N], cancel, reset, confirm-reset, "
                       "mode wifi_bridge|tailnet_gateway, capabilities, pm, " MEMORY_COMMANDS "reboot, bootloader. Setup: http://192.168.77.1/ or the button menu (setup access point)\r\n":
                       "T-Dongle Wi-Fi bridge protocol=1\r\nCommands: status, list, use N, del N, scan, profile JSON, display BRIGHTNESS ROTATION DIM_SECONDS, setup [N], cancel, reset, confirm-reset, "
                       "mode wifi_bridge|tailnet_gateway, capabilities, pm, " MEMORY_COMMANDS "reboot, bootloader. Add Wi-Fi: hold the button for the setup access point (TDongle-XXXXXX), or profile {\"slot\":N,\"priority\":50,\"name\":\"X\",\"ssid\":\"X\",\"password\":\"X\"}, or muness.com/T-Dongle\r\n");
        else if (!strcmp(line, "capabilities"))
            mgmt_write(gateway_tailnet_mode()?"capabilities schema=1 features=tailnet_gateway,boot_diagnostics,mode_switch,chip_temperature,automatic_display,power_report,setup_ap,button_menu,factory_reset,status_led,display_pages,display_settings" MEMORY_FEATURE "\r\n":"capabilities schema=1 features=boot_diagnostics,mode_switch,chip_temperature,automatic_display,power_report,setup_ap,button_menu,factory_reset,status_led,display_pages,display_settings,roaming_assist" MEMORY_FEATURE "\r\n");
        else if (!strcmp(line, "pm")) {
            pm_report();
        } else if (!strcmp(line, "status")) {
            gateway_serial_command(line);
            gateway_bridge_status();    /* bridge mode: new lines after the established ones, from this task's frame rather than that call's */
        } else if (!strcmp(line, "boot-status")) {
            gateway_boot_report(NULL,boot_sink);mgmt_write("\r\n");
        } else if (!strcmp(line, "retry-startup")) {
            if(gateway_boot_retry()!=ESP_OK)mgmt_write("ERR Could not preserve crash evidence or reset recovery guard\r\n");
            else {mgmt_write("OK restarting services\r\ndone>\r\n");vTaskDelay(pdMS_TO_TICKS(300));esp_restart();}
        } else if (!strcmp(line, "crypto bench")) {
            wg_crypto_bench_run(mgmt_write);
        } else if(gateway_serial_command(line) || gateway_memory_command(line)) {
        }
        else if (!strcmp(line, "reboot")) {
            mgmt_write("OK rebooting\r\ndone>\r\n");
            vTaskDelay(pdMS_TO_TICKS(200));
            esp_restart();
        } else if (!strcmp(line, "bootloader")) {
            gateway_display_installing();
            mgmt_write("OK rebooting into ROM download mode\r\ndone>\r\n");
            vTaskDelay(pdMS_TO_TICKS(200));
            REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
            esp_rom_software_reset_system();
        } else
            mgmt_write(gateway_tailnet_mode()?"ERR Unknown command; type help. USB setup: http://192.168.77.1/\r\n":"ERR Unknown command; type help\r\n");
        mgmt_write("done>\r\n");
    }
}
esp_err_t gateway_console_start(void) {
    commands=xQueueCreateStatic(2,512,command_bytes,&command_queue);
    extern esp_err_t console_init(void);
    esp_err_t result=console_init();if(result!=ESP_OK)return result;
    return xTaskCreateStatic(command_task,"gateway_control",sizeof(command_stack),NULL,3,command_stack,&command_tcb)?ESP_OK:ESP_ERR_NO_MEM;
}

#include "esp_rom_sys.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "gateway.h"
#include "soc/rtc_cntl_reg.h"
#include "tusb.h"
extern void mgmt_write(const char *s);
extern bool gateway_online(void);
static QueueHandle_t commands;
bool control_submit(const char *line) {
    char buffer[128] = {0};
    if (strlen(line) >= sizeof(buffer))
        return false;
    strlcpy(buffer, line, sizeof(buffer));
    return commands && xQueueSend(commands, buffer, 0) == pdTRUE;
}
static void command_task(void *arg) {
    char line[128], reply[384];
    for (;;) {
        if (xQueueReceive(commands, line, portMAX_DELAY) != pdTRUE)
            continue;
        if (!strcmp(line, "help"))
            mgmt_write("T-Dongle tailnet gateway protocol=1\r\nCommands: status, list, "
                       "capabilities, reboot, bootloader. Setup: http://192.168.77.1/\r\n");
        else if (!strcmp(line, "capabilities"))
            mgmt_write("capabilities schema=1 features=tailnet_gateway\r\n");
        else if (!strcmp(line, "status")) {
            snprintf(reply, sizeof(reply),
                     "mode=tailnet trial=0 active=0 wifi=%s rssi=unknown usb_enumerated=%d "
                     "usb_transport_ready=%d host_interface_ready=unknown "
                     "internet=not_checked\r\nuptime_ms=%llu free_heap=%lu\r\n",
                     gateway_online() ? "up" : "joining", tud_mounted(), tud_ready(),
                     (unsigned long long)(esp_timer_get_time() / 1000),
                     (unsigned long)esp_get_free_heap_size());
            mgmt_write(reply);
        } else if (!strcmp(line, "list")) {
        } /* Wi-Fi enrollment is owned by USB setup. */
        else if (!strcmp(line, "reboot")) {
            mgmt_write("OK rebooting\r\ndone>\r\n");
            vTaskDelay(pdMS_TO_TICKS(200));
            esp_restart();
        } else if (!strcmp(line, "bootloader")) {
            mgmt_write("OK rebooting into ROM download mode\r\ndone>\r\n");
            vTaskDelay(pdMS_TO_TICKS(200));
            REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
            esp_rom_software_reset_system();
        } else
            mgmt_write("ERR Use USB setup at http://192.168.77.1/\r\n");
        mgmt_write("done>\r\n");
    }
}
void gateway_console_start(void) {
    commands = xQueueCreate(4, 128);
    assert(commands);
    extern void console_init(void);
    console_init();
    assert(xTaskCreate(command_task, "gateway_control", 3072, NULL, 3, NULL) == pdPASS);
}

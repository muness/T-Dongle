// SPDX-License-Identifier: MIT
// CDC plumbing adapted from DrWhax/esp32-usb-wifi; see licenses/.
#include "gateway.h"
#include "boot_health.h"
bool control_submit(const char *line);
#include "sdkconfig.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#if CONFIG_TINYUSB_CDC_ENABLED
#include "tinyusb_cdc_acm.h"
static char line[512];
static size_t used;
static bool overflow;
static QueueHandle_t output;
static StaticQueue_t output_queue;
static uint8_t output_bytes[8*128];
static StaticTask_t writer_tcb;
static StackType_t writer_stack[3072];
static void writer(void *arg) {
    char b[128];
    for (;;)
        if (xQueueReceive(output, b, portMAX_DELAY) == pdTRUE) {
            size_t n = strlen(b), off = 0;
            unsigned retries = 0;
            while (off < n && retries++ < 10) {
                off += tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, (const uint8_t *)b + off,
                                                  n - off);
                tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, pdMS_TO_TICKS(20));
                if (off < n)
                    vTaskDelay(pdMS_TO_TICKS(10));
            }
        }
}
void mgmt_write(const char *s) {
    if (!output)
        return;
    while (*s) {
        char b[128] = {0};
        size_t n = strlen(s);
        if (n > 127)
            n = 127;
        memcpy(b, s, n);
        /* Bounded backpressure: boot reports must not silently lose chunks.
         * CDC callbacks never block the TinyUSB task. */
        TickType_t wait=!strcmp(pcTaskGetName(NULL),"gateway_control")?pdMS_TO_TICKS(300):0;
        xQueueSend(output, b, wait);
        s += n;
    }
}
static void rx(int itf, cdcacm_event_t *e) {
    uint8_t buf[64];
    size_t n;
    while (tinyusb_cdcacm_read(itf, buf, sizeof(buf), &n) == ESP_OK && n) {
        for (size_t i = 0; i < n; i++) {
            unsigned char c = buf[i];
            if (c == '\r' || c == '\n') {
                if (overflow)
                    mgmt_write("ERR line too long/invalid; discarded\r\n");
                else if (used) {
                    line[used] = 0;
                    if (!control_submit(line))
                        mgmt_write("ERR command queue full\r\n");
                } else
                    mgmt_write("tdongle>\r\n");
                memset(line, 0, sizeof(line));
                used = 0;
                overflow = false;
            } else if (c == 8 || c == 127) {
                if (used)
                    line[--used] = 0;
            } else if (c >= 32 && c < 127 && !overflow) {
                if (used < sizeof(line) - 1)
                    line[used++] = c;
                else
                    overflow = true;
            } else
                overflow = true;
        }
    }
}
static void state(int itf, cdcacm_event_t *e) {
    if (e->line_state_changed_data.dtr)
        /* The bridge keeps the v0.1.x greeting prefix ("T-Dongle-S3 adapter"); the gateway has always said "tailnet". */
        mgmt_write(gateway_tailnet_mode()?"T-Dongle-S3 tailnet " GATEWAY_VERSION ". Type help. Input is not echoed.\r\n":"T-Dongle-S3 adapter " GATEWAY_VERSION ". Type help. Input is not echoed.\r\n");
}
esp_err_t console_init(void) {
    output = xQueueCreateStatic(8,128,output_bytes,&output_queue);
    if(!xTaskCreateStatic(writer,"console_tx",sizeof(writer_stack),NULL,2,writer_stack,&writer_tcb))return ESP_ERR_NO_MEM;
    tinyusb_config_cdcacm_t c = {
        .cdc_port = TINYUSB_CDC_ACM_0, .callback_rx = rx, .callback_line_state_changed = state};
    return tinyusb_cdcacm_init(&c);
}
#else
void mgmt_write(const char *s) { (void)s; }
esp_err_t console_init(void) {return ESP_ERR_NOT_SUPPORTED;}
#endif
void console_printf(const char *fmt, ...) {
    char b[512];
    va_list a;
    va_start(a, fmt);
    vsnprintf(b, sizeof(b), fmt, a);
    va_end(a);
    mgmt_write(b);
}

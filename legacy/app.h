// SPDX-License-Identifier: MIT
#pragma once
#include "bridge.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
typedef struct {
    uint64_t ms;
    uint16_t code, detail;
} event_t;
typedef struct {
    settings_t cfg; /* public copy has passwords cleared */
    int active;
    bool setup, trial;
    char error[48];
    char ap_ssid[25], ap_pass[17];
    uint64_t setup_deadline;
    uint32_t free_heap, min_heap, dma_heap, control_stack, ui_stack;
    event_t events[24];
    unsigned event_count;
} app_snapshot_t;
void settings_load(settings_t *s);
esp_err_t settings_save(const settings_t *s);
esp_err_t settings_stage(int slot, const profile_t *p);
bool settings_take_candidate(int *slot, profile_t *p);
esp_err_t settings_reset(void);
bool settings_store_ok(void);
void control_init(bool setup);
bool control_submit(const char *line);
void app_snapshot(app_snapshot_t *s);
void app_event(unsigned code, unsigned detail);
void app_ui_stack(uint32_t n);
void console_init(void);
void mgmt_write(const char *s);
void console_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void portal_start(void);
void portal_trace_dump(void);
void portal_identity(char *ssid, char *pass);
void ui_start(void);
void setup_reboot(bool enter);
bool setup_requested(void);
int setup_preferred_slot(void);

#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "lcd_view.h"
/* The panel driver. What is shown, and when, is decided by the UI poll (device_ui.inc). */
/* The backlight percentage and rotation to start with (the stored display settings). */
esp_err_t gateway_display_start(unsigned backlight_percent, unsigned rotation);
bool gateway_display_present(void);                        /* the panel works */
void gateway_display_show(const lcd_view *view);           /* draw it (skipped when it equals what is on the glass) */
/* Backlight percentage (0 to 100) and rotation (0 or 1: 180 degrees); both are only sent to the hardware when they change. */
void gateway_display_apply(unsigned backlight_percent, unsigned rotation);
void gateway_display_installing(void);                     /* the INSTALLING screen, immediately and from then on */
bool gateway_display_is_installing(void);
/* The UI poll: button, status light, display. Called by the gateway_control task between commands, every UI_POLL_MS at most. */
enum { UI_POLL_MS = 20 };
void gateway_display_tick(void);
/* A command a button gesture chose, for the control task's loop (same task as the poll); false when none. */
bool gateway_ui_take_command(char *out, size_t size);

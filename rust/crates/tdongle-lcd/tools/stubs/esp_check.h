#pragma once
#include <assert.h>
#include <stddef.h>
#include "esp_lcd_panel_interface.h"
#define ESP_RETURN_ON_ERROR(x, tag, msg) do { esp_err_t e_ = (x); if (e_ != ESP_OK) return e_; } while (0)
#define ESP_GOTO_ON_ERROR(x, label, tag, msg) do { ret = (x); if (ret != ESP_OK) goto label; } while (0)
#define ESP_GOTO_ON_FALSE(c, e, label, tag, msg) do { if (!(c)) { ret = (e); goto label; } } while (0)
#define __containerof(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

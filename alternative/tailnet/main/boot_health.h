#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define GATEWAY_VERSION "0.2.13"
/* Numeric stages are persisted, so append rather than reorder. */
enum gateway_boot_stage {
    BOOT_USB=1, BOOT_SETTINGS, BOOT_NETWORK, BOOT_HTTP, BOOT_DIRECTORY,
    BOOT_ROUTES, BOOT_WIFI, BOOT_DNS, BOOT_MANAGER, BOOT_RUNNING,
    BOOT_STAGE_COUNT
};
void gateway_boot_begin(void);
void gateway_boot_storage(void);
void gateway_boot_stage(unsigned stage);
void gateway_boot_result(unsigned stage, int error);
void gateway_boot_complete(void);
bool gateway_boot_recovery(void);
int gateway_boot_retry(void);
int gateway_boot_report(void *context, int (*sink)(void *, const char *, size_t));
/* RAM/RTC breadcrumbs only: never write flash on the packet path. */
void gateway_route_mark(unsigned stage, uint32_t member);

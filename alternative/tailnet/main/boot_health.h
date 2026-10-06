#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Set by main/CMakeLists.txt from the project version (VERSION file or TDONGLE_VERSION). The fallback keeps host tests building. */
#ifndef GATEWAY_VERSION
#define GATEWAY_VERSION "0.0.0-host"
#endif
/* Numeric stages are persisted, so append rather than reorder. */
enum gateway_boot_stage {
    BOOT_USB=1, BOOT_SETTINGS, BOOT_NETWORK, BOOT_HTTP, BOOT_DIRECTORY,
    BOOT_ROUTES, BOOT_WIFI, BOOT_DNS, BOOT_MANAGER, BOOT_RUNNING, BOOT_DISPLAY,
    BOOT_SETUP,   /* the setup access point (a setup boot's own start, in place of directory/routes/wifi/dns/manager) */
    BOOT_STAGE_COUNT
};
void gateway_boot_begin(void);
void gateway_boot_storage(void);
void gateway_boot_stage(unsigned stage);
void gateway_boot_result(unsigned stage, int error);
void gateway_boot_complete(void);
bool gateway_boot_recovery(void);
bool gateway_boot_needs_attention(void);
int gateway_boot_retry(void);
int gateway_boot_report(void *context, int (*sink)(void *, const char *, size_t));
/* RAM/RTC breadcrumbs only: never write flash on the packet path. */
void gateway_route_mark(unsigned stage, uint32_t member);

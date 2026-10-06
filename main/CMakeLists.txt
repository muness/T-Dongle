set(unified "${CMAKE_CURRENT_LIST_DIR}/../alternative/tailnet/main")
# Platform-neutral parts of the device UI and setup (host tested by tools/test.sh): settings, saved-network metadata, the v0.1.x import, the
# setup boot decision and access rules, captive DNS, the nearby-network list, the button menu, the status light, traffic and health.
set(device "ui_settings.c" "wifi_meta.c" "legacy_import.c" "setup_boot.c" "setup_access.c" "captive_dns.c" "scan_list.c" "menu.c" "led.c" "traffic.c" "traffic_hooks.c" "health.c")
idf_component_register(SRCS "core.c" "profile_json.c" ${device} "${unified}/gateway_main.c" "${unified}/boot_health.c" "${unified}/lcd.c" "${unified}/lcd_view.c" "${unified}/router.c" "${unified}/route_table.c" "${unified}/dns.c" "${unified}/console.c" "${unified}/control.c" "${unified}/socket_budget.c" "${unified}/usb_health.c" INCLUDE_DIRS "${unified}" "." REQUIRES esp_timer bootloader_support tdongle_runtime esp_lcd st7735 esp_driver_spi esp_driver_gpio esp_driver_ledc espcoredump esp_app_format microlink esp_tinyusb esp_http_server nvs_flash esp_wifi esp_netif lwip json EMBED_TXTFILES "${unified}/setup.html" "${unified}/setup_ap.html")
# Traffic counting (traffic_hooks.c) wraps the two NCM callbacks; the other wraps are the socket budget's. The wrappers are only referenced by
# the TinyUSB archive, which the linker reads after this component's, so -u forces them in.
idf_build_set_property(LINK_OPTIONS "-Wl,--wrap=lwip_socket,--wrap=lwip_accept,--wrap=lwip_close,--wrap=tud_network_recv_cb,--wrap=tud_network_xmit_cb,-u,__wrap_tud_network_recv_cb,-u,__wrap_tud_network_xmit_cb" APPEND)
# The reported firmware version is the project version (see the root CMakeLists.txt).
idf_build_get_property(tdongle_version PROJECT_VER)
target_compile_definitions(${COMPONENT_LIB} PRIVATE GATEWAY_VERSION="${tdongle_version}")

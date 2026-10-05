# Read the build property, not the option: see the root CMakeLists.txt.
idf_build_get_property(tdongle_legacy_bridge TDONGLE_LEGACY_BRIDGE)
if(tdongle_legacy_bridge)
idf_component_register(SRCS "bridge.c" "core.c" "settings.c" "control.c" "console.c" "portal.c" "ui.c" "view.c" "profile_json.c"
 INCLUDE_DIRS "." PRIV_REQUIRES esp_tinyusb esp_wifi esp_netif nvs_flash esp_timer esp_driver_gpio esp_driver_ledc esp_driver_spi esp_lcd st7735 esp_http_server json esp_system)
else()
set(unified "${CMAKE_CURRENT_LIST_DIR}/../alternative/tailnet/main")
idf_component_register(SRCS "core.c" "profile_json.c" "${unified}/gateway_main.c" "${unified}/boot_health.c" "${unified}/lcd.c" "${unified}/lcd_view.c" "${unified}/router.c" "${unified}/dns.c" "${unified}/console.c" "${unified}/control.c" "${unified}/socket_budget.c" "${unified}/usb_health.c" INCLUDE_DIRS "${unified}" "." REQUIRES esp_timer tdongle_runtime esp_lcd st7735 esp_driver_spi esp_driver_gpio espcoredump esp_app_format microlink esp_tinyusb esp_http_server nvs_flash esp_wifi esp_netif lwip json EMBED_TXTFILES "${unified}/setup.html")
idf_build_set_property(LINK_OPTIONS "-Wl,--wrap=lwip_socket,--wrap=lwip_accept,--wrap=lwip_close" APPEND)
endif()

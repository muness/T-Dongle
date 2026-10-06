set(unified "${CMAKE_CURRENT_LIST_DIR}/../alternative/tailnet/main")
idf_component_register(SRCS "core.c" "profile_json.c" "${unified}/gateway_main.c" "${unified}/boot_health.c" "${unified}/lcd.c" "${unified}/lcd_view.c" "${unified}/router.c" "${unified}/route_table.c" "${unified}/dns.c" "${unified}/console.c" "${unified}/control.c" "${unified}/socket_budget.c" "${unified}/usb_health.c" INCLUDE_DIRS "${unified}" "." REQUIRES esp_timer tdongle_runtime esp_lcd st7735 esp_driver_spi esp_driver_gpio espcoredump esp_app_format microlink esp_tinyusb esp_http_server nvs_flash esp_wifi esp_netif lwip json EMBED_TXTFILES "${unified}/setup.html")
idf_build_set_property(LINK_OPTIONS "-Wl,--wrap=lwip_socket,--wrap=lwip_accept,--wrap=lwip_close" APPEND)
# The reported firmware version is the project version (see the root CMakeLists.txt).
idf_build_get_property(tdongle_version PROJECT_VER)
target_compile_definitions(${COMPONENT_LIB} PRIVATE GATEWAY_VERSION="${tdongle_version}")

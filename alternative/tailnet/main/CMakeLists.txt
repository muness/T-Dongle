idf_component_register(SRCS "../../../main/core.c" "../../../main/profile_json.c" "gateway_main.c" "boot_health.c" "lcd.c" "lcd_view.c" "router.c" "route_table.c" "dns.c" "console.c" "control.c" "socket_budget.c" "usb_health.c" INCLUDE_DIRS "." "../../../main" REQUIRES esp_timer tdongle_runtime esp_lcd st7735 esp_driver_spi esp_driver_gpio espcoredump esp_app_format microlink esp_tinyusb esp_http_server nvs_flash esp_wifi esp_netif lwip json EMBED_TXTFILES "setup.html")

idf_build_set_property(LINK_OPTIONS "-Wl,--wrap=lwip_socket,--wrap=lwip_accept,--wrap=lwip_close" APPEND)

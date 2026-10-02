idf_component_register(SRCS "gateway_main.c" "boot_health.c" "router.c" "dns.c" "console.c" "control.c" "socket_budget.c" INCLUDE_DIRS "." REQUIRES espcoredump esp_app_format microlink esp_tinyusb esp_http_server nvs_flash esp_wifi esp_netif lwip json EMBED_TXTFILES "setup.html")

idf_build_set_property(LINK_OPTIONS "-Wl,--wrap=lwip_socket,--wrap=lwip_accept,--wrap=lwip_close" APPEND)

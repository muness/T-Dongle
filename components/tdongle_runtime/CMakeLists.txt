idf_component_register(SRCS "temperature.c" "memory.c" "mode_store.c" "l2.c" INCLUDE_DIRS "include" REQUIRES nvs_flash esp_driver_tsens esp_timer esp_wifi esp_tinyusb)

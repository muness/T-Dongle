set(srcs "temperature.c" "memory.c" "mode_store.c" "l2.c" "tdongle_pm.c" "tdongle_pm_burst.c")
# CONFIG_* is not visible while IDF expands requirements, so mbedtls is always a private requirement.
if(CONFIG_TDONGLE_MEMORY_DIAGNOSTICS)
 list(APPEND srcs "memory_diagnostics.c" "tls_hooks.c")
endif()
idf_component_register(SRCS ${srcs} INCLUDE_DIRS "include" REQUIRES nvs_flash esp_pm esp_hw_support esp_driver_tsens esp_timer esp_wifi esp_tinyusb PRIV_REQUIRES mbedtls)

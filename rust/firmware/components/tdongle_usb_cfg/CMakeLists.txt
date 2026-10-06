# TinyUSB configuration for the Rust firmware: the only C in this component is a header. The USB glue itself (descriptors, the CDC console,
# the NCM class callbacks, the transmit ring) is Rust: src/usb/.
#
# The second public include directory is for bindgen alone: TinyUSB's FreeRTOS OSAL includes "FreeRTOS.h" without the "freertos/" prefix, which
# the C compiler finds through the freertos component's private include path but bindgen (which reads the public include directories only) does not.
idf_component_register(INCLUDE_DIRS "include" "${IDF_PATH}/components/freertos/FreeRTOS-Kernel/include/freertos"
                       PRIV_REQUIRES espressif__tinyusb)

# TinyUSB includes "tusb_config.h" from its own sources; hand it ours (esp_tinyusb does the same for the C firmware).
idf_component_get_property(tusb_lib espressif__tinyusb COMPONENT_LIB)
target_include_directories(${tusb_lib} PRIVATE "include")

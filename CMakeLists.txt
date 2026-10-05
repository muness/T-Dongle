cmake_minimum_required(VERSION 3.16)
option(TDONGLE_LEGACY_BRIDGE "Build the archived transparent bridge implementation" OFF)
if(NOT TDONGLE_LEGACY_BRIDGE)
 set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/alternative/tailnet/components/microlink" "${CMAKE_CURRENT_LIST_DIR}/alternative/tailnet/components/microlink/components/wireguard_lwip")
 if(NOT DEFINED SDKCONFIG_DEFAULTS)
  set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/alternative/tailnet/sdkconfig.defaults")
 endif()
 if(NOT DEFINED SDKCONFIG)
  set(SDKCONFIG "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.unified")
 endif()
endif()
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
# ESP-IDF expands component CMakeLists in a separate `cmake -P` process to
# collect requirements; project variables/options are not visible there, only
# build properties are. Publish the mode as a property for main/CMakeLists.txt.
if(TDONGLE_LEGACY_BRIDGE)
 idf_build_set_property(TDONGLE_LEGACY_BRIDGE 1)
else()
 idf_build_set_property(TDONGLE_LEGACY_BRIDGE 0)
endif()
# Network input reaches cJSON_Parse (control responses, the /key reply, the DERP
# map, setup requests) on tasks whose stacks are sized from measurements. cJSON
# recurses once per nesting level, so the default limit of 1000 lets a hostile
# document run a task out of stack. Tailscale's own documents nest about ten deep
# (tests/test_json_depth.c checks the figure and the stack cost); the projection
# path already refuses more than 32. tools/test-gateway.sh reads this number.
set(TDONGLE_CJSON_NESTING_LIMIT 32)
if(TDONGLE_LEGACY_BRIDGE)
 project(tdongle_adapter VERSION 0.1.0)
else()
 project(tdongle_unified VERSION 0.2.18)
 target_include_directories(__idf_lwip PRIVATE "${CMAKE_CURRENT_LIST_DIR}/alternative/tailnet/main")
 target_compile_definitions(__idf_lwip PRIVATE ESP_IDF_LWIP_HOOK_FILENAME="gateway_hooks.h")
endif()
if(TARGET __idf_json)
 target_compile_definitions(__idf_json PRIVATE CJSON_NESTING_LIMIT=${TDONGLE_CJSON_NESTING_LIMIT})
endif()

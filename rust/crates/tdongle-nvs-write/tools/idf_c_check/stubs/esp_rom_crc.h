#pragma once
#include <cstdint>
extern "C" uint32_t esp_rom_crc32_le(uint32_t crc, uint8_t const *buf, uint32_t len);

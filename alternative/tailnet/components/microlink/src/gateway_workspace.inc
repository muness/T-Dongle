static uint8_t gateway_plain[20480 + 16];
static union { uint64_t alignment; uint8_t bytes[24576]; } gateway_storage;
#define gateway_json (gateway_storage.bytes)
static StaticSemaphore_t gateway_lock_storage;
static SemaphoreHandle_t gateway_lock;
static portMUX_TYPE gateway_init_lock = portMUX_INITIALIZER_UNLOCKED;

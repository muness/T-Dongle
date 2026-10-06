static uint8_t gateway_plain[ML_GATEWAY_PLAIN_BYTES];
static union { uint64_t alignment; uint8_t bytes[ML_GATEWAY_JSON_BYTES]; } gateway_storage;
#define gateway_json (gateway_storage.bytes)
static StaticSemaphore_t gateway_lock_storage;
static SemaphoreHandle_t gateway_lock;
static portMUX_TYPE gateway_init_lock = portMUX_INITIALIZER_UNLOCKED;

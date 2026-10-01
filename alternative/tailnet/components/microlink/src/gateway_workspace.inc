static uint8_t gateway_plain[20480 + 16];
static uint8_t gateway_json[24576];
static StaticSemaphore_t gateway_lock_storage;
static SemaphoreHandle_t gateway_lock;
static portMUX_TYPE gateway_init_lock = portMUX_INITIALIZER_UNLOCKED;

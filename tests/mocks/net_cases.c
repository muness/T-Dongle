// SPDX-License-Identifier: MIT
static int caller_free_count;
static void released(void *cookie, void *ctx) {
    (void)ctx;
    assert(cookie != NULL);
    free(cookie);
    free_count++;
}
/* Match gateway usb_tx's ownership: callback frees successful sends; caller
 * frees every failed send. ASan catches a second copy/free of any payload. */
static void send_packet(int timing, int writable, esp_err_t expected) {
    uint8_t *bytes = malloc(100);
    assert(bytes);
    memset(bytes, 0x5a, 100);
    int before = free_count;
    schedule = timing;
    allow_tx = writable;
    esp_err_t result = tinyusb_net_send_sync(bytes, 100, bytes, 20);
    assert(result == expected);
    if (result != ESP_OK) {
        free(bytes);
        caller_free_count++;
    }
    assert(free_count == before + (result == ESP_OK));
    assert(s_net_obj.packet_to_send == NULL);
}
int main(void) {
    tinyusb_net_config_t cfg = {.free_tx_buffer = released};
    assert(tinyusb_net_init(&cfg) == ESP_OK);
    send_packet(0, 1, ESP_OK);
    send_packet(1, 1, ESP_ERR_TIMEOUT);
    run_deferred();
    assert(free_count == 1);
    /* Copy begins exactly as wait expires. Returning TIMEOUT would cause the
     * caller to free a payload already consumed by the USB callback. */
    send_packet(2, 1, ESP_OK);
    send_packet(0, 0, ESP_FAIL);
    send_packet(0, 1, ESP_OK);

    /* Retain old callbacks until the next send. An old callback may consume
     * the new slot, but its own callback must then be a harmless wakeup. */
    for (int repeat = 0; repeat < 1000; ++repeat) {
        for (int old = 1; old <= 7; ++old) {
            for (int i = 0; i < old; ++i) send_packet(1, 1, ESP_ERR_TIMEOUT);
            send_packet(0, 1, ESP_OK);
            assert(pending == 0);
            /* Same overlap, with the copy starting after the wait expires. */
            for (int i = 0; i < old; ++i) send_packet(1, 1, ESP_ERR_TIMEOUT);
            send_packet(2, 1, ESP_OK);
            assert(pending == 0);
            /* Backpressure also consumes its slot without releasing payload. */
            for (int i = 0; i < old; ++i) send_packet(1, 1, ESP_ERR_TIMEOUT);
            send_packet(0, 0, ESP_FAIL);
            send_packet(0, 1, ESP_OK);
        }
    }
    tinyusb_net_deinit();
    printf("PASS: TinyUSB allocated-buffer ownership; %d callback releases, %d caller releases; timeout backlog, deadline/copy race, backpressure, recovery\n", free_count, caller_free_count);
}

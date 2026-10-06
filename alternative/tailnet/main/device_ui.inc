/* The v0.1.1 front panel, restored for both modes: the button and its menu, the APA102 status light, the screen pages, and the display
 * settings. Compiled into gateway_main.c after the saved-network store and the setup access point.
 *
 * No task of its own. gateway_display_tick() is the poll: the gateway_control task (control.c) calls it every UI_POLL_MS between
 * commands, and a task would cost about 3 KB of the heap the tailnet admission budget is measured against (ml_admission.h). The cost
 * of sharing: a serial command that takes long (`scan`, about 3 s) pauses the button, light and screen for that long. All UI state
 * belongs to that one caller, so it needs no locking; the saved-network list it reads is copied under members_lock. */
enum { UI_DRAW_MS = 250, UI_LED_MS = 50, UI_LED_REFRESH_MS = 1000, UI_HEALTH_ROTATE_MS = 4000 };
static struct {
    bool ready;
    button_t button;
    menu_state menu;
    unsigned page;
    uint32_t last_touch_ms, last_draw_ms, last_led_ms, led_sent_ms, led_since_ms;
    bool redraw;
    led_mode led;
    led_rgb led_sent;
    bool led_sent_valid;
    led_inputs led_in;
    traffic_sampler traffic;
    unsigned saved_count;      /* saved networks, refreshed while the menu is open */
    char menu_name[25];        /* the display name of the network the menu is showing */
} ui;
static SemaphoreHandle_t ui_lock;
static StaticSemaphore_t ui_lock_storage;
static RTC_NOINIT_ATTR health_counters health_rtc;
static uint32_t reset_reason_at_boot;
bool gateway_display_state(lcd_state *s);   /* defined with the tailnet admission code below */
extern unsigned gateway_usb_health(unsigned index);
extern bool control_submit(const char *line);   /* for the HTTP handlers (the setup page's Done); the front panel uses ui_submit */

/* ---- APA102: one pixel, bit-banged (GPIO39 clock, GPIO40 data). A frame is about 50 microseconds of GPIO writes. */
static void led_write(led_rgb color) {
    uint8_t frame[12];
    led_apa102_frame(color, frame);
    for (unsigned i = 0; i < sizeof(frame); i++)
        for (int bit = 7; bit >= 0; bit--) {
            gpio_set_level(BOARD_LED_CLK, 0);
            gpio_set_level(BOARD_LED_DATA, (frame[i] >> bit) & 1);
            gpio_set_level(BOARD_LED_CLK, 1);
        }
}
static esp_err_t ui_start(void) {
    ui_lock = xSemaphoreCreateMutexStatic(&ui_lock_storage);
    if (!ui_lock) return ESP_ERR_NO_MEM;
    gpio_config_t button = {.pin_bit_mask = 1ULL << BOARD_BUTTON, .mode = GPIO_MODE_INPUT, .pull_up_en = GPIO_PULLUP_ENABLE};
    gpio_config_t light = {.pin_bit_mask = (1ULL << BOARD_LED_DATA) | (1ULL << BOARD_LED_CLK), .mode = GPIO_MODE_OUTPUT};
    esp_err_t e = gpio_config(&button);
    if (e == ESP_OK) e = gpio_config(&light);
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    ui.last_touch_ms = ui.led_since_ms = now;
    ui.led = LED_JOIN;
    ui.redraw = true;
    ui.ready = e == ESP_OK;
    return e;
}

/* ---- What a button gesture does: the same commands the serial console takes, so the two cannot disagree. Handed to the control task's loop through
 * a 20 byte slot, not control_submit: that copies into a 512 byte stack buffer, on top of this frame, on a 4 KB stack. */
static char ui_pending[20];   /* the command a gesture chose, taken by the control task's loop (same task) */
bool gateway_ui_take_command(char *out, size_t size) {
    if (!ui_pending[0]) return false;
    strlcpy(out, ui_pending, size);
    ui_pending[0] = 0;
    return true;
}
static void ui_submit(const char *command) { if (!ui_pending[0]) strlcpy(ui_pending, command, sizeof(ui_pending)); }
static void ui_run(menu_action a) {
    char command[16];
    switch (a.kind) {
    case MENU_ACTION_SETUP: ui_submit("setup"); break;
    case MENU_ACTION_CANCEL_SETUP: ui_submit("cancel"); break;
    case MENU_ACTION_USE: snprintf(command, sizeof(command), "use %u", a.slot); ui_submit(command); break;
    case MENU_ACTION_RESET: ui_submit("reset"); break;
    case MENU_ACTION_CONFIRM_RESET: ui_submit("confirm-reset"); break;
    default: break;
    }
}
/* The display name of saved network `slot` (1-based) for the menu. Only the shown one is copied, under the lock, with a short timeout: the
 * previous name stays when the lock is busy. */
static const char *ui_name_of(void *ctx, unsigned slot) {
    (void)ctx;
    if (slot >= 1 && slot <= 8 && xSemaphoreTake(members_lock, pdMS_TO_TICKS(10)) == pdTRUE) {
        strlcpy(ui.menu_name, slot <= wifi_saved.count ? wifi_meta.slot[slot - 1].name : "", sizeof(ui.menu_name));
        ui.saved_count = wifi_saved.count;
        xSemaphoreGive(members_lock);
    }
    return ui.menu_name;
}

/* The state the screen and the light are drawn from, once per UI_DRAW_MS. */
static bool ui_compose(uint32_t now, bool dim, lcd_view *view) {
    lcd_state st = {0};
    if (!gateway_display_state(&st)) return false;   /* the lock is busy: draw again next time */
    st.installing = gateway_display_is_installing();
    st.usb = tud_ready();
    st.usb_configured = tud_mounted();
    st.usb_suspended = tud_suspended();
    st.page = ui.page;
    st.health_view = (now / UI_HEALTH_ROTATE_MS) % 3;
    wifi_link_info link = wifi_link_read();
    st.rssi_valid = link.connected && link.rssi_valid;
    st.rssi = link.rssi;
    st.setup = setup_active;
    if (setup_active) {
        snprintf(st.ap_ssid, sizeof(st.ap_ssid), "%s", setup_ap_name);
        st.setup_seconds_left = setup_session_seconds_left(&setup_clock, now);
    }
    traffic_counters counters = traffic_read();
    traffic_sample(&ui.traffic, &counters, now);
    st.down_kbps = ui.traffic.down_kbps;
    st.up_kbps = ui.traffic.up_kbps;
    st.down_bytes = ui.traffic.down_total;
    st.up_bytes = ui.traffic.up_total;
    st.down_frames = ui.traffic.down_frames_total;
    st.up_frames = ui.traffic.up_frames_total;
    traffic_bars(&ui.traffic, st.bars);
    st.uptime_s = (uint32_t)(esp_timer_get_time() / 1000000);   /* the 64 bit clock: `now` wraps after 49.7 days */
    st.wifi_up_s = online && wifi_link_stats.connects ? (uint32_t)(now - wifi_link_stats.last_connect_ms) / 1000 : 0;
    st.connects = wifi_link_stats.connects;
    st.last_reason = wifi_link_stats.last_reason;
    st.usb_resets = gateway_usb_health(8);
    st.heap_free = esp_get_free_heap_size();
    st.heap_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    /* The largest-block query walks the heap with the allocator locked: only while the one Health view that shows it is on the glass. */
    st.heap_largest = ui.page == 2 && st.health_view == 1 ? heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) : 0;
    st.reset_reason = reset_reason_at_boot;
    st.boots = health_rtc.boots;
    st.watchdogs = health_rtc.watchdogs;
    st.panics = health_rtc.panics;
    ui.led_in = (led_inputs){.setup = setup_active, .no_network = !st.saved_wifi, .associated = st.wifi, .usb_ready = st.usb, .recovery = st.recovery,
                             .tailnet = !st.bridge, .tailnet_ready = st.ready, .tailnet_failed = st.failed, .tailnet_login = st.login,
                             .last_reason = (uint16_t)wifi_link_stats.last_reason};
    if (ui.menu.open) {
        menu_context context = {.setup_active = setup_active, .saved_count = setup_active ? 0 : wifi_saved.count};
        /* Straight into the view's own rows (the same 5 x 27 bytes): no second buffer on the control task's stack. */
        _Static_assert(sizeof(view->row) == MENU_ROWS * (MENU_ROW_CHARS + 1), "menu rows are the view's rows");
        memset(view, 0, sizeof(*view));
        menu_render(&ui.menu, &context, ui_name_of, NULL, view->row);
        view->layout = LCD_LAYOUT_ROWS;
        view->attention = ui.menu.confirm;
    } else
        lcd_compose(&st, GATEWAY_VERSION, view);
    (void)dim;
    return true;
}
void gateway_display_tick(void) {
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    /* Before anything that can be unavailable (the panel, the lock): a setup boot always ends, whatever failed to start. */
    if (setup_active && setup_session_should_end(&setup_clock, now, wifi_ready)) {
        ESP_LOGW("setup", "leaving setup (%s): restarting into normal mode", wifi_ready ? "the 10 minutes are over" : "the access point did not start");
        setup_restart(SETUP_REQUEST_LEAVE, 0);
    }
    if (!ui.ready || !ui_lock || xSemaphoreTake(ui_lock, 0) != pdTRUE) return;
    /* Button. A press while the backlight is dimmed only wakes it (the whole gesture is swallowed), as in v0.1.1. */
    bool dim = !setup_active && (uint32_t)(now - ui.last_touch_ms) > (uint32_t)display_settings.dim_seconds * 1000u;
    /* The 64 bit clock: the button's debounce and hold timers are differences, which a 32 bit millisecond count would break at 49.7 days. */
    button_event_t event = button_update(&ui.button, !gpio_get_level(BOARD_BUTTON), dim, (uint64_t)(esp_timer_get_time() / 1000));
    if (event != BUTTON_NONE) {
        ui.last_touch_ms = now;
        dim = false;
        ui.redraw = true;
        menu_context context = {.setup_active = setup_active, .saved_count = setup_active ? 0 : wifi_saved.count};   /* no network switching during setup (see `use`) */
        menu_action action;
        if (event == BUTTON_SHORT) {
            if (!menu_event_handle(&ui.menu, &context, MENU_EVENT_SHORT, now, &action)) ui.page = (ui.page + 1) % LCD_PAGES;
        } else if (event == BUTTON_HOLD) {
            if (menu_event_handle(&ui.menu, &context, MENU_EVENT_HOLD, now, &action)) ui_run(action);
        }
    }
    menu_tick(&ui.menu, now);
    /* Screen: twice the 4 Hz rate of v0.1.1 is pointless on this panel; redraw on a gesture or every UI_DRAW_MS. */
    if (ui.redraw || (uint32_t)(now - ui.last_draw_ms) >= UI_DRAW_MS) {
        lcd_view view;
        if (ui_compose(now, dim, &view)) {
            ui.last_draw_ms = now;
            ui.redraw = false;
            gateway_display_apply(ui_settings_backlight_percent(&display_settings, dim), display_settings.rotation);
            gateway_display_show(&view);
            led_mode mode = led_select(&ui.led_in);
            if (mode != ui.led) { ui.led = mode; ui.led_since_ms = now; }
        }
    }
    /* Status light: animated every UI_LED_MS, written only when the colour changed (and once a second regardless, so a glitch on the
     * two wires cannot leave it wrong for long). */
    if ((uint32_t)(now - ui.last_led_ms) >= UI_LED_MS) {
        ui.last_led_ms = now;
        led_rgb color = led_color(ui.led, now, ui.led_since_ms);
        if (!ui.led_sent_valid || memcmp(&color, &ui.led_sent, sizeof(color)) || (uint32_t)(now - ui.led_sent_ms) >= UI_LED_REFRESH_MS) {
            led_write(color);
            ui.led_sent = color;
            ui.led_sent_valid = true;
            ui.led_sent_ms = now;
        }
    }
    xSemaphoreGive(ui_lock);
}

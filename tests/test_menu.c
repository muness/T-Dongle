// SPDX-License-Identifier: MIT
#include "menu.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *names[] = {"", "Home", "Phone hotspot", "A network with a very long display name", "Car"};
static const char *name_of(void *ctx, unsigned slot) { (void)ctx; return names[slot]; }
static menu_action act(menu_state *m, const menu_context *c, menu_event e, uint32_t now, bool *consumed) {
    menu_action a;
    *consumed = menu_event_handle(m, c, e, now, &a);
    return a;
}
static void opening_and_stepping(void) {
    menu_state m; menu_init(&m);
    menu_context c = {false, 3};
    bool used;
    menu_action a = act(&m, &c, MENU_EVENT_SHORT, 100, &used);
    assert(!used && !m.open && a.kind == MENU_ACTION_NONE);          /* short press, menu closed: the caller changes page */
    a = act(&m, &c, MENU_EVENT_HOLD, 2000, &used);
    assert(used && m.open && m.item == 0 && a.kind == MENU_ACTION_NONE);
    assert(menu_item_count(&c) == 6);                                  /* setup, three networks, factory reset, exit */
    for (unsigned i = 1; i <= 5; i++) { act(&m, &c, MENU_EVENT_SHORT, 2100 + i, &used); assert(used && m.item == i); }
    act(&m, &c, MENU_EVENT_SHORT, 3000, &used); assert(m.item == 0);   /* wraps */
}
static void choosing_items(void) {
    menu_state m; menu_init(&m);
    menu_context c = {false, 3};
    bool used;
    menu_action a;
    act(&m, &c, MENU_EVENT_HOLD, 0, &used);
    a = act(&m, &c, MENU_EVENT_HOLD, 10, &used);
    assert(a.kind == MENU_ACTION_SETUP && !m.open);
    c.setup_active = true;
    act(&m, &c, MENU_EVENT_HOLD, 20, &used);
    a = act(&m, &c, MENU_EVENT_HOLD, 30, &used);
    assert(a.kind == MENU_ACTION_CANCEL_SETUP && !m.open);             /* the same item cancels setup while it runs */
    c.setup_active = false;
    for (unsigned slot = 1; slot <= 3; slot++) {
        act(&m, &c, MENU_EVENT_HOLD, 40, &used);
        for (unsigned i = 0; i < slot; i++) act(&m, &c, MENU_EVENT_SHORT, 41, &used);
        a = act(&m, &c, MENU_EVENT_HOLD, 50, &used);
        assert(a.kind == MENU_ACTION_USE && a.slot == slot && !m.open);
    }
    act(&m, &c, MENU_EVENT_HOLD, 60, &used);
    for (unsigned i = 0; i < 5; i++) act(&m, &c, MENU_EVENT_SHORT, 61, &used);   /* Exit menu */
    a = act(&m, &c, MENU_EVENT_HOLD, 70, &used);
    assert(a.kind == MENU_ACTION_NONE && !m.open && used);
}
static void factory_reset_needs_a_second_hold(void) {
    menu_state m; menu_init(&m);
    menu_context c = {false, 1};
    bool used;
    menu_action a;
    act(&m, &c, MENU_EVENT_HOLD, 0, &used);
    act(&m, &c, MENU_EVENT_SHORT, 1, &used); act(&m, &c, MENU_EVENT_SHORT, 2, &used);   /* item 2 = Factory reset */
    a = act(&m, &c, MENU_EVENT_HOLD, 1000, &used);
    assert(a.kind == MENU_ACTION_RESET && m.open && m.confirm && m.confirm_until_ms == 11000);
    a = act(&m, &c, MENU_EVENT_HOLD, 10999, &used);
    assert(a.kind == MENU_ACTION_CONFIRM_RESET && !m.open && !m.confirm);
    /* A short press cancels the confirmation and moves on. */
    menu_init(&m);
    act(&m, &c, MENU_EVENT_HOLD, 0, &used);
    act(&m, &c, MENU_EVENT_SHORT, 1, &used); act(&m, &c, MENU_EVENT_SHORT, 2, &used);
    act(&m, &c, MENU_EVENT_HOLD, 3, &used);
    a = act(&m, &c, MENU_EVENT_SHORT, 4, &used);
    assert(a.kind == MENU_ACTION_NONE && !m.confirm && m.open && m.item == 3);
    /* Ten seconds pass: the confirmation is gone and holding asks again instead of resetting. */
    menu_init(&m);
    act(&m, &c, MENU_EVENT_HOLD, 0, &used);
    act(&m, &c, MENU_EVENT_SHORT, 1, &used); act(&m, &c, MENU_EVENT_SHORT, 2, &used);
    act(&m, &c, MENU_EVENT_HOLD, 100, &used);
    menu_tick(&m, 10099); assert(m.confirm);
    menu_tick(&m, 10100); assert(!m.confirm && m.open && m.item == 2);
    a = act(&m, &c, MENU_EVENT_HOLD, 10200, &used);
    assert(a.kind == MENU_ACTION_RESET && m.confirm);
    /* Expiry is noticed even without a tick (the event itself checks the clock), and across the 32 bit wrap. */
    menu_init(&m);
    act(&m, &c, MENU_EVENT_HOLD, 0xfffffff0u, &used);
    act(&m, &c, MENU_EVENT_SHORT, 0xfffffff1u, &used); act(&m, &c, MENU_EVENT_SHORT, 0xfffffff2u, &used);
    act(&m, &c, MENU_EVENT_HOLD, 0xfffffff3u, &used);
    a = act(&m, &c, MENU_EVENT_HOLD, 0xfffffff3u + 10001, &used);
    assert(a.kind == MENU_ACTION_RESET);
}
static void the_list_changes_under_an_open_menu(void) {
    menu_state m; menu_init(&m);
    menu_context c = {false, 4};
    bool used;
    act(&m, &c, MENU_EVENT_HOLD, 0, &used);
    for (unsigned i = 0; i < 4; i++) act(&m, &c, MENU_EVENT_SHORT, 1, &used);   /* network 4 */
    c.saved_count = 1;                                                           /* deleted from the setup page meanwhile */
    menu_action a = act(&m, &c, MENU_EVENT_HOLD, 2, &used);
    assert(a.kind == MENU_ACTION_SETUP);   /* never an action for a network that no longer exists: back to the first item */
    c.saved_count = 0;
    menu_init(&m);
    act(&m, &c, MENU_EVENT_HOLD, 0, &used);
    assert(menu_item_count(&c) == 3);
    act(&m, &c, MENU_EVENT_SHORT, 1, &used); a = act(&m, &c, MENU_EVENT_HOLD, 2, &used);
    assert(a.kind == MENU_ACTION_RESET);   /* with nothing saved the next item after setup is the reset */
}
static void text(void) {
    menu_state m; menu_init(&m);
    menu_context c = {false, 3};
    char rows[MENU_ROWS][MENU_ROW_CHARS + 1];
    bool used;
    act(&m, &c, MENU_EVENT_HOLD, 0, &used);
    menu_render(&m, &c, name_of, NULL, rows);
    assert(!strcmp(rows[0], "SETUP MENU") && !strcmp(rows[1], "Enter setup AP") && !strcmp(rows[3], "Short: next  Hold: select") && !rows[2][0] && !rows[4][0]);
    c.setup_active = true; menu_render(&m, &c, name_of, NULL, rows); assert(!strcmp(rows[1], "Cancel setup AP")); c.setup_active = false;
    act(&m, &c, MENU_EVENT_SHORT, 1, &used); menu_render(&m, &c, name_of, NULL, rows); assert(!strcmp(rows[1], "1 Home"));
    act(&m, &c, MENU_EVENT_SHORT, 1, &used); menu_render(&m, &c, name_of, NULL, rows); assert(!strcmp(rows[1], "2 Phone hotspot"));
    act(&m, &c, MENU_EVENT_SHORT, 1, &used); menu_render(&m, &c, name_of, NULL, rows); assert(!strncmp(rows[1], "3 A network with a very", 23) && strlen(rows[1]) <= MENU_ROW_CHARS);
    act(&m, &c, MENU_EVENT_SHORT, 1, &used); menu_render(&m, &c, name_of, NULL, rows); assert(!strcmp(rows[1], "Factory reset..."));
    act(&m, &c, MENU_EVENT_SHORT, 1, &used); menu_render(&m, &c, name_of, NULL, rows); assert(!strcmp(rows[1], "Exit menu"));
    act(&m, &c, MENU_EVENT_SHORT, 1, &used); act(&m, &c, MENU_EVENT_SHORT, 1, &used); act(&m, &c, MENU_EVENT_SHORT, 1, &used); act(&m, &c, MENU_EVENT_SHORT, 1, &used); act(&m, &c, MENU_EVENT_SHORT, 1, &used);   /* to Factory reset */
    act(&m, &c, MENU_EVENT_HOLD, 5, &used);
    menu_render(&m, &c, name_of, NULL, rows);
    assert(!strcmp(rows[0], "CONFIRM FACTORY RESET") && !strcmp(rows[1], "Release; hold again <10s") && !strcmp(rows[2], "Short press cancels"));
    for (unsigned r = 0; r < MENU_ROWS; r++) assert(strlen(rows[r]) <= MENU_ROW_CHARS);
}
int main(void) {
    opening_and_stepping(); choosing_items(); factory_reset_needs_a_second_hold(); the_list_changes_under_an_open_menu(); text();
    puts("Menu: hold opens, short steps and wraps, hold runs, factory reset needs a second hold inside 10 s, list changes are safe");
    return 0;
}

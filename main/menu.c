// SPDX-License-Identifier: MIT
#include "menu.h"
#include <stdio.h>
#include <string.h>

void menu_init(menu_state *m) { memset(m, 0, sizeof(*m)); }
unsigned menu_item_count(const menu_context *c) { return 1 + c->saved_count + 2; }
static unsigned reset_item(const menu_context *c) { return 1 + c->saved_count; }
bool menu_event_handle(menu_state *m, const menu_context *c, menu_event event, uint32_t now_ms, menu_action *action) {
    *action = (menu_action){MENU_ACTION_NONE, 0};
    unsigned items = menu_item_count(c);
    if (m->open && m->item >= items) m->item = 0;                 /* the list shrank while the menu was open */
    if (m->confirm && (int32_t)(now_ms - m->confirm_until_ms) >= 0) m->confirm = false;
    if (!m->open) {
        if (event != MENU_EVENT_HOLD) return false;
        m->open = true;
        m->item = 0;
        m->confirm = false;
        return true;
    }
    if (event == MENU_EVENT_SHORT) {
        m->item = (m->item + 1) % items;
        m->confirm = false;
        return true;
    }
    if (m->confirm) {
        action->kind = MENU_ACTION_CONFIRM_RESET;
        m->confirm = false;
        m->open = false;
    } else if (m->item == 0) {
        action->kind = c->setup_active ? MENU_ACTION_CANCEL_SETUP : MENU_ACTION_SETUP;
        m->open = false;
    } else if (m->item <= c->saved_count) {
        *action = (menu_action){MENU_ACTION_USE, m->item};
        m->open = false;
    } else if (m->item == reset_item(c)) {
        action->kind = MENU_ACTION_RESET;
        m->confirm = true;
        m->confirm_until_ms = now_ms + MENU_CONFIRM_MS;
    } else {
        m->open = false;                                          /* Exit menu */
    }
    return true;
}
void menu_tick(menu_state *m, uint32_t now_ms) {
    if (m->confirm && (int32_t)(now_ms - m->confirm_until_ms) >= 0) m->confirm = false;
}
void menu_render(const menu_state *m, const menu_context *c, const char *(*network_name)(void *, unsigned), void *ctx,
                 char rows[MENU_ROWS][MENU_ROW_CHARS + 1]) {
    memset(rows, 0, MENU_ROWS * (MENU_ROW_CHARS + 1));
    if (m->confirm) {
        snprintf(rows[0], MENU_ROW_CHARS + 1, "CONFIRM FACTORY RESET");
        snprintf(rows[1], MENU_ROW_CHARS + 1, "Release; hold again <10s");
        snprintf(rows[2], MENU_ROW_CHARS + 1, "Short press cancels");
        return;
    }
    snprintf(rows[0], MENU_ROW_CHARS + 1, "SETUP MENU");
    unsigned item = m->item < menu_item_count(c) ? m->item : 0;
    if (item == 0) snprintf(rows[1], MENU_ROW_CHARS + 1, "%s", c->setup_active ? "Cancel setup AP" : "Enter setup AP");
    else if (item <= c->saved_count) {
        const char *name = network_name ? network_name(ctx, item) : "";
        snprintf(rows[1], MENU_ROW_CHARS + 1, "%u %.22s", item, name ? name : "");
    } else if (item == reset_item(c)) snprintf(rows[1], MENU_ROW_CHARS + 1, "Factory reset...");
    else snprintf(rows[1], MENU_ROW_CHARS + 1, "Exit menu");
    snprintf(rows[3], MENU_ROW_CHARS + 1, "Short: next  Hold: select");
}

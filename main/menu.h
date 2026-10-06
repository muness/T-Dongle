// SPDX-License-Identifier: MIT
#pragma once
/* The button menu (v0.1.1 semantics, one button).
 *
 *   short press, menu closed   next screen page (the caller does that; the menu does not consume it)
 *   hold 1.5 s, menu closed    open the menu at its first item
 *   short press, menu open     next item (wraps), and cancels a pending factory-reset confirmation
 *   hold, menu open            run the item, then close the menu, except Factory reset, which asks for confirmation
 *   hold again within 10 s     confirm the factory reset (anything else, or the time running out, cancels it)
 *
 * Items, in order: 0 Enter setup AP (Cancel setup AP while setup is running); 1..N the saved networks (switch to it);
 * Factory reset; Exit menu. v0.1.1 listed all eight slots with "(empty) add" for the free ones; the unified store keeps the
 * networks in a packed list, so a free slot is just "Enter setup AP" and is not listed again.
 *
 * The menu only decides. What an item does is returned as an action for the caller to run through the serial command layer
 * (`setup`, `cancel`, `use N`, `reset`, `confirm-reset`), so a button and a terminal can never disagree. Pure C, host tested
 * (tests/test_menu.c). */
#include <stdbool.h>
#include <stdint.h>

enum { MENU_CONFIRM_MS = 10000, MENU_ROW_CHARS = 26, MENU_ROWS = 5 };
typedef enum { MENU_EVENT_SHORT, MENU_EVENT_HOLD } menu_event;
typedef enum { MENU_ACTION_NONE, MENU_ACTION_SETUP, MENU_ACTION_CANCEL_SETUP, MENU_ACTION_USE, MENU_ACTION_RESET, MENU_ACTION_CONFIRM_RESET } menu_action_kind;
typedef struct { menu_action_kind kind; unsigned slot; /* MENU_ACTION_USE: 1-based saved network */ } menu_action;

typedef struct { bool open; unsigned item; bool confirm; uint32_t confirm_until_ms; } menu_state;
typedef struct { bool setup_active; unsigned saved_count; /* 0 to 8 */ } menu_context;

void menu_init(menu_state *m);
unsigned menu_item_count(const menu_context *c);
/* Feed a button event. Returns true when the menu consumed it (it was open, or this event opened it); *action is then what to
 * run (MENU_ACTION_NONE for most). Returns false for a short press with the menu closed. */
bool menu_event_handle(menu_state *m, const menu_context *c, menu_event event, uint32_t now_ms, menu_action *action);
/* Call regularly: a confirmation that was not given in time is cancelled (the menu stays open on Factory reset). */
void menu_tick(menu_state *m, uint32_t now_ms);
/* The text of the open menu, MENU_ROWS rows of at most MENU_ROW_CHARS characters; the first is the title. network_name(slot)
 * returns the display name of saved network `slot` (1-based). */
void menu_render(const menu_state *m, const menu_context *c, const char *(*network_name)(void *ctx, unsigned slot), void *ctx,
                 char rows[MENU_ROWS][MENU_ROW_CHARS + 1]);

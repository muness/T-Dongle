#pragma once
#include <stdbool.h>
#include <stdint.h>
/* Same policy in firmware and fault-injection tests. A new binary gets one
 * attempt. A failed attempt never auto-starts tailnets on the next boot. */
static inline bool boot_should_recover(bool same_build, bool unfinished,
                                      bool crash, bool latched) {
    return same_build && (unfinished || crash || latched);
}

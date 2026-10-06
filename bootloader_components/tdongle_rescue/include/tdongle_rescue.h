// SPDX-License-Identifier: MIT
// Lockout rescue protocol shared by the bootloader and any app that opts in (the Rust port).
//
// The T-Dongle's only console is the app's own USB (OTG). An app that hangs or reset-loops
// therefore leaves no software way back into ROM download mode. The bootloader breaks that:
// an app opts in by writing ARMED into RTC_CNTL_STORE0 at start and HEALTHY once it has proven
// itself (its console task and data path made progress for a while with USB configured). The
// bootloader counts consecutive boots that ended without HEALTHY (any reset that keeps the RTC
// domain: watchdog, panic, software) and after TDONGLE_RESCUE_LIMIT of them boots the ROM
// download mode instead of the app. Power-on clears everything. Apps that never write the word
// (the C firmware) are unaffected.
#pragma once
#define TDONGLE_RESCUE_MAGIC   0xD0E5u
#define TDONGLE_RESCUE_ARMED   0xA5u
#define TDONGLE_RESCUE_HEALTHY 0x0Cu
#define TDONGLE_RESCUE_LIMIT   2u
// The RTC watchdog the bootloader leaves armed for the app start (reset the digital core only; the app re-arms it with its own timeout).
#define TDONGLE_RESCUE_WDT_MS  30000u
// word = MAGIC << 16 | state << 8 | consecutive unhealthy boots
#define TDONGLE_RESCUE_WORD(state, count) ((TDONGLE_RESCUE_MAGIC << 16) | ((state) << 8) | ((count) & 0xFFu))

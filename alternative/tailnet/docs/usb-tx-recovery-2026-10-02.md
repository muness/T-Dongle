# USB transmit ownership crash

## Evidence and mechanism

The saved Android v122 report identifies a panic in the `TinyUSB` task on firmware 0.2.13. Its full ELF SHA matches the archived binary, and its intact backtrace reaches a TLSF heap assertion through `usb_free_tx`, `tud_network_xmit_cb`, `tud_network_xmit` and `do_send_sync`. This is a different failure from the preceding DNS stack overflow. The [sanitized report](v122-usb-tx-crash-2026-10-02.json) retains the boot state and trace without credentials or network identities. Recovery latched and management remained readable.

The wrapper queues callbacks referring to one shared synchronous-send slot. A timed-out call cancels that slot, but its callback remains in the TinyUSB event queue. If a new send publishes its packet before the old callback runs, the old callback consumes the new packet. Before this fix, the new callback could then consume and release that same packet a second time before its waiting caller resumed. The host regression reproduces a heap use-after-free in the actual wrapper, using the gateway's allocation/release contract. The captured device trace identifies the failing release path but cannot independently prove this exact scheduling history.

## Correction in 0.2.14

While holding the existing semaphore, `do_send_sync` takes the current packet and clears the shared slot before entering TinyUSB's synchronous copy/free callback. Subsequent callbacks find no packet and release the semaphore before returning. A callback is a wakeup to consume available work, not ownership of the currently published buffer. A failed send still leaves its payload with the caller. A successful copy racing the timeout still returns success after the caller waits for the semaphore; reverting that earlier behavior would restore a second double-free path.

There is no new task, queue, heap allocation or persistent RAM cost. Synchronous callers must remain serialized, as documented in the API. The gateway sends through lwIP under its core lock; the original bridge uses one transmit worker. Driver deinitialization is outside active sends, as before. The unused async path is unchanged. Flash offsets, saved identities, Wi-Fi settings, peerstore and crash partitions are unchanged.

## Execution and review

The aim is to remove the observed USB ownership failure and deliver an installable firmware bundle while preserving management recovery. The correction remains bounded to the driver, regression coverage and firmware version. Review found no reason to change routing or enrollment architecture for this trace.

| Risk | Evidence | Incorrect patch rejected |
|---|---|---|
| A queued timeout callback consumes the next packet twice | Actual wrapper under ASan/UBSan; allocated payloads, 1–7 delayed callbacks, 1,000 repetitions per schedule | Retaining only the previous timeout-result fix; the old source fails with heap use-after-free |
| Clearing the slot leaves the semaphore locked | The same backlogged callbacks execute before the waiting caller resumes | Clearing the slot but returning on null without giving the semaphore; this mutation fails the scheduler's blocking assertion |
| Completion races the timeout | Callback begins after event wait expires, including stale backlog | Returning timeout after a completed copy; caller would free the already released buffer |
| USB backpressure releases an unconsumed payload | Busy transmit with delayed callbacks followed by successful sends | Freeing on failure or replaying the canceled packet |
| Test passes without exercising shipping code | Test replaces includes only; production wrapper function bodies compile unchanged, and the gateway build now runs this check | A duplicate model or a test omitted from the alternative firmware pipeline |
| Hardware routing remains broken for another reason | Accepted boundary: sustained Android-to-peer HTTP traffic requires the physical dongle | Treating a connected screen, host regression or completed build as proof of routed traffic |

The focused regression completes 112,005 allocated-buffer sends (21,003 callback releases and 91,002 caller releases) without sanitizer findings. The original bridge host suite and the full gateway checks run for this build. Final packaging uses isolated committed trees because unrelated UI/LCD work is in progress in the shared checkouts. No physical flash or erase is performed by the agent.

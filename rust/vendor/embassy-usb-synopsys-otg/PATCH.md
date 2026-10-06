# embassy-usb-synopsys-otg 0.4.0, patched for multi-packet bulk OUT transfers

Vendored from crates.io (`embassy-usb-synopsys-otg` 0.4.0) and used through `[patch.crates-io]` in the no_std spikes. Everything changed is marked `PATCH` in `src/lib.rs`;
the pure logic is `rust/crates/tdongle-usb-out` (host-tested against a model of the core). Upstream-able: `embassy_usb_driver::EndpointOut::read_transfer` (embassy #2753) already exists with a default that reads packet by packet; this driver overrides it with whole-transfer reads, and adds `read_chunk`, which also says whether a short packet ended the chunk (needed to find the end of an NTB that is a multiple of MPS).

Why: S2 on the board (`sink`) showed OUT capped at 4.6 Mbit/s whatever the host offered, against 7.41 Mbit/s for IN. The stock driver arms every OUT endpoint for one packet
(`PKTCNT = 1`, `XFRSIZ = MPS`) and re-arms from the task that read it, so the endpoint NAKs between packets.

What: `Config::out_transfer_bytes[ep]` (default 0 = stock) arms a bulk OUT endpoint for a whole buffer (`PKTCNT = bytes / MPS`, `XFRSIZ = bytes`). The interrupt appends each packet
from the RX FIFO into the endpoint's buffer and, on the core's "OUT transfer completed" status, publishes the chunk (length, and whether a short packet ended it). The task reads it with
`Endpoint::read_chunk` (and `EndpointOut::read_transfer`, the upstream hook, is overridden to use it) and re-arms. Nothing is armed while the class is not reading, so the host is NAKed (backpressure is kept). `EndpointOut::read` keeps working on such an endpoint (it returns the
bytes, not the short flag). `ep_out_buffer` must hold `out_transfer_bytes` for that endpoint.

Not done: DMA mode (the esp-hal OTG setup never sets `GAHBCFG.DMAEN`; the C firmware's TinyUSB does). Slave mode with a whole-NTB transfer removes the per-packet NAK; DMA would remove the interrupt per packet.

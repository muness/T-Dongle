//! Fixed limits shared by the data path (`ml_gateway_limits.h`, `microlink_internal.h`, `usb_rx_budget.h`).

/// `ML_GATEWAY_PLAIN_BYTES`: the gateway control-plane plaintext workspace, static, shared by every membership, never heap.
pub const ML_GATEWAY_PLAIN_BYTES: usize = 20480 + 16;
/// `ML_GATEWAY_JSON_BYTES`: the control-plane JSON workspace.
pub const ML_GATEWAY_JSON_BYTES: usize = 16384;
/// `ML_WG_RX_QUEUE_DEPTH`: the slot count bound of the WireGuard receive queue (the byte bound is [`crate::wg_rx::ML_WG_RX_QUEUE_BYTES`]).
pub const ML_WG_RX_QUEUE_DEPTH: usize = 12;
/// `ML_JIT_PENDING`: packets pending a peer handshake, per membership.
pub const ML_JIT_PENDING: usize = 8;
/// `ML_JIT_PACKET_MAX`.
pub const ML_JIT_PACKET_MAX: usize = 1400;
/// `ML_NET_IO_DEEP`: a drain this deep means the UDP mailbox was within two datagrams of overflowing.
pub const ML_NET_IO_DEEP: u32 = 4;
/// `ML_NET_IO_DRAIN_CAP`: datagrams per socket per pass.
pub const ML_NET_IO_DRAIN_CAP: u32 = 16;
/// `CONFIG_LWIP_UDP_RECVMBOX_SIZE` (sdkconfig.defaults) the budget is checked against.
pub const CONFIG_LWIP_UDP_RECVMBOX_SIZE: u32 = 6;
const _: () =
    assert!(CONFIG_LWIP_UDP_RECVMBOX_SIZE <= crate::heap::ML_HB_PIN_BUFFERS, "a UDP socket mailbox can pin more Wi-Fi RX buffers than the heap budget allows");
const _: () = assert!(ML_NET_IO_DRAIN_CAP >= CONFIG_LWIP_UDP_RECVMBOX_SIZE, "a full mailbox is emptied in one drain");

/* Compile with the microlink.c command line from build-bytes/compile_commands.json plus -g -c, then
 *   xtensa-esp32s3-elf-gdb -batch -ex 'ptype /o struct microlink_s' probe.o
 * The tables below are also printed as constants so they can be read with nm --size-sort. */
#include "microlink_internal.h"
#include "ml_directory.h"
#include "ml_runtime.h"
const unsigned sz_microlink = sizeof(microlink_t);
const unsigned sz_peer = sizeof(ml_peer_t);
const unsigned sz_derp_conn = sizeof(ml_derp_conn_t);
const unsigned sz_probe = sizeof(ml_disco_probe_t);
const unsigned sz_directory = sizeof(ml_directory_t);
const unsigned sz_region = sizeof(ml_derp_region_t);
const unsigned sz_config = sizeof(microlink_config_t);
const unsigned sz_wgloop = sizeof(ml_wg_loop_t);
const unsigned sz_published = sizeof(ml_published_name_t);
const microlink_t *keep;
const unsigned sz_rx_packet = sizeof(ml_rx_packet_t);
const unsigned sz_derp_tx_item = sizeof(ml_derp_tx_item_t);
const unsigned sz_coord_cmd = sizeof(ml_coord_cmd_t);
const unsigned sz_peer_update = sizeof(ml_peer_update_t);
const unsigned q_derp = ML_DERP_TX_QUEUE_DEPTH, q_disco = ML_DISCO_RX_QUEUE_DEPTH, q_wg = ML_WG_RX_QUEUE_DEPTH,
               q_stun = ML_STUN_RX_QUEUE_DEPTH, q_cmd = ML_COORD_CMD_QUEUE_DEPTH, q_upd = ML_PEER_UPDATE_QUEUE_DEPTH;
const unsigned sz_staticqueue = sizeof(StaticQueue_t), sz_statictask = sizeof(StaticTask_t);

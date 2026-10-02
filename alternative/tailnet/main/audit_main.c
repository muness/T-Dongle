/* Compile-time measurement only: does not start networking or enroll a node. */
#include <stdio.h>
#include "microlink_internal.h"
const uint32_t tailnet_audit_metrics[] = {
    sizeof(microlink_t), sizeof(ml_peer_t),
    ML_TASK_NET_IO_STACK + 2 * ML_TASK_DERP_TX_STACK + ML_TASK_COORD_STACK + ML_TASK_WG_MGR_STACK,
    ML_H2_BUFFER_SIZE, ML_JSON_BUFFER_SIZE,
    ML_DERP_TX_QUEUE_DEPTH * sizeof(ml_derp_tx_item_t) +
    (ML_DISCO_RX_QUEUE_DEPTH + ML_WG_RX_QUEUE_DEPTH + ML_STUN_RX_QUEUE_DEPTH) * sizeof(ml_rx_packet_t) +
    ML_COORD_CMD_QUEUE_DEPTH * sizeof(ml_coord_cmd_t) +
    ML_PEER_UPDATE_QUEUE_DEPTH * sizeof(ml_peer_update_t *),
    sizeof(ml_peer_update_t)
};
void app_main(void) {
    puts("AUDIT ONLY: no USB gateway, no tailnet enrollment, no credentials.");
    for (unsigned i = 0; i < sizeof(tailnet_audit_metrics) / sizeof(tailnet_audit_metrics[0]); ++i)
        printf("audit[%u]=%lu\n", i, (unsigned long)tailnet_audit_metrics[i]);
}

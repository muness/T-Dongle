#pragma once
/* Gateway control-plane workspaces: static, shared by every membership, never heap. */
#define ML_GATEWAY_PLAIN_BYTES  (20480 + 16)
#define ML_GATEWAY_JSON_BYTES   16384

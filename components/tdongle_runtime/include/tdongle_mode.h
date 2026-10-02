#pragma once
#include <stdbool.h>
#include <string.h>
typedef enum {TDONGLE_WIFI_BRIDGE=0,TDONGLE_TAILNET_GATEWAY=1} tdongle_mode;
static inline const char *tdongle_mode_name(tdongle_mode m){return m==TDONGLE_WIFI_BRIDGE?"wifi_bridge":"tailnet_gateway";}
static inline bool tdongle_mode_parse(const char *name,tdongle_mode *out){if(!name)return false;if(!strcmp(name,"wifi_bridge"))*out=TDONGLE_WIFI_BRIDGE;else if(!strcmp(name,"tailnet_gateway"))*out=TDONGLE_TAILNET_GATEWAY;else return false;return true;}

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../main/boot_health.h"
#include "../main/boot_policy.h"
#define ESP_FAIL -1
static bool tailnet=true;static bool gateway_tailnet_mode(void){return tailnet;}
static unsigned fail_at, seen[BOOT_STAGE_COUNT], sequence, failed, complete, usb_alive;
static bool recovery;
#define STAGE(name,code) static int start_##name(void){assert(code==BOOT_USB || usb_alive);seen[code]=++sequence;if(code==BOOT_USB && code!=fail_at)usb_alive=1;return code==fail_at?-1:0;}
STAGE(usb,BOOT_USB) STAGE(settings,BOOT_SETTINGS) STAGE(network,BOOT_NETWORK)
STAGE(http,BOOT_HTTP) STAGE(directory,BOOT_DIRECTORY) STAGE(routes,BOOT_ROUTES)
STAGE(display,BOOT_DISPLAY) STAGE(wifi,BOOT_WIFI) STAGE(dns,BOOT_DNS) STAGE(manager,BOOT_MANAGER)
static bool start_step(unsigned stage,int(*start)(void)){int result=start();if(stage==BOOT_USB && !result)usb_alive=1;if(result)failed=stage;return !result;}
void gateway_boot_begin(void){assert(usb_alive);}
void gateway_boot_result(unsigned stage,int error){if(error)failed=stage;}
bool gateway_boot_recovery(void){return recovery;}
void gateway_boot_complete(void){complete++;}
#include "../main/startup_sequence.inc"
int main(void) {
    for(unsigned fault=0;fault<BOOT_STAGE_COUNT;fault++) {
        if(fault==BOOT_USB || fault==BOOT_RUNNING)continue; // physical USB failure cannot provide USB recovery
        memset(seen,0,sizeof(seen));sequence=complete=failed=usb_alive=0;fail_at=fault;
        gateway_startup_sequence();assert(complete==1 && usb_alive && seen[BOOT_USB]==1);
        assert(!fault || failed==fault);
        if(fault==BOOT_SETTINGS || fault==BOOT_WIFI)assert(!seen[BOOT_MANAGER]);
        if(fault==BOOT_DIRECTORY || fault==BOOT_ROUTES)assert(seen[BOOT_MANAGER]); // Wi-Fi recovery remains alive; start_member independently gates routes.
        if(fault!=BOOT_NETWORK)assert(seen[BOOT_HTTP]);
        if(fault==BOOT_NETWORK)assert(!seen[BOOT_HTTP] && !seen[BOOT_WIFI]);
        if(fault==BOOT_HTTP)assert(seen[BOOT_MANAGER]); // HTTP isn't a routing dependency
    }
    tailnet=false;memset(seen,0,sizeof(seen));fail_at=0;gateway_startup_sequence();assert(!seen[BOOT_HTTP] && !seen[BOOT_DNS] && !seen[BOOT_DIRECTORY] && !seen[BOOT_ROUTES] && seen[BOOT_WIFI] && seen[BOOT_MANAGER]);tailnet=true;
    memset(seen,0,sizeof(seen));sequence=complete=failed=usb_alive=0;recovery=true;fail_at=0;
    gateway_startup_sequence();assert(seen[BOOT_HTTP] && !seen[BOOT_DIRECTORY] && !seen[BOOT_WIFI] && !seen[BOOT_MANAGER]);
    for(unsigned same=0;same<2;same++)for(unsigned pending=0;pending<2;pending++)
    for(unsigned crash=0;crash<2;crash++)for(unsigned latch=0;latch<2;latch++)
        assert(boot_should_recover(same,pending,crash,latch)==(same && (pending||crash||latch)));
    puts("Startup: every optional stage failure retains USB, dependencies fail closed, crash recovery skips automatic tailnet activation");
}

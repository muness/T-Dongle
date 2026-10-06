#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../main/boot_health.h"
#include "../main/boot_policy.h"
#define ESP_FAIL -1
static bool tailnet=true,setup_active;static bool gateway_tailnet_mode(void){return tailnet;}
static unsigned fail_at, seen[BOOT_STAGE_COUNT], sequence, failed, complete, usb_alive;
static bool recovery,recovery_after_settings;
#define STAGE(name,code) static int start_##name(void){assert(code==BOOT_USB || usb_alive);seen[code]=++sequence;if(code==BOOT_USB && code!=fail_at)usb_alive=1;return code==fail_at?-1:0;}
STAGE(usb,BOOT_USB) STAGE(settings,BOOT_SETTINGS) STAGE(network,BOOT_NETWORK)
STAGE(http,BOOT_HTTP) STAGE(directory,BOOT_DIRECTORY) STAGE(routes,BOOT_ROUTES)
STAGE(display,BOOT_DISPLAY) STAGE(setup,BOOT_SETUP) STAGE(wifi,BOOT_WIFI) STAGE(dns,BOOT_DNS) STAGE(manager,BOOT_MANAGER)
static bool start_step(unsigned stage,int(*start)(void)){int result=start();if(stage==BOOT_USB && !result)usb_alive=1;if(result)failed=stage;return !result;}
void gateway_boot_begin(void){assert(usb_alive);}
void gateway_boot_result(unsigned stage,int error){if(error)failed=stage;}
bool gateway_boot_recovery(void){return recovery || (recovery_after_settings && seen[BOOT_SETTINGS]);}
void gateway_boot_complete(void){complete++;}
#include "../main/startup_sequence.inc"
int main(void) {
    for(unsigned fault=0;fault<BOOT_STAGE_COUNT;fault++) {
        if(fault==BOOT_USB || fault==BOOT_RUNNING || fault==BOOT_SETUP)continue; // physical USB failure cannot provide USB recovery; the setup stage runs only in a setup boot (below)
        memset(seen,0,sizeof(seen));sequence=complete=failed=usb_alive=0;fail_at=fault;
        gateway_startup_sequence();assert(complete==1 && usb_alive && seen[BOOT_USB]==1);
        assert(!fault || failed==fault);
        assert(!seen[BOOT_SETUP]);   /* a normal boot never starts the access point */
        if(fault==BOOT_SETTINGS || fault==BOOT_WIFI)assert(!seen[BOOT_MANAGER]);
        if(fault==BOOT_DIRECTORY || fault==BOOT_ROUTES)assert(seen[BOOT_MANAGER]); // Wi-Fi recovery remains alive; start_member independently gates routes.
        if(fault!=BOOT_NETWORK)assert(seen[BOOT_HTTP]);
        if(fault==BOOT_NETWORK)assert(!seen[BOOT_HTTP] && !seen[BOOT_WIFI]);
        if(fault==BOOT_HTTP)assert(seen[BOOT_MANAGER]); // HTTP isn't a routing dependency
    }
    tailnet=false;memset(seen,0,sizeof(seen));fail_at=0;gateway_startup_sequence();assert(!seen[BOOT_HTTP] && !seen[BOOT_DNS] && !seen[BOOT_DIRECTORY] && !seen[BOOT_ROUTES] && seen[BOOT_WIFI] && seen[BOOT_MANAGER]);tailnet=true;
    memset(seen,0,sizeof(seen));sequence=complete=failed=usb_alive=0;recovery=true;fail_at=0;
    gateway_startup_sequence();assert(seen[BOOT_HTTP] && !seen[BOOT_DIRECTORY] && !seen[BOOT_WIFI] && !seen[BOOT_MANAGER]);
    /* A setup boot (ADR 0024): the HTTP server, the display and the access point, and none of the bridge, tailnet, DNS or manager stages,
     * in either mode, whatever mode was saved. */
    recovery=false;
    for(unsigned mode=0;mode<2;mode++){
        tailnet=mode;setup_active=true;memset(seen,0,sizeof(seen));sequence=complete=failed=usb_alive=0;fail_at=0;
        gateway_startup_sequence();
        assert(complete==1 && usb_alive && seen[BOOT_HTTP] && seen[BOOT_DISPLAY] && seen[BOOT_SETUP] && setup_active);
        assert(!seen[BOOT_WIFI] && !seen[BOOT_DNS] && !seen[BOOT_DIRECTORY] && !seen[BOOT_ROUTES] && !seen[BOOT_MANAGER]);   /* nothing that could start a tailnet or the bridge */
        assert(seen[BOOT_SETUP]>seen[BOOT_NETWORK] && seen[BOOT_SETUP]>seen[BOOT_SETTINGS]);   /* after the settings and the network layer it needs */
        /* Every optional stage may fail: USB management stays, and a failed access point does not stop the others. */
        for(unsigned fault=0;fault<BOOT_STAGE_COUNT;fault++){
            if(fault==BOOT_USB || fault==BOOT_RUNNING || fault==BOOT_DIRECTORY || fault==BOOT_ROUTES || fault==BOOT_WIFI || fault==BOOT_DNS || fault==BOOT_MANAGER)continue;   /* not run in a setup boot */
            setup_active=true;memset(seen,0,sizeof(seen));sequence=complete=failed=usb_alive=0;fail_at=fault;
            gateway_startup_sequence();assert(complete==1 && usb_alive && seen[BOOT_USB]==1 && (!fault || failed==fault));
            assert(!seen[BOOT_MANAGER] && !seen[BOOT_WIFI] && !seen[BOOT_DNS]);
            if(fault==BOOT_NETWORK)assert(!seen[BOOT_HTTP] && !seen[BOOT_SETUP]);   /* no network layer: no server and no access point */
            if(fault==BOOT_SETTINGS)assert(!seen[BOOT_SETUP]);                       /* nothing saved can be shown or edited */
            if(fault==BOOT_SETUP)assert(seen[BOOT_HTTP] && seen[BOOT_DISPLAY]);
        }
    }
    /* Recovery outranks a setup request: a crash loop starts no new radio stack. The latch can also appear while the settings load. */
    tailnet=false;fail_at=0;
    recovery=true;setup_active=true;memset(seen,0,sizeof(seen));gateway_startup_sequence();assert(!setup_active && !seen[BOOT_SETUP] && !seen[BOOT_WIFI]);
    recovery=false;recovery_after_settings=true;setup_active=true;memset(seen,0,sizeof(seen));gateway_startup_sequence();assert(!setup_active && !seen[BOOT_SETUP] && !seen[BOOT_WIFI]);
    recovery_after_settings=false;tailnet=true;
    for(unsigned same=0;same<2;same++)for(unsigned pending=0;pending<2;pending++)
    for(unsigned crash=0;crash<2;crash++)for(unsigned latch=0;latch<2;latch++)
        assert(boot_should_recover(same,pending,crash,latch)==(same && (pending||crash||latch)));
    puts("Startup: every optional stage failure retains USB, dependencies fail closed, crash recovery skips automatic tailnet activation");
}

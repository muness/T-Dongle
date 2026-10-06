/* The serial commands of the front panel (serial_setup.inc, the real code): setup, cancel, reset, confirm-reset, display, use, profile, list
 * and the new `status` lines, against the same in-memory store as test_wifi_profiles.c. The button menu runs these same commands. */
#include "host_store.h"
#include <ctype.h>
#include "../main/wifi_link.h"
#include "../main/clock_sync.h"
#include "tdongle_temperature.h"
#include "tdongle_mode.h"
#include "../../../main/setup_boot.h"
#include "../../../main/traffic.h"
#define GATEWAY_VERSION "9.9.9-test"
#define vTaskDelay(x) ((void)(x))
static unsigned restarts;static setup_request restart_request;static unsigned restart_slot;
static bool setup_active,recovery,tailnet;static unsigned setup_preselect;static char setup_ap_name[16]="TDongle-AB0CF9";static setup_session setup_clock;
static void setup_restart(setup_request r,unsigned slot){restarts++;restart_request=r;restart_slot=slot;}   /* the firmware's does not return */
static void esp_restart(void){restarts++;}
static bool gateway_boot_recovery(void){return recovery;}
static bool gateway_tailnet_mode(void){return tailnet;}
static char out[32768];
void mgmt_write(const char *s){strlcat(out,s,sizeof(out));}
tdongle_temperature tdongle_temperature_snapshot(void){return (tdongle_temperature){.valid=true,.current_tenths=553,.peak_tenths=600};}
static wifi_link_events wifi_link_stats;
static wifi_link_info wifi_link_read(void){return (wifi_link_info){.connected=online,.rssi_valid=online,.rssi=-61,.selected_slot=(uint8_t)(wifi_current+1)};}
static bool tud_mounted(void){return true;}static bool tud_ready(void){return true;}
static unsigned long esp_get_free_heap_size(void){return 100000;}
static bool ml_derp_clock_valid(void){return false;}
static gw_clock_t sntp_clock;
unsigned tdongle_memory_count(void){return 0;}
tdongle_memory_record tdongle_memory_get(unsigned i){(void)i;return (tdongle_memory_record){0};}
static int tdongle_mode_save(int handle,tdongle_mode m){(void)handle;(void)m;return 0;}
static struct {unsigned page;struct {uint32_t down_kbps,up_kbps;} traffic;} ui={.page=2};
static unsigned gateway_usb_health(unsigned i){return i==8?3:0;}
#include "serial_setup.inc"

static const char *run(const char *line){out[0]=0;bool handled=gateway_serial_command(line);if(!handled)return NULL;return out;}
static bool says(const char *text){return strstr(out,text)!=NULL;}
static void fresh(void){reset_world();restarts=0;setup_active=recovery=tailnet=false;setup_preselect=0;factory_reset_armed=false;ui.page=2;out[0]=0;}
static void v011_slot(settings_t *o,unsigned slot,const char *name,const char *ssid,const char *pass,unsigned priority){strcpy(o->p[slot].name,name);strcpy(o->p[slot].ssid,ssid);strcpy(o->p[slot].pass,pass);o->p[slot].priority=(uint8_t)priority;}
static void save(const char *ssid,const char *name,int priority){assert(wifi_save_with(ssid,"password1",name,priority,false,-1));}

static void display_command(void){
 fresh();
 assert(run("display") && says("display brightness=60 rotation=0 dim_seconds=60\r\n"));
 assert(run("display 85 1 300") && says("OK display saved") && display_settings.brightness==85 && display_settings.rotation==1 && display_settings.dim_seconds==300);
 forget_ram();display_load();assert(display_settings.brightness==85 && display_settings.dim_seconds==300);   /* remembered */
 assert(run("display") && says("brightness=85 rotation=1 dim_seconds=300"));
 const char *bad[]={"display 4 0 60","display 101 0 60","display 60 2 60","display 60 0 9","display 60 0 3601","display 60","display 60 0","display 60 0 60 1","display x 0 60","display 60 0 60x","display  ","display -5 0 60"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){assert(run(bad[i]) && says("ERR display: brightness 5..100 rotation 0|1 dim 10..3600 seconds") && display_settings.brightness==85 && display_settings.rotation==1 && display_settings.dim_seconds==300);}
 fail_write=true;assert(run("display 20 0 20") && says("ERR Storage save failed") && display_settings.brightness==85);fail_write=false;   /* a failed write changes nothing */
 assert(!run("displays") && !run("displayX 1 2 3"));   /* only the command itself */
 /* v0.1.1 users: the settings they had are what `display` shows until they change them. */
 fresh();settings_t o;memset(&o,0,sizeof(o));o.version=CFG_VERSION;o.brightness=35;o.rotation=1;o.dim_seconds=900;old_settings=o;have_old=true;display_load();
 assert(run("display") && says("brightness=35 rotation=1 dim_seconds=900"));
}
static void setup_command(void){
 fresh();
 assert(run("setup") && says("OK restarting into setup") && restarts==1 && restart_request==SETUP_REQUEST_ENTER && restart_slot==0);
 fresh();assert(run("setup 3") && restarts==1 && restart_request==SETUP_REQUEST_ENTER && restart_slot==3);
 fresh();assert(run("setup 8") && restart_slot==8);
 const char *bad[]={"setup 0","setup 9","setup x","setup 2x","setup -1","setup "};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){fresh();assert(run(bad[i]) && says("ERR setup:") && restarts==0);}
 fresh();recovery=true;assert(run("setup") && says("ERR Setup is not available in recovery mode") && restarts==0);   /* a crash loop starts no radio stack */
 fresh();setup_active=true;assert(run("setup 2") && says("OK setup already open") && setup_preselect==2 && restarts==0);
 fresh();tailnet=true;assert(run("setup") && restarts==1 && restart_request==SETUP_REQUEST_ENTER);   /* both modes */
}
static void cancel_command(void){
 fresh();assert(run("cancel") && says("OK setup saved") && restarts==0);   /* clients send it after `profile`: still a no-op outside setup */
 fresh();setup_active=true;assert(run("cancel") && says("OK leaving setup") && restarts==1 && restart_request==SETUP_REQUEST_LEAVE);
}
static void factory_reset_command(void){
 fresh();
 settings_t o;memset(&o,0,sizeof(o));o.version=CFG_VERSION;o.brightness=70;o.dim_seconds=60;v011_slot(&o,0,"Home","HomeNet","password1",60);old_settings=o;have_old=true;
 assert(wifi_load_profiles() && wifi_saved.count==1);save("Work","Work",70);display_save(&(ui_settings){40,1,120});
 uint8_t mode=1;assert(nvs_set_blob(1,"mode",&mode,1)==0 && nvs_set_blob(1,"members",&mode,1)==0);
 /* Two steps: nothing happens on the first. */
 assert(run("confirm-reset") && says("ERR reset confirmation expired") && wifi_saved.count==2 && restarts==0);   /* not armed */
 test_time=5000000;
 assert(run("reset") && says("Confirm within 10 seconds: confirm-reset") && wifi_saved.count==2 && restarts==0 && factory_reset_armed);
 test_time+=9999000;   /* still inside the 10 seconds */
 assert(run("confirm-reset") && says("OK factory reset; restarting into setup") && restarts==1 && restart_request==SETUP_REQUEST_ENTER && restart_slot==0);
 assert(wifi_saved.count==0 && find("wifi_profiles")<0 && find("wifi_meta")<0 && find("display")<0 && old_erased && !have_old && display_settings.brightness==60 && find("mode")>=0 && find("members")>=0);
 /* One reset, one confirmation. */
 assert(run("confirm-reset") && says("ERR reset confirmation expired") && restarts==1);
 /* Too late. */
 fresh();save("Home","Home",-1);test_time=1000000;assert(run("reset"));test_time+=10000000;
 assert(run("confirm-reset") && says("ERR reset confirmation expired") && wifi_saved.count==1 && restarts==0 && !factory_reset_armed);
 /* The clock wrapping inside the window does not make an old reset live. */
 fresh();save("Home","Home",-1);test_time=(int64_t)0xfffffff0u*1000;assert(run("reset"));test_time+=5000000;assert(run("confirm-reset") && restarts==1);
 /* Asking again re-arms with a fresh 10 seconds. */
 fresh();save("Home","Home",-1);test_time=1000000;run("reset");test_time+=8000000;run("reset");test_time+=8000000;assert(run("confirm-reset") && restarts==1);
 /* A failure to erase is reported; the dongle does not restart into a half-reset state. */
 fresh();save("Home","Home",-1);run("reset");fail_erase=true;assert(run("confirm-reset") && says("ERR Factory reset failed") && restarts==0 && wifi_saved.count==1 && !factory_reset_armed);
 /* The same in a setup boot and in tailnet mode. */
 fresh();setup_active=true;tailnet=true;save("Home","Home",-1);run("reset");assert(run("confirm-reset") && restarts==1 && wifi_saved.count==0);
}
static void use_command(void){
 fresh();save("Home","Home",50);save("Work","Work",60);save("Cafe","Cafe",70);
 assert(run("use 2") && says("OK switching to 2\r\n") && wifi_pinned.slot==1 && wifi_current==1 && wifi_meta.preferred==1);   /* pinned for the session AND preferred for good */
 forget_ram();assert(wifi_load_profiles() && wifi_meta.preferred==1);                                                          /* kept across a restart */
 assert(run("use 3") && wifi_meta.preferred==2 && wifi_pinned.slot==2);
 fail_write=true;assert(run("use 1") && says("OK switching to 1 (preference not saved)") && wifi_pinned.slot==0 && wifi_meta.preferred==2);fail_write=false;   /* the switch still happens */
 const char *bad[]={"use 0","use 4","use x","use 1x","use -1","use "};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){unsigned before=wifi_revision;int preferred=wifi_meta.preferred;assert(run(bad[i]) && says("ERR Invalid saved network") && wifi_revision==before && wifi_meta.preferred==preferred);}
 reject_config=true;assert(run("use 1") && says("ERR Wi-Fi driver refused the network") && wifi_meta.preferred==2);reject_config=false;   /* a refused join does not become the preference */
 wifi_ready=false;assert(run("use 1") && says("ERR Invalid saved network"));wifi_ready=true;
 /* Not while setup is open: the radio belongs to the access point. */
 setup_active=true;unsigned before=wifi_revision,joined=joins;int pin=wifi_pinned.slot,preferred=wifi_meta.preferred;
 assert(run("use 1") && says("ERR Not available while setup is open") && wifi_revision==before && wifi_pinned.slot==pin && wifi_meta.preferred==preferred && joins==joined);
 setup_active=false;
}
static void profile_and_list(void){
 fresh();
 assert(run("profile {\"slot\":1,\"priority\":80,\"name\":\"Home sweet\",\"ssid\":\"HomeNet\",\"password\":\"secret-pass\"}") && says("OK saved to slot 1"));
 assert(run("profile {\"slot\":2,\"priority\":10,\"name\":\"Car\",\"ssid\":\"CarWifi\",\"password\":\"\"}") && says("OK saved to slot 2"));
 assert(run("list") && !strcmp(out,"1 name=Home sweet ssid=HomeNet priority=80\r\n2 name=Car ssid=CarWifi priority=10\r\n"));   /* the v0.1.1 line format, with the real name and priority */
 wifi_current=1;assert(run("list") && says("2* name=Car"));
 assert(run("profile {\"slot\":9,\"priority\":10,\"name\":\"Car\",\"ssid\":\"x\",\"password\":\"\"}") && says("ERR"));
 assert(run("profile {\"slot\":5,\"priority\":10,\"name\":\"Gap\",\"ssid\":\"gap\",\"password\":\"\"}") && says("ERR Refresh saved networks before editing") && wifi_saved.count==2);   /* no gaps in a packed list */
 assert(run("profile {\"slot\":3,\"priority\":101,\"name\":\"Bad\",\"ssid\":\"bad\",\"password\":\"\"}") && says("ERR") && wifi_saved.count==2);
 assert(run("profile {\"slot\":1,\"priority\":55,\"name\":\"Renamed\",\"ssid\":\"HomeNet\",\"password\":\"secret-pass\"}") && wifi_meta.slot[0].priority==55 && !strcmp(wifi_meta.slot[0].name,"Renamed"));
 assert(run("del 1") && says("OK deleted") && wifi_saved.count==1 && !strcmp(wifi_meta.slot[0].name,"Car") && wifi_meta.slot[0].priority==10);
 assert(run("list") && !strcmp(out,"1* name=Car ssid=CarWifi priority=10\r\n") || !strcmp(out,"1 name=Car ssid=CarWifi priority=10\r\n"));
}
static void status_lines(void){
 fresh();save("Home","Home",80);save("Work","Work",30);wifi_set_preferred(1);wifi_link_stats.roams=2;ui.traffic.down_kbps=1234;ui.traffic.up_kbps=56;
 assert(run("status"));
 /* The first lines keep the shape every client parses. */
 assert(!strncmp(out,"mode=adapter trial=0 active=0 wifi=joining rssi=unknown usb_enumerated=1 usb_transport_ready=1 host_interface_ready=unknown internet=not_checked\r\nfirmware=9.9.9-test\r\n",160));
 assert(says("chip_temperature valid=1 current_tenths=553 peak_tenths=600 sampled_uptime_ms=0 errors=0\r\n"));
 /* New information is on new lines. */
 assert(says("wifi_prefs saved=2 preferred=2 priorities=80,30 roaming_assist=1 roams=2\r\n"));
 assert(says("display brightness=60 rotation=0 dim_seconds=60 page=2\r\n"));
 assert(says("setup active=0 ap=- seconds_left=0\r\n"));
 assert(says("traffic down_bytes=") && says("down_kbps=1234 up_kbps=56 usb_resets=3\r\n"));
 tailnet=true;roaming=false;assert(run("status") && !strncmp(out,"mode=tailnet",12) && says("roaming_assist=0"));tailnet=false;roaming=true;
 setup_active=true;setup_session_start(&setup_clock,0);test_time=100000000;
 assert(run("status") && !strncmp(out,"mode=setup trial=0",18) && says("setup active=1 ap=TDongle-AB0CF9 seconds_left=")); /* clock past the session */
 fresh();assert(run("status") && says("wifi_prefs saved=0 preferred=0 priorities=- roaming_assist=1"));
}
static void other_commands_are_left_alone(void){
 fresh();
 assert(!run("help") && !run("reboot") && !run("bootloader") && !run("boot-status") && !run("capabilities") && !run("nonsense") && !run("") && !run("setupx") && !run("resetx") && !run("cancelled"));
 assert(run("mode wifi_bridge") && restarts==1);
}
int main(void){
 display_command();setup_command();cancel_command();factory_reset_command();use_command();profile_and_list();status_lines();other_commands_are_left_alone();
 puts("Serial commands: display, setup, cancel, reset/confirm-reset (two steps, 10 s, nothing half erased), use (pin and preference), profile/list (name and priority), status lines, the others untouched");
 return 0;
}

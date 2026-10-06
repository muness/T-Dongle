/* What a boot decides before the settings are open (setup_ap.inc setup_early_has_networks, the real function): is anything saved? It must agree with
 * what wifi_load_profiles then loads, and an unreadable store must never open an access point. */
#include "host_store.h"
#include "../../../main/setup_boot.h"
#include "setup_early.inc"

static settings_t v011(unsigned networks){settings_t o;memset(&o,0,sizeof(o));o.version=CFG_VERSION;o.brightness=60;o.dim_seconds=60;for(unsigned i=0;i<networks;i++){snprintf(o.p[i].name,sizeof(o.p[i].name),"n%u",i);snprintf(o.p[i].ssid,sizeof(o.p[i].ssid),"net%u",i);strcpy(o.p[i].pass,"password1");o.p[i].priority=50;}return o;}
static bool probe(bool *store_ok){*store_ok=true;return setup_early_has_networks(1,store_ok);}
static bool probe_without_namespace(bool *store_ok){*store_ok=true;return setup_early_has_networks(0,store_ok);}
static void put_list_with(unsigned schema,unsigned count){typeof(wifi_saved) l;memset(&l,0,sizeof(l));l.schema=schema;l.count=count;for(unsigned i=0;i<count && i<8;i++){snprintf(l.profiles[i].ssid,33,"net%u",i);strcpy(l.profiles[i].password,"password1");}assert(nvs_set_blob(1,"wifi_profiles",&l,sizeof(l))==0);}
static void put_list(unsigned count){put_list_with(1,count);}
int main(void){
 bool ok;
 /* A fresh chip: nothing anywhere, setup opens. */
 reset_world();assert(!probe(&ok) && ok && !probe_without_namespace(&ok) && ok);
 setup_boot_decision d=setup_boot_decide(false,0,0,0,false,true);assert(d.setup);
 /* The unified list decides when it exists, and agrees with the loader. */
 reset_world();put_list(2);assert(probe(&ok) && ok);assert(wifi_load_profiles() && wifi_saved.count==2);
 reset_world();put_list(0);assert(!probe(&ok) && ok);assert(wifi_load_profiles() && wifi_saved.count==0);   /* every network deleted: setup again on a cold boot */
 /* ... even when the old v0.1.x blob still holds networks: the list is the user's current state (they deleted them). */
 reset_world();put_list(0);old_settings=v011(3);have_old=true;assert(!probe(&ok) && ok);
 /* No list yet: the older single network, then the v0.1.x list. */
 reset_world();wifi_config_t single;memset(&single,0,sizeof(single));memcpy(single.sta.ssid,"single",6);assert(nvs_set_blob(1,"wifi",&single,sizeof(single))==0);assert(probe(&ok) && ok);
 reset_world();memset(&single,0,sizeof(single));assert(nvs_set_blob(1,"wifi",&single,sizeof(single))==0);assert(!probe(&ok) && ok);   /* a stored but empty single network */
 reset_world();old_settings=v011(2);have_old=true;assert(probe(&ok) && ok && probe_without_namespace(&ok) && ok);                 /* an upgrade from v0.1.x: no tn_settings at all */
 reset_world();old_settings=v011(0);have_old=true;assert(!probe(&ok) && ok && !probe_without_namespace(&ok) && ok);              /* a v0.1.x install with nothing saved */
 reset_world();old_settings=v011(1);old_settings.version=7;have_old=true;assert(!probe(&ok) && ok);                              /* not a v0.1.x blob: not networks */
 /* Unreadable or damaged: never "nothing saved" (that would open an access point over data we could not read). */
 reset_world();assert(nvs_set_blob(1,"wifi_profiles",&single,sizeof(single))==0);assert(probe(&ok) && !ok);                       /* a list of the wrong size */
 reset_world();put_list(1);kv[find("wifi_profiles")].size=sizeof(wifi_saved)-1;assert(probe(&ok) && !ok);
 reset_world();put_list_with(2,1);assert(probe(&ok) && !ok);                                                                   /* a schema from the future */
 reset_world();put_list_with(1,9);assert(probe(&ok) && !ok);                                                                   /* more networks than exist */
 reset_world();put_list_with(1,1);assert(probe(&ok) && ok);
 d=setup_boot_decide(false,0,0,0,true,false);assert(!d.setup);
 /* And when the store is damaged, a person who asks for setup still gets it. */
 d=setup_boot_decide(true,SETUP_BOOT_MAGIC,SETUP_REQUEST_ENTER,0,true,false);assert(d.setup);
 puts("Early setup probe: fresh chip, unified list, single network, v0.1.x blob and an unreadable store each decide as the loader will");
 return 0;
}

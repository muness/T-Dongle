#include "host_store.h"
static void race_use_slot_one(void){assert(wifi_use_profile(1)==0);}
static void race_edit(void){assert(wifi_save_profile(wifi_saved.profiles[wifi_saved.count-1].ssid,"",true));}
static void original_cases(void){
 have_old=true;old_settings.version=CFG_VERSION;strcpy(old_settings.p[0].ssid,"bridge");strcpy(old_settings.p[0].pass,"secret");assert(wifi_load_profiles() && wifi_saved.count==1 && !strcmp(wifi_saved.profiles[0].ssid,"bridge"));have_old=false;
 memcpy(wifi_config.sta.ssid,"legacy",6);memcpy(wifi_config.sta.password,"secret",6);assert(wifi_load_profiles());assert(wifi_saved.count==1 && !strcmp(wifi_saved.profiles[0].ssid,"legacy"));
 for(unsigned i=1;i<8;i++){char name[16];snprintf(name,sizeof(name),"network%u",i);assert(wifi_save_profile(name,"key",false));}
 assert(wifi_saved.count==8);assert(!wifi_save_profile("ninth","key",false));assert(wifi_save_profile("legacy","updated",false));
 memset(&wifi_saved,0,sizeof(wifi_saved));assert(wifi_load_profiles() && wifi_saved.count==8 && !strcmp(wifi_saved.profiles[0].password,"updated"));
 fail_write=true;assert(!wifi_save_profile("legacy","lost",false));assert(!strcmp(wifi_saved.profiles[0].password,"updated"));fail_write=false;
 assert(wifi_save_profile("legacy","",true));assert(wifi_saved.count==7 && !strcmp(wifi_saved.profiles[0].ssid,"network1"));assert(wifi_save_profile("ninth","key",false));assert(wifi_saved.count==8);
 for(unsigned i=0;i<8;i++){strlcpy((char*)found[i].ssid,wifi_saved.profiles[i].ssid,33);found[i].rssi=-90+i*5;}
 wifi_rescan=true;wifi_maintain();assert(joins==1 && wifi_current==7); // strongest of all eight, not first saved
 wifi_retry_after[7]=(uint32_t)(test_time/1000)+60000;connected=online=false;wifi_rescan=true;wifi_maintain();assert(joins==2 && wifi_current==6); // failed strongest cannot trap retries
 wifi_rescan=true;wifi_maintain();assert(joins==2); // no oscillation while current scan signal is healthy
 unsigned previous=scans;current_rssi=-55;wifi_rescan=false;test_time+=61000000;wifi_maintain();assert(scans==previous);current_rssi=-85;test_time+=61000000;wifi_maintain();assert(scans==previous+1);
 /* `use N`: deterministic, and the choice sticks against roaming until the user changes it or the join fails. */
 {unsigned count=wifi_saved.count;assert(count==8);
  assert(wifi_use_profile(0)==-1 && wifi_use_profile(9)==-1 && wifi_use_profile(-3)==-1 && wifi_pinned.slot==-1);
  wifi_ready=false;assert(wifi_use_profile(1)==-1);wifi_ready=true;
  unsigned revision_before=wifi_revision,joins_before=joins;
  wifi_retry_after[0]=(uint32_t)(test_time/1000)+60000;
  assert(wifi_use_profile(1)==0 && wifi_current==0 && wifi_pinned.slot==0 && joins==joins_before+1 && wifi_revision==revision_before+1 && wifi_retry_after[0]==0);
  assert(!strcmp((char*)wifi_config.sta.ssid,wifi_saved.profiles[0].ssid) && !strcmp((char*)wifi_config.sta.password,wifi_saved.profiles[0].password));
  assert(!wifi_scan_pauses_reconnect);
  for(unsigned i=0;i<8;i++){strlcpy((char*)found[i].ssid,wifi_saved.profiles[i].ssid,33);found[i].rssi=i==7?-40:-85;}
  /* Weak current network and a far stronger saved one: unpinned selection would roam; the pin must not. */
  current_rssi=-88;connected=online=true;joins_before=joins;
  for(int pass=0;pass<5;pass++){wifi_rescan=true;wifi_maintain();assert(joins==joins_before && wifi_current==0 && wifi_pinned.slot==0);}
  /* Lost link: the worker retries the pinned network (even unseen) a bounded number of times, never another one. */
  for(unsigned i=0;i<8;i++)found[i].ssid[0]=0;
  for(int attempt=1;attempt<=WIFI_PIN_MAX_ATTEMPTS;attempt++){connected=online=false;wifi_rescan=true;wifi_maintain();assert(wifi_current==0 && wifi_pinned.slot==0 && joins==joins_before+attempt);}
  /* Still not joined: the pin is given up, reported, and normal selection resumes. */
  for(unsigned i=0;i<8;i++){strlcpy((char*)found[i].ssid,wifi_saved.profiles[i].ssid,33);found[i].rssi=i==7?-40:-85;}
  connected=online=false;wifi_rescan=true;wifi_maintain();
  assert(wifi_pinned.slot==-1 && wifi_pinned.failed_slot==1 && wifi_current==7);
  /* A fresh `use` clears the failure; editing the saved list drops the pin. */
  assert(wifi_use_profile(3)==0 && wifi_pinned.slot==2 && wifi_pinned.failed_slot==0 && wifi_current==2);
  assert(!wifi_save_profile("another","key",false));   /* list full: refused, pin untouched */
  assert(wifi_pinned.slot==2);
  assert(wifi_save_profile(wifi_saved.profiles[7].ssid,"",true) && wifi_pinned.slot==-1 && wifi_current==-1);
  assert(wifi_use_profile(2)==0);
  /* Race: a `use` lands while the worker is scanning (members_lock is free then). The worker must notice the revision
   * change, discard its stale choice without touching the pin, and rerun; it must never connect elsewhere in between. */
  for(unsigned i=0;i<8;i++){strlcpy((char*)found[i].ssid,wifi_saved.profiles[i].ssid,33);found[i].rssi=i==7?-40:-85;}
  connected=online=false;wifi_rescan=true;joins_before=joins;
  during_scan=race_use_slot_one;wifi_maintain();
  assert(joins==joins_before+1 && wifi_pinned.slot==0 && wifi_current==0 && wifi_rescan && !wifi_scan_pauses_reconnect);   /* only the `use` joined */
  /* Editing the saved list mid-scan likewise aborts the pass and clears the pin. */
  connected=online=false;wifi_rescan=true;joins_before=joins;during_scan=race_edit;wifi_maintain();
  assert(joins==joins_before && wifi_pinned.slot==-1 && wifi_rescan);
  /* The driver refusing the config leaves the previous pin alone and says so. */
  reject_config=true;int old_pin=wifi_pinned.slot;assert(wifi_use_profile(1)==-2 && wifi_pinned.slot==old_pin && !wifi_scan_pauses_reconnect);reject_config=false;
 }
 *(uint32_t*)kv[find("wifi_profiles")].data=999;assert(!wifi_load_profiles());   /* a schema nothing here knows: refused, never overwritten */
}

/* ---- Restored from v0.1.1: names, priorities, the preferred network, display settings and the factory reset; and the upgrade that must lose nothing. */
static settings_t v011_settings(void){settings_t o;memset(&o,0,sizeof(o));o.version=CFG_VERSION;o.brightness=60;o.dim_seconds=60;return o;}
static void v011_set(settings_t *o,unsigned slot,const char *name,const char *ssid,const char *pass,unsigned priority){strcpy(o->p[slot].name,name);strcpy(o->p[slot].ssid,ssid);strcpy(o->p[slot].pass,pass);o->p[slot].priority=(uint8_t)priority;}
static unsigned unified_keys(void){unsigned n=0;for(int i=0;i<KEYS;i++)n+=kv[i].used;return n;}

/* The upgrade from v0.1.1 loses nothing: every network with its name and priority, the preferred slot, the display settings. */
static void upgrade_is_lossless(void){
 reset_world();
 settings_t o=v011_settings();
 v011_set(&o,0,"Home","HomeNet","correct-horse",50);v011_set(&o,1,"Phone","Pixel hotspot","",90);v011_set(&o,4,"Car","CarWifi","12345678",10);
 o.preferred=4;o.brightness=85;o.rotation=1;o.dim_seconds=300;old_settings=o;have_old=true;
 assert(wifi_load_profiles());
 assert(wifi_saved.count==3 && !strcmp(wifi_saved.profiles[0].ssid,"HomeNet") && !strcmp(wifi_saved.profiles[0].password,"correct-horse") && !strcmp(wifi_saved.profiles[1].ssid,"Pixel hotspot") && !wifi_saved.profiles[1].password[0] && !strcmp(wifi_saved.profiles[2].ssid,"CarWifi"));
 assert(!strcmp(wifi_meta.slot[0].name,"Home") && wifi_meta.slot[0].priority==50 && !strcmp(wifi_meta.slot[1].name,"Phone") && wifi_meta.slot[1].priority==90 && !strcmp(wifi_meta.slot[2].name,"Car") && wifi_meta.slot[2].priority==10);
 assert(wifi_meta.preferred==2);   /* the preferred slot followed its network through the compaction of the empty slots */
 display_load();assert(display_settings.brightness==85 && display_settings.rotation==1 && display_settings.dim_seconds==300);
 assert(unified_keys()==0 && have_old);   /* importing writes nothing, and never touches the old namespace */
 /* Until the first explicit save the import repeats at every boot, so it must give the same answer. */
 forget_ram();assert(wifi_load_profiles() && wifi_saved.count==3 && wifi_meta.preferred==2 && wifi_meta.slot[1].priority==90);
 /* The first explicit save moves the networks to the unified keys (the old blob stays), and a reload gives the same networks and metadata. */
 assert(wifi_save_with("Pixel hotspot","",NULL,-1,false,-1));
 assert(find("wifi_profiles")>=0 && find("wifi_meta")>=0 && have_old);
 forget_ram();assert(wifi_load_profiles() && wifi_saved.count==3 && wifi_meta.preferred==2 && !strcmp(wifi_meta.slot[1].name,"Phone") && wifi_meta.slot[1].priority==90 && wifi_meta.slot[2].priority==10);
 /* Display settings: the old ones until the user saves their own, then theirs. */
 forget_ram();display_load();assert(display_settings.brightness==85);
 ui_settings mine={40,0,120};assert(display_save(&mine));forget_ram();display_load();assert(display_settings.brightness==40 && display_settings.dim_seconds==120 && display_settings.rotation==0);
 /* A damaged display blob falls back to the old settings, never to garbage. */
 kv[find("display")].data[0]=7;forget_ram();display_load();assert(display_settings.brightness==85);
}
/* An install that ran the first unified build (networks saved without metadata) still has its v0.1.1 priorities in the old namespace. */
static void in_between_build_keeps_priorities(void){
 reset_world();
 settings_t o=v011_settings();v011_set(&o,0,"Home","HomeNet","pass1234",30);v011_set(&o,1,"Work","WorkNet","pass5678",80);o.preferred=1;old_settings=o;have_old=true;
 typeof(wifi_saved) list;memset(&list,0,sizeof(list));list.schema=1;list.count=2;strcpy(list.profiles[0].ssid,"WorkNet");strcpy(list.profiles[0].password,"pass5678");strcpy(list.profiles[1].ssid,"HomeNet");strcpy(list.profiles[1].password,"pass1234");
 assert(nvs_set_blob(1,"wifi_profiles",&list,sizeof(list))==0);   /* the list was re-ordered by the in-between build */
 assert(wifi_load_profiles() && wifi_saved.count==2);
 assert(wifi_meta.slot[0].priority==80 && !strcmp(wifi_meta.slot[0].name,"Work") && wifi_meta.slot[1].priority==30 && wifi_meta.preferred==0);   /* matched by SSID, not by position */
 /* Once metadata exists it wins over the old namespace. */
 assert(wifi_save_with("WorkNet","pass5678",NULL,10,false,-1));forget_ram();assert(wifi_load_profiles() && wifi_meta.slot[0].priority==10);
}
/* The wifi_profiles blob is exactly what the first unified build wrote: an older firmware (a downgrade) still reads it. */
static void profile_blob_format_is_frozen(void){
 reset_world();
 assert(sizeof(wifi_saved)==8+8*97 && sizeof(wifi_profile)==97 && offsetof(wifi_profile,password)==33);
 assert(wifi_save_with("Home","pass1234","Home sweet",70,false,-1));
 int i=find("wifi_profiles");assert(i>=0 && kv[i].size==sizeof(wifi_saved));
 uint32_t schema,count;memcpy(&schema,kv[i].data,4);memcpy(&count,kv[i].data+4,4);assert(schema==1 && count==1 && !strcmp((char*)kv[i].data+8,"Home") && !strcmp((char*)kv[i].data+8+33,"pass1234"));
 /* A build that knows nothing of the metadata key simply ignores it, and one that edits the list leaves the metadata keyed by SSID. */
 typeof(wifi_saved) edited;memcpy(&edited,kv[i].data,sizeof(edited));strcpy(edited.profiles[1].ssid,"Added");strcpy(edited.profiles[1].password,"pass5678");edited.count=2;
 assert(nvs_set_blob(1,"wifi_profiles",&edited,sizeof(edited))==0);forget_ram();assert(wifi_load_profiles() && wifi_saved.count==2 && !strcmp(wifi_meta.slot[0].name,"Home sweet") && wifi_meta.slot[0].priority==70 && wifi_meta.slot[1].priority==50);
}
/* `use N` right after an upgrade from v0.1.1 (the list has not been saved yet): the preference is written alone and must survive a restart. */
static int join_after_scan(void);static void see(const char *ssid,unsigned slot,int rssi);
static void use_after_upgrade_survives_a_restart(void){
 reset_world();
 settings_t o=v011_settings();v011_set(&o,0,"Home","HomeNet","pass1234",30);v011_set(&o,1,"Work","WorkNet","pass5678",80);v011_set(&o,2,"Cafe","CafeNet","pass9999",10);o.preferred=0;old_settings=o;have_old=true;
 assert(wifi_load_profiles() && wifi_meta.preferred==0);
 assert(wifi_set_preferred(2) && find("wifi_profiles")<0 && find("wifi_meta")>=0);     /* only the metadata was written */
 forget_ram();assert(wifi_load_profiles() && wifi_saved.count==3);
 assert(wifi_meta.preferred==2);                                                         /* the new preference, not the v0.1.1 one */
 assert(wifi_meta.slot[0].priority==30 && wifi_meta.slot[1].priority==80 && wifi_meta.slot[2].priority==10 && !strcmp(wifi_meta.slot[1].name,"Work"));   /* and the v0.1.1 priorities for networks it does not name */
 assert(wifi_set_preferred(-1));forget_ram();assert(wifi_load_profiles() && wifi_meta.preferred==-1);   /* "no preference" is a choice too */
}
static void replacing_the_preferred_network(void){
 reset_world();
 assert(wifi_save_with("Home","pass1234",NULL,50,false,-1) && wifi_save_with("Work","pass5678",NULL,50,false,-1) && wifi_set_preferred(0));
 assert(wifi_save_with("NewHome","pass0000",NULL,-1,false,0) && wifi_meta.preferred==0 && !strcmp(wifi_saved.profiles[0].ssid,"NewHome"));   /* v0.1.1: the preferred SLOT stays preferred */
 forget_ram();assert(wifi_load_profiles() && wifi_meta.preferred==0 && !strcmp(wifi_saved.profiles[0].ssid,"NewHome"));
 assert(wifi_save_profile("NewHome","",true) && wifi_meta.preferred==-1);                   /* removing it clears the preference */
}
static void the_network_in_use_is_remembered_across_a_save(void){
 reset_world();
 assert(wifi_save_with("Home","pass1234",NULL,-1,false,-1) && wifi_save_with("Work","pass5678",NULL,-1,false,-1));
 see("Home",0,-50);see("Work",1,-60);
 assert(join_after_scan()==0);
 connected=online=true;current_rssi=-50;
 assert(wifi_save_with("Cafe","pass9999",NULL,-1,false,-1) && wifi_current==-1);          /* a save forgets which network is in use ... */
 wifi_maintain();assert(wifi_current==0);                                                   /* ... and the next pass, which stays put, finds out again */
 wifi_current=-1;wifi_rescan=false;test_time+=61000000;current_rssi=-55;wifi_maintain();assert(wifi_current==0);   /* also when it does not even scan (a healthy link) */
}
static void saving_with_metadata(void){
 reset_world();
 assert(wifi_save_with("Home","pass1234","Home sweet",70,false,-1) && wifi_saved.count==1 && !strcmp(wifi_meta.slot[0].name,"Home sweet") && wifi_meta.slot[0].priority==70);
 assert(wifi_save_at("Work","",false,-1) && !strcmp(wifi_meta.slot[1].name,"Work") && wifi_meta.slot[1].priority==50);   /* defaults for a new network */
 assert(wifi_save_with("Home","newpass12",NULL,-1,false,-1) && !strcmp(wifi_meta.slot[0].name,"Home sweet") && wifi_meta.slot[0].priority==70 && !strcmp(wifi_saved.profiles[0].password,"newpass12"));   /* same network: metadata kept */
 assert(wifi_save_with("Home","newpass12","Renamed",-1,false,-1) && !strcmp(wifi_meta.slot[0].name,"Renamed") && wifi_meta.slot[0].priority==70);
 assert(wifi_save_with("Cafe","pass5678",NULL,-1,false,0) && !strcmp(wifi_saved.profiles[0].ssid,"Cafe") && !strcmp(wifi_meta.slot[0].name,"Cafe") && wifi_meta.slot[0].priority==50);   /* a different network in slot 1: its own metadata */
 assert(!wifi_save_with("Work","pass5678",NULL,-1,false,0));   /* Work is in slot 2: refused, nothing changes */
 assert(!wifi_save_with("X","pass5678","bad\tname",-1,false,-1) && !wifi_save_with("X","pass5678",NULL,101,false,-1) && wifi_saved.count==2);
 assert(wifi_save_with("Third","pass5678",NULL,-1,false,2) && wifi_saved.count==3 && !wifi_save_with("Hole","pass5678",NULL,-1,false,4));
 /* Removing a network takes its metadata with it and shifts the rest. */
 wifi_meta.slot[2].priority=90;assert(wifi_set_preferred(2));
 assert(wifi_save_profile("Cafe","",true) && wifi_saved.count==2 && !strcmp(wifi_meta.slot[0].name,"Work") && !strcmp(wifi_meta.slot[1].name,"Third") && wifi_meta.slot[1].priority==90 && wifi_meta.preferred==1 && !wifi_meta.slot[2].name[0]);
 assert(wifi_save_profile("Third","",true) && wifi_meta.preferred==-1);   /* the preferred network is gone */
 forget_ram();assert(wifi_load_profiles() && wifi_saved.count==1 && wifi_meta.preferred==-1);
}
static void saves_are_all_or_nothing(void){
 reset_world();
 assert(wifi_save_with("Home","pass1234","Home",70,false,-1));
 typeof(wifi_saved) before=wifi_saved;wifi_meta_set before_meta=wifi_meta;unsigned revision=wifi_revision;
 /* The metadata write fails: nothing changed, in RAM or on flash. */
 fail_write=true;assert(!wifi_save_with("Work","pass5678","Work",60,false,-1));fail_write=false;
 assert(!memcmp(&before,&wifi_saved,sizeof(before)) && !memcmp(&before_meta,&wifi_meta,sizeof(before_meta)) && wifi_revision==revision);
 /* The list write fails after the metadata was written: the previous metadata is put back, so flash and RAM still agree. */
 writes_before_failure=write_count+1;assert(!wifi_save_with("Work","pass5678","Work",60,false,-1));writes_before_failure=~0u;
 assert(!memcmp(&before,&wifi_saved,sizeof(before)) && !memcmp(&before_meta,&wifi_meta,sizeof(before_meta)));
 forget_ram();assert(wifi_load_profiles() && wifi_saved.count==1 && wifi_meta.slot[0].priority==70 && !strcmp(wifi_meta.slot[0].name,"Home"));
 /* Preferred: a failed write leaves it alone. */
 assert(wifi_save_at("Work","pass5678",false,-1));
 fail_write=true;assert(!wifi_set_preferred(1) && wifi_meta.preferred==-1);fail_write=false;
 assert(wifi_set_preferred(1) && wifi_meta.preferred==1 && wifi_set_preferred(1) && wifi_set_preferred(-1) && wifi_meta.preferred==-1 && !wifi_set_preferred(2) && !wifi_set_preferred(-2));
}
static int join_after_scan(void){connected=online=false;wifi_rescan=true;wifi_maintain();return wifi_current;}
static void see(const char *ssid,unsigned slot,int rssi){strlcpy((char*)found[slot].ssid,ssid,33);found[slot].rssi=rssi;}
static void preferred_and_priority_choose_the_network(void){
 reset_world();
 assert(wifi_save_with("Home","pass1234",NULL,50,false,-1) && wifi_save_with("Work","pass5678",NULL,50,false,-1) && wifi_save_with("Phone","pass9999",NULL,80,false,-1));
 see("Home",0,-50);see("Work",1,-60);see("Phone",2,-70);
 assert(join_after_scan()==2);                                   /* the highest priority beats the strongest signal */
 assert(wifi_save_with("Phone","pass9999",NULL,50,false,-1));
 assert(join_after_scan()==0);                                   /* all equal: the strongest, exactly as before priorities existed */
 assert(wifi_set_preferred(1));assert(join_after_scan()==1);     /* the preferred network beats both */
 see("Work",1,-90);assert(join_after_scan()==0);                 /* ... but not when it can barely be heard */
 assert(wifi_set_preferred(-1));
 /* Not seen at all (a hidden network): the preferred and highest priority are tried first, a different one each pass. */
 for(unsigned i=0;i<3;i++)found[i].ssid[0]=0;
 assert(wifi_set_preferred(2));
 for(unsigned i=0;i<3;i++)wifi_retry_after[i]=0;
 assert(join_after_scan()==2);
 wifi_retry_after[2]=(uint32_t)(test_time/1000)+60000;assert(join_after_scan()==0);
 /* A priority set on the page changes what is joined without anything else. */
 assert(wifi_save_with("Work","pass5678",NULL,95,false,-1));wifi_set_preferred(-1);
 see("Home",0,-50);see("Work",1,-70);see("Phone",2,-60);
 assert(join_after_scan()==1);
 /* `use N` still pins for the session whatever the ranking says. */
 assert(wifi_use_profile(1)==0 && wifi_pinned.slot==0 && wifi_current==0);
 connected=online=true;current_rssi=-88;wifi_rescan=true;wifi_maintain();assert(wifi_current==0 && wifi_pinned.slot==0);
}
static void station_configuration(void){
 reset_world();
 wifi_profile secure={"HomeNet","correct-horse"},open={"CafeNet",""};
 wifi_config_t c;
 roaming=true;wifi_fill_station(&c,&secure);
 assert(!strcmp((char*)c.sta.ssid,"HomeNet") && !strcmp((char*)c.sta.password,"correct-horse") && c.sta.scan_method==WIFI_ALL_CHANNEL_SCAN && c.sta.sort_method==WIFI_CONNECT_AP_BY_SIGNAL);
 assert(c.sta.sae_pwe_h2e==WPA3_SAE_PWE_BOTH && c.sta.pmf_cfg.capable && c.sta.threshold.authmode==WIFI_AUTH_WPA2_PSK);   /* WPA3 and PMF, and no downgrade below WPA2 */
 assert(c.sta.rm_enabled==1 && c.sta.btm_enabled==1);            /* 802.11k and 802.11v: the roaming assist */
 wifi_fill_station(&c,&open);assert(c.sta.threshold.authmode==WIFI_AUTH_OPEN && !c.sta.password[0]);
 roaming=false;wifi_fill_station(&c,&secure);assert(c.sta.rm_enabled==0 && c.sta.btm_enabled==0 && c.sta.pmf_cfg.capable);   /* roaming off, v0.1.1 profile still on (bridge with the option off) */
 station_v011=false;wifi_fill_station(&c,&secure);assert(!c.sta.sae_pwe_h2e && !c.sta.pmf_cfg.capable && c.sta.threshold.authmode==WIFI_AUTH_OPEN && c.sta.scan_method==WIFI_ALL_CHANNEL_SCAN);   /* tailnet gateway: #44's configuration */
 wifi_fill_station(&c,&open);assert(c.sta.threshold.authmode==WIFI_AUTH_OPEN);station_v011=true;
 /* A 32 character SSID and a 63 character password fill their fields exactly, without a terminator. */
 wifi_profile widest;memset(&widest,0,sizeof(widest));memset(widest.ssid,'s',32);memset(widest.password,'p',63);
 wifi_fill_station(&c,&widest);assert(!memcmp(c.sta.ssid,widest.ssid,32) && !memcmp(c.sta.password,widest.password,63) && !c.sta.password[63]);
 /* Both ways of joining use it. */
 roaming=true;assert(wifi_save_with("HomeNet","correct-horse",NULL,-1,false,-1));assert(wifi_use_profile(1)==0 && wifi_config.sta.btm_enabled==1 && wifi_config.sta.pmf_cfg.capable);
 memset(&wifi_config,0,sizeof(wifi_config));see("HomeNet",0,-50);assert(join_after_scan()==0 && wifi_config.sta.rm_enabled==1 && wifi_config.sta.sae_pwe_h2e==WPA3_SAE_PWE_BOTH);
}
static void factory_reset(void){
 reset_world();
 settings_t o=v011_settings();v011_set(&o,0,"Home","HomeNet","pass1234",30);old_settings=o;have_old=true;
 memcpy(wifi_config.sta.ssid,"single",6);memcpy(wifi_config.sta.password,"pass0000",8);
 assert(wifi_load_profiles() && wifi_saved.count==2);
 assert(wifi_save_with("Work","pass5678","Work",70,false,-1));wifi_set_preferred(1);ui_settings mine={40,1,120};assert(display_save(&mine));
 uint8_t mode=1;assert(nvs_set_blob(1,"mode",&mode,1)==0);assert(nvs_set_blob(1,"members",&mode,1)==0);   /* not v0.1.1 data: kept */
 assert(wifi_factory_reset());
 assert(find("wifi_profiles")<0 && find("wifi_meta")<0 && find("display")<0 && find("wifi")<0 && find("mode")>=0 && find("members")>=0);
 assert(old_erased && !have_old);                                  /* the old namespace too: it would otherwise be imported again */
 assert(wifi_saved.count==0 && wifi_meta.preferred==-1 && display_settings.brightness==60 && display_settings.rotation==0 && !wifi_config.sta.ssid[0]);
 forget_ram();memset(&wifi_config,0,sizeof(wifi_config));assert(wifi_load_profiles() && wifi_saved.count==0);display_load();assert(display_settings.brightness==60);   /* nothing comes back after a restart */
 /* A failure to erase is reported and leaves the RAM alone, so the caller never restarts into a half reset. */
 reset_world();assert(wifi_save_with("Home","pass1234",NULL,-1,false,-1));fail_erase=true;assert(!wifi_factory_reset() && wifi_saved.count==1);fail_erase=false;
 /* Erasing keys that are not there is not an error (a dongle that never saved a display setting). */
 assert(wifi_factory_reset() && wifi_saved.count==0 && wifi_factory_reset());
}
static void early_setup_probe_matches_the_loader(void){
 /* What setup_early_has_networks decides before the store is open must agree with what wifi_load_profiles then loads (see setup_ap.inc):
  * the same three sources in the same order. */
 reset_world();
 settings_t o=v011_settings();v011_set(&o,0,"Home","HomeNet","pass1234",30);old_settings=o;have_old=true;
 legacy_import li;assert(wifi_read_legacy(&li) && li.count==1);
 have_old=false;assert(!wifi_read_legacy(&li));
 o=v011_settings();old_settings=o;have_old=true;assert(wifi_read_legacy(&li) && li.count==0);   /* a v0.1.1 install with nothing saved */
}
int main(void){
 original_cases();
 upgrade_is_lossless();in_between_build_keeps_priorities();use_after_upgrade_survives_a_restart();replacing_the_preferred_network();the_network_in_use_is_remembered_across_a_save();profile_blob_format_is_frozen();saving_with_metadata();saves_are_all_or_nothing();
 preferred_and_priority_choose_the_network();station_configuration();factory_reset();early_setup_probe_matches_the_loader();
 puts("Wi-Fi profiles: v0.1.1 import is lossless, metadata is keyed by SSID and written with rollback (two writes, never one transaction), priority/preferred choose the network, factory reset forgets everything v0.1.1 stored");
 return 0;
}

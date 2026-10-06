typedef struct {char ssid[33], password[64];} wifi_profile;
static struct {uint32_t schema,count;wifi_profile profiles[WIFI_PROFILE_LIMIT];} wifi_saved;   /* tn_settings/wifi_profiles: SSID and password only, format frozen */
static wifi_meta_set wifi_meta;   /* names, priorities, preferred: parallel to wifi_saved, persisted in tn_settings/wifi_meta (wifi_meta.h). Both guarded by members_lock. */
static ui_settings display_settings;   /* tn_settings/display, imported from the v0.1.1 adapter/config when absent; see device_ui.inc */
static volatile bool wifi_rescan=true;
static unsigned wifi_revision;
static int wifi_current=-1;
static uint32_t wifi_retry_after[8];
static wifi_pin wifi_pinned=WIFI_PIN_INIT;   /* the network `use N` chose, kept against roaming; guarded by members_lock */
_Static_assert(WIFI_META_SLOTS==WIFI_PROFILE_LIMIT,"saved-network metadata must have a slot for every saved network");
static void wifi_ssid_list(const char *ssids[WIFI_PROFILE_LIMIT]){for(unsigned i=0;i<WIFI_PROFILE_LIMIT;i++)ssids[i]=i<wifi_saved.count?wifi_saved.profiles[i].ssid:"";}
/* The v0.1.x firmware's settings (NVS adapter/config), read-only and only decoded, never trusted: see legacy_import.h. Every boot until the
 * first explicit save moves the data into the keys above, so nothing the old firmware stored is ever lost to an upgrade. */
static bool wifi_read_legacy(legacy_import *out){
    nvs_handle_t old_store;bool found=false;
    if(nvs_open("adapter",NVS_READONLY,&old_store)!=ESP_OK)return false;
    settings_t *old=malloc(sizeof(*old));   /* 1,004 B: not on a task stack */
    if(old){size_t bytes=sizeof(*old);
        if(nvs_get_blob(old_store,"config",old,&bytes)==ESP_OK)found=legacy_import_decode(old,bytes,out);
        memset(old,0,sizeof(*old));free(old);}
    nvs_close(old_store);
    return found;
}
/* Attach the v0.1.x name, priority and preferred slot to the networks already in wifi_saved, by SSID. */
static void wifi_apply_legacy_meta(const legacy_import *legacy){
    for(unsigned i=0;i<wifi_saved.count;i++)for(unsigned j=0;j<legacy->count;j++)
        if(!strcmp(wifi_saved.profiles[i].ssid,legacy->net[j].ssid)){wifi_meta.slot[i]=legacy->net[j].meta;break;}
    if(legacy->preferred>=0)for(unsigned i=0;i<wifi_saved.count;i++)
        if(!strcmp(wifi_saved.profiles[i].ssid,legacy->net[legacy->preferred].ssid))wifi_meta.preferred=(int)i;
}
static bool wifi_load_profiles(void){
    size_t n=sizeof(wifi_saved);esp_err_t e=nvs_get_blob(store,"wifi_profiles",&wifi_saved,&n);
    legacy_import *legacy=malloc(sizeof(*legacy));bool have_legacy=legacy && wifi_read_legacy(legacy);
    const char *ssids[WIFI_PROFILE_LIMIT];
    bool ok=true;
    if(e==ESP_ERR_NVS_NOT_FOUND){
        memset(&wifi_saved,0,sizeof(wifi_saved));wifi_saved.schema=1;
        if(wifi_config.sta.ssid[0]){wifi_saved.count=1;memcpy(wifi_saved.profiles[0].ssid,wifi_config.sta.ssid,32);memcpy(wifi_saved.profiles[0].password,wifi_config.sta.password,63);}
        /* Import the untouched original bridge profiles, without erasing its NVS. */
        if(have_legacy)for(unsigned i=0;i<legacy->count && wifi_saved.count<8;i++){
            bool duplicate=false;for(unsigned j=0;j<wifi_saved.count;j++)if(!strcmp(wifi_saved.profiles[j].ssid,legacy->net[i].ssid))duplicate=true;
            if(!duplicate){wifi_profile *p=&wifi_saved.profiles[wifi_saved.count++];strlcpy(p->ssid,legacy->net[i].ssid,33);strlcpy(p->password,legacy->net[i].password,64);}
        }
        wifi_ssid_list(ssids);wifi_meta_defaults(&wifi_meta,ssids,wifi_saved.count);
        if(have_legacy)wifi_apply_legacy_meta(legacy);
        /* Imported credentials and metadata persist on the next explicit save. */
    }else{
        if(e!=ESP_OK || n!=sizeof(wifi_saved) || wifi_saved.schema!=1 || wifi_saved.count>8)ok=false;
        for(unsigned i=0;ok && i<wifi_saved.count;i++)if(!wifi_saved.profiles[i].ssid[0] || wifi_saved.profiles[i].ssid[32] || wifi_saved.profiles[i].password[63])ok=false;
        if(ok){
            wifi_ssid_list(ssids);wifi_meta_defaults(&wifi_meta,ssids,wifi_saved.count);
            wifi_meta_blob *blob=malloc(sizeof(*blob));size_t bytes=sizeof(*blob);
            bool stored=blob && nvs_get_blob(store,"wifi_meta",blob,&bytes)==ESP_OK && wifi_meta_decode(blob,bytes,ssids,wifi_saved.count,&wifi_meta);
            free(blob);
            /* No (valid) metadata yet: this list was saved by a build that predates it (the first unified release saved networks
             * without it), so the v0.1.x settings, if they are still there, are still the user's priorities. */
            if(!stored && have_legacy)wifi_apply_legacy_meta(legacy);
        }
    }
    if(legacy){memset(legacy,0,sizeof(*legacy));free(legacy);}
    return ok;
}
/* Save, replace or remove one network, with its name and priority (name NULL or empty, priority < 0: keep what it has, or the defaults for a
 * new or replaced network). slot >= 0 targets that slot (it may be one past the end to append); -1 finds the network by SSID. The password
 * and the metadata are written together: metadata first, because it is keyed by SSID and harmless without the list change, then the
 * list, then one commit. Either everything changes or nothing does. */
static bool wifi_save_with(const char *ssid,const char *password,const char *name,int priority,bool remove,int slot){
    unsigned i=0;for(;i<wifi_saved.count;i++)if(!strcmp(wifi_saved.profiles[i].ssid,ssid))break;
    if(slot>=0){if(slot>(int)wifi_saved.count || (i<wifi_saved.count && i!=(unsigned)slot))return false;i=(unsigned)slot;}
    if(remove && i==wifi_saved.count)return false;
    if(!remove && i==8)return false;
    if(!remove && name && name[0] && !wifi_meta_name_valid(name))return false;
    if(!remove && priority>WIFI_META_PRIORITY_MAX)return false;
    typeof(wifi_saved) candidate=wifi_saved;
    wifi_meta_set meta=wifi_meta;
    if(remove){memmove(&candidate.profiles[i],&candidate.profiles[i+1],(candidate.count-i-1)*sizeof(wifi_profile));memset(&candidate.profiles[candidate.count-1],0,sizeof(wifi_profile));wifi_meta_remove(&meta,candidate.count,i);candidate.count--;}
    else {
        bool same=i<candidate.count && !strcmp(candidate.profiles[i].ssid,ssid);
        strlcpy(candidate.profiles[i].ssid,ssid,33);strlcpy(candidate.profiles[i].password,password,64);
        if(i==candidate.count)candidate.count++;
        if(!same)wifi_meta_slot_default(&meta.slot[i],ssid);   /* a different network in this slot: its own name and the default priority */
        if(name && name[0])strlcpy(meta.slot[i].name,name,sizeof(meta.slot[i].name));
        if(priority>=0)meta.slot[i].priority=(uint8_t)priority;
    }
    const char *ssids[WIFI_PROFILE_LIMIT];
    for(unsigned k=0;k<WIFI_PROFILE_LIMIT;k++)ssids[k]=k<candidate.count?candidate.profiles[k].ssid:"";
    wifi_meta_blob *blob=malloc(sizeof(*blob)),*previous=malloc(sizeof(*previous));
    bool ok=blob && previous;size_t old_bytes=sizeof(*previous);
    bool had_meta=ok && nvs_get_blob(store,"wifi_meta",previous,&old_bytes)==ESP_OK && old_bytes==sizeof(*previous);
    if(ok){wifi_meta_encode(blob,ssids,candidate.count,&meta);ok=nvs_set_blob(store,"wifi_meta",blob,sizeof(*blob))==ESP_OK;}
    if(ok && nvs_set_blob(store,"wifi_profiles",&candidate,sizeof(candidate))!=ESP_OK){
        /* Put the previous metadata back (best effort: it is keyed by SSID, so what it holds is correct for the list that stayed). */
        if(had_meta)nvs_set_blob(store,"wifi_meta",previous,sizeof(*previous));
        ok=false;
    }
    free(blob);free(previous);
    if(!ok || nvs_commit(store)!=ESP_OK)return false;
    wifi_saved=candidate;wifi_meta=meta;wifi_revision++;wifi_current=-1;wifi_pin_clear(&wifi_pinned);memset(wifi_retry_after,0,sizeof(wifi_retry_after));
    wifi_rescan=true;
    return true;
}
static bool wifi_save_at(const char *ssid,const char *password,bool remove,int slot){return wifi_save_with(ssid,password,NULL,-1,remove,slot);}
static bool wifi_save_profile(const char *ssid,const char *password,bool remove){return wifi_save_at(ssid,password,remove,-1);}
/* The preferred network (v0.1.1's preferred slot): tried first at boot and whenever the strongest choice is made. slot is 0-based, -1 clears it.
 * Only the metadata is written; the current connection and any `use` pin are untouched. */
static bool wifi_set_preferred(int slot){
    if(slot<-1 || slot>=(int)wifi_saved.count)return false;
    if(slot==wifi_meta.preferred)return true;
    wifi_meta_set meta=wifi_meta;meta.preferred=slot;
    const char *ssids[WIFI_PROFILE_LIMIT];wifi_ssid_list(ssids);
    wifi_meta_blob *blob=malloc(sizeof(*blob));
    bool ok=blob;
    if(ok){wifi_meta_encode(blob,ssids,wifi_saved.count,&meta);ok=nvs_set_blob(store,"wifi_meta",blob,sizeof(*blob))==ESP_OK && nvs_commit(store)==ESP_OK;}
    free(blob);
    if(!ok)return false;
    wifi_meta=meta;wifi_revision++;   /* a scan already in flight must rank with the new choice */
    return true;
}
/* Factory reset: forget everything v0.1.1 stored (saved networks and display settings), in the unified keys and in the old adapter
 * namespace, which would otherwise be imported again on the next boot. The routing mode, tailnet memberships and their identities are
 * kept: they are not v0.1.1 data and are removed from the app or the USB page. Returns false when any key could not be erased; the
 * caller must not restart into a half-reset state then. */
static bool wifi_factory_reset(void){
    static const char *const keys[]={"wifi_profiles","wifi_meta","display","wifi"};
    bool ok=true;
    for(unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);i++){esp_err_t e=nvs_erase_key(store,keys[i]);if(e!=ESP_OK && e!=ESP_ERR_NVS_NOT_FOUND)ok=false;}
    if(nvs_commit(store)!=ESP_OK)ok=false;
    nvs_handle_t old_store;esp_err_t e=nvs_open("adapter",NVS_READWRITE,&old_store);
    if(e==ESP_OK){if(nvs_erase_all(old_store)!=ESP_OK || nvs_commit(old_store)!=ESP_OK)ok=false;nvs_close(old_store);}
    else if(e!=ESP_ERR_NVS_NOT_FOUND)ok=false;
    if(!ok)return false;
    memset(&wifi_saved,0,sizeof(wifi_saved));wifi_saved.schema=1;
    const char *ssids[WIFI_PROFILE_LIMIT];wifi_ssid_list(ssids);wifi_meta_defaults(&wifi_meta,ssids,0);
    memset(&wifi_config,0,sizeof(wifi_config));ui_settings_defaults(&display_settings);
    wifi_revision++;wifi_current=-1;wifi_pin_clear(&wifi_pinned);memset(wifi_retry_after,0,sizeof(wifi_retry_after));
    return true;
}
/* ---- Display settings: tn_settings/display, else the v0.1.1 adapter/config (brightness, rotation, dim time), else the defaults. */
static void display_load(void) {
    ui_settings loaded;
    ui_settings_defaults(&loaded);
    ui_settings_blob blob;
    size_t n = sizeof(blob);
    if (nvs_get_blob(store, "display", &blob, &n) == ESP_OK && ui_settings_decode(&blob, n, &loaded)) { display_settings = loaded; return; }
    legacy_import *legacy = malloc(sizeof(*legacy));
    if (legacy && wifi_read_legacy(legacy) && legacy->display_valid) loaded = legacy->display;
    free(legacy);
    display_settings = loaded;
}
static bool display_save(const ui_settings *s) {
    ui_settings_blob blob;
    ui_settings_encode(s, &blob);
    if (nvs_set_blob(store, "display", &blob, sizeof(blob)) != ESP_OK || nvs_commit(store) != ESP_OK) return false;
    display_settings = *s;   /* the UI poll applies it within UI_DRAW_MS */
    return true;
}

/* Scanning and reconnecting run on the existing manager, never on event callbacks or HTTP.
 * One AP record at a time bounds our SRAM, regardless of nearby AP count. */
/* The station configuration for one saved network, the same for every way of joining it (the worker, `use N`).
 *  - scan every channel and join the strongest AP of the SSID, not the first one the fast scan finds (v0.1.1);
 *  - WPA3 (SAE both methods) and protected management frames on, and an AP weaker than WPA2 refused for a network with a password (v0.1.1);
 *  - 802.11k neighbour reports and 802.11v BSS transition requests, so the network can steer the dongle to a better AP: the roaming assist
 *    of v0.1.1. Self-initiated roaming stays off (an RSSI-only rule ping-ponged between two similar access points). Per mode, see
 *    wifi_roaming_assist() in gateway_main.c. */
static void wifi_fill_station(wifi_config_t *c,const wifi_profile *p){
    memset(c,0,sizeof(*c));
    memcpy(c->sta.ssid,p->ssid,strnlen(p->ssid,32));memcpy(c->sta.password,p->password,strnlen(p->password,63));
    c->sta.scan_method=WIFI_ALL_CHANNEL_SCAN;c->sta.sort_method=WIFI_CONNECT_AP_BY_SIGNAL;
    c->sta.sae_pwe_h2e=WPA3_SAE_PWE_BOTH;c->sta.pmf_cfg.capable=true;
    c->sta.threshold.authmode=p->password[0]?WIFI_AUTH_WPA2_PSK:WIFI_AUTH_OPEN;
    c->sta.rm_enabled=c->sta.btm_enabled=wifi_roaming_assist()?1:0;
}
static void wifi_maintain(void){
    static unsigned hidden_cursor;
    static uint32_t next_scan;
    uint32_t tick=(uint32_t)(esp_timer_get_time()/1000);
    if(!wifi_rescan && (int32_t)(next_scan-tick)>0)return;
    if(!wifi_ready || xSemaphoreTake(wifi_scan_lock,0)!=pdTRUE)return;
    bool forced=wifi_rescan;wifi_rescan=false;next_scan=tick+(online?60000:10000);
        wifi_profile profiles[8];unsigned count,revision;uint8_t priority[8];wifi_rank rank={priority,-1};
        xSemaphoreTake(members_lock,portMAX_DELAY);count=wifi_saved.count;revision=wifi_revision;memcpy(profiles,wifi_saved.profiles,sizeof(profiles));
        for(unsigned i=0;i<8;i++){priority[i]=wifi_meta.slot[i].priority;}
        rank.preferred=wifi_meta.preferred;xSemaphoreGive(members_lock);
        wifi_scan_pauses_reconnect=true;
        wifi_ap_record_t ap;bool connected=esp_wifi_sta_get_ap_info(&ap)==ESP_OK;
        int current=-1;int16_t signal[8];for(unsigned i=0;i<8;i++)signal[i]=-127;
        if(connected)for(unsigned i=0;i<count;i++)if(!strncmp(profiles[i].ssid,(char*)ap.ssid,32)){current=i;signal[i]=ap.rssi;}
        if(connected && current>=0 && ap.rssi>-75 && !forced && (wifi_pinned.slot<0 || current==wifi_pinned.slot)){memset(profiles,0,sizeof(profiles));wifi_scan_pauses_reconnect=false;xSemaphoreGive(wifi_scan_lock);return;}
        if(!count){esp_wifi_disconnect();memset(&wifi_config,0,sizeof(wifi_config));wifi_scan_pauses_reconnect=false;xSemaphoreGive(wifi_scan_lock);return;}
        if(!connected)esp_wifi_disconnect();
        wifi_scan_config_t scan={.show_hidden=true,.scan_type=WIFI_SCAN_TYPE_ACTIVE,.scan_time.active={.min=40,.max=100}};
        esp_err_t result=esp_wifi_scan_start(&scan,true);
        tdongle_memory_note(TDONGLE_MEMORY_OP_WIFI_PROFILES,0,result!=ESP_OK);
        if(result==ESP_OK){while(esp_wifi_scan_get_ap_record(&ap)==ESP_OK)for(unsigned i=0;i<count;i++)if(!strncmp(profiles[i].ssid,(char*)ap.ssid,32)&&ap.rssi>signal[i])signal[i]=ap.rssi;esp_wifi_clear_ap_list();}
        uint32_t now=(uint32_t)(esp_timer_get_time()/1000);
        for(unsigned i=0;i<count;i++)if((int32_t)(wifi_retry_after[i]-now)>0)signal[i]=-127;
        xSemaphoreTake(members_lock,portMAX_DELAY);   /* the pin belongs to members_lock; a `use` that raced the scan bumped the revision */
        if(revision!=wifi_revision){xSemaphoreGive(members_lock);memset(profiles,0,sizeof(profiles));wifi_scan_pauses_reconnect=false;xSemaphoreGive(wifi_scan_lock);wifi_rescan=true;return;}
        int selected=wifi_pin_pick_ranked(&wifi_pinned,signal,count,current,connected,&rank);
        /* Hidden/unseen networks get bounded round-robin attempts when offline, the preferred and highest-priority ones first. */
        if(selected<0 && !connected && count){uint8_t order[8];wifi_rank_order(&rank,count,order);for(unsigned n=0;n<count;n++){unsigned i=order[(hidden_cursor++)%count];if((int32_t)(wifi_retry_after[i]-now)<=0){selected=i;break;}}}
        if(selected>=0){
            wifi_config_t candidate;wifi_fill_station(&candidate,&profiles[selected]);
            esp_wifi_disconnect();
            if(esp_wifi_set_config(WIFI_IF_STA,&candidate)==ESP_OK){wifi_config=candidate;wifi_current=selected;esp_wifi_connect();}
        }
        xSemaphoreGive(members_lock);
        memset(profiles,0,sizeof(profiles));wifi_scan_pauses_reconnect=false;xSemaphoreGive(wifi_scan_lock);
}
/* `use N`: switch to saved network N (1-based) and keep it. Caller holds members_lock. Returns 0 when the switch was
 * started (the join itself is asynchronous: wifi_link reports join=joining/connected/failed), -1 for a bad slot or no
 * Wi-Fi, -2 when the driver refused the configuration (the previous pin and network are left as they were). */
static int wifi_use_profile(long slot){
    if(slot<1 || slot>(long)wifi_saved.count || !wifi_ready)return -1;
    const wifi_profile *p=&wifi_saved.profiles[slot-1];
    wifi_config_t candidate;wifi_fill_station(&candidate,p);
    wifi_scan_pauses_reconnect=true;esp_wifi_disconnect();
    int result=-2;
    if(esp_wifi_set_config(WIFI_IF_STA,&candidate)==ESP_OK){
        wifi_config=candidate;wifi_current=(int)slot-1;wifi_pin_set(&wifi_pinned,(int)slot-1);
        wifi_retry_after[slot-1]=0;wifi_revision++;   /* a scan already in flight must not override this choice */
        esp_wifi_connect();result=0;
    }
    wifi_scan_pauses_reconnect=false;
    memset(&candidate,0,sizeof(candidate));
    return result;
}

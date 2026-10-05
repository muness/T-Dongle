typedef struct {char ssid[33], password[64];} wifi_profile;
static struct {uint32_t schema,count;wifi_profile profiles[WIFI_PROFILE_LIMIT];} wifi_saved;
static volatile bool wifi_rescan=true;
static unsigned wifi_revision;
static int wifi_current=-1;
static uint32_t wifi_retry_after[8];
static wifi_pin wifi_pinned=WIFI_PIN_INIT;   /* the network `use N` chose, kept against roaming; guarded by members_lock */
static bool wifi_load_profiles(void){
    size_t n=sizeof(wifi_saved);esp_err_t e=nvs_get_blob(store,"wifi_profiles",&wifi_saved,&n);
    if(e==ESP_ERR_NVS_NOT_FOUND){
        memset(&wifi_saved,0,sizeof(wifi_saved));wifi_saved.schema=1;
        if(wifi_config.sta.ssid[0]){wifi_saved.count=1;memcpy(wifi_saved.profiles[0].ssid,wifi_config.sta.ssid,32);memcpy(wifi_saved.profiles[0].password,wifi_config.sta.password,63);}
        /* Import untouched original bridge profiles, without erasing its NVS. */
        nvs_handle_t old_store;
        if(nvs_open("adapter",NVS_READONLY,&old_store)==ESP_OK){
            settings_t old;size_t bytes=sizeof(old);
            if(nvs_get_blob(old_store,"config",&old,&bytes)==ESP_OK && bytes==sizeof(old) && old.version==CFG_VERSION){
                for(unsigned i=0;i<PROFILE_MAX && wifi_saved.count<8;i++){
                    if(!old.p[i].ssid[0] || !memchr(old.p[i].ssid,0,33) || !memchr(old.p[i].pass,0,65) || strlen(old.p[i].pass)>63)continue;
                    bool duplicate=false;for(unsigned j=0;j<wifi_saved.count;j++)if(!strcmp(wifi_saved.profiles[j].ssid,old.p[i].ssid))duplicate=true;
                    if(!duplicate){wifi_profile *p=&wifi_saved.profiles[wifi_saved.count++];strlcpy(p->ssid,old.p[i].ssid,33);strlcpy(p->password,old.p[i].pass,64);}
                }
            }
            memset(&old,0,sizeof(old));nvs_close(old_store);
        }
        return true; /* Imported credentials persist on the next explicit save. */
    }
    if(e!=ESP_OK || n!=sizeof(wifi_saved) || wifi_saved.schema!=1 || wifi_saved.count>8)return false;
    for(unsigned i=0;i<wifi_saved.count;i++)if(!wifi_saved.profiles[i].ssid[0] || wifi_saved.profiles[i].ssid[32] || wifi_saved.profiles[i].password[63])return false;
    return true;
}
static bool wifi_save_at(const char *ssid,const char *password,bool remove,int slot){
    unsigned i=0;for(;i<wifi_saved.count;i++)if(!strcmp(wifi_saved.profiles[i].ssid,ssid))break;
    if(slot>=0){if(slot>(int)wifi_saved.count || (i<wifi_saved.count && i!=(unsigned)slot))return false;i=(unsigned)slot;}
    if(remove && i==wifi_saved.count)return false;
    if(!remove && i==8)return false;
    typeof(wifi_saved) candidate=wifi_saved;
    if(remove){memmove(&candidate.profiles[i],&candidate.profiles[i+1],(candidate.count-i-1)*sizeof(wifi_profile));memset(&candidate.profiles[--candidate.count],0,sizeof(wifi_profile));}
    else {strlcpy(candidate.profiles[i].ssid,ssid,33);strlcpy(candidate.profiles[i].password,password,64);if(i==candidate.count)candidate.count++;}
    if(nvs_set_blob(store,"wifi_profiles",&candidate,sizeof(candidate))!=ESP_OK || nvs_commit(store)!=ESP_OK)return false;
    wifi_saved=candidate;wifi_revision++;wifi_current=-1;wifi_pin_clear(&wifi_pinned);memset(wifi_retry_after,0,sizeof(wifi_retry_after));
    wifi_rescan=true;
    return true;
}
static bool wifi_save_profile(const char *ssid,const char *password,bool remove){return wifi_save_at(ssid,password,remove,-1);}
/* Scanning and reconnecting run on the existing manager, never on event callbacks or HTTP.
 * One AP record at a time bounds our SRAM, regardless of nearby AP count. */
static void wifi_maintain(void){
    static unsigned hidden_cursor;
    static uint32_t next_scan;
    uint32_t tick=(uint32_t)(esp_timer_get_time()/1000);
    if(!wifi_rescan && (int32_t)(next_scan-tick)>0)return;
    if(!wifi_ready || xSemaphoreTake(wifi_scan_lock,0)!=pdTRUE)return;
    bool forced=wifi_rescan;wifi_rescan=false;next_scan=tick+(online?60000:10000);
        wifi_profile profiles[8];unsigned count,revision;
        xSemaphoreTake(members_lock,portMAX_DELAY);count=wifi_saved.count;revision=wifi_revision;memcpy(profiles,wifi_saved.profiles,sizeof(profiles));xSemaphoreGive(members_lock);
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
        int selected=wifi_pin_pick(&wifi_pinned,signal,count,current,connected);
        /* Hidden/unseen networks get bounded round-robin attempts when offline. */
        if(selected<0 && !connected && count)for(unsigned n=0;n<count;n++){unsigned i=(hidden_cursor++)%count;if((int32_t)(wifi_retry_after[i]-now)<=0){selected=i;break;}}
        if(selected>=0){
            wifi_config_t candidate={0};memcpy(candidate.sta.ssid,profiles[selected].ssid,strlen(profiles[selected].ssid));memcpy(candidate.sta.password,profiles[selected].password,strlen(profiles[selected].password));
            candidate.sta.scan_method=WIFI_ALL_CHANNEL_SCAN;candidate.sta.sort_method=WIFI_CONNECT_AP_BY_SIGNAL;
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
    wifi_config_t candidate={0};memcpy(candidate.sta.ssid,p->ssid,strlen(p->ssid));strlcpy((char*)candidate.sta.password,p->password,64);
    candidate.sta.scan_method=WIFI_ALL_CHANNEL_SCAN;candidate.sta.sort_method=WIFI_CONNECT_AP_BY_SIGNAL;
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

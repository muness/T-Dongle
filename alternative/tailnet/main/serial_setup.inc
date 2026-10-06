/* Same saved Wi-Fi store and mode setting over CDC, available without a USB IP. */
extern void mgmt_write(const char *s);
static bool factory_reset_armed;
static uint32_t factory_reset_until_ms;
bool gateway_serial_command(const char *line) {
 char reply[768];
 if(!strcmp(line,"status")){
  tdongle_temperature t=tdongle_temperature_snapshot();
  wifi_link_info link=wifi_link_read();char rssi_buffer[5];const char *rssi_text=wifi_link_rssi_text(&link,rssi_buffer);
  /* Android parses the chip_temperature line with an end-anchored regex that stops after errors=: extra fields live on the
   * chip_temperature_detail line so existing clients keep working (additions go on new lines, never onto old ones). */
  snprintf(reply,sizeof(reply),"mode=%s trial=0 active=%d wifi=%s rssi=%s usb_enumerated=%d usb_transport_ready=%d host_interface_ready=unknown internet=not_checked\r\nfirmware=" GATEWAY_VERSION "\r\nuptime_ms=%llu free_heap=%lu\r\nchip_temperature valid=%d current_tenths=%ld peak_tenths=%ld sampled_uptime_ms=%lu errors=%lu\r\nchip_temperature_detail age_ms=%lu samples=%lu changed_uptime_ms=%lu step_tenths=%d\r\n",
   setup_active?"setup":gateway_tailnet_mode()?"tailnet":"adapter",wifi_current+1,online?"up":"joining",rssi_text,tud_mounted(),tud_ready(),(unsigned long long)(esp_timer_get_time()/1000),(unsigned long)esp_get_free_heap_size(),t.valid,(long)t.current_tenths,(long)t.peak_tenths,(unsigned long)t.sampled_at_ms,(unsigned long)t.errors,(unsigned long)t.age_ms,(unsigned long)t.samples,(unsigned long)t.changed_at_ms,TDONGLE_TEMPERATURE_STEP_TENTHS);mgmt_write(reply);
  {bool clock_valid=ml_derp_clock_valid();snprintf(reply,sizeof(reply),"clock=%s valid=%d sntp_restarts=%lu server=%s retry_in_ms=%lu\r\n",gw_clock_state(&sntp_clock,clock_valid,online),clock_valid,(unsigned long)sntp_clock.restarts,gw_clock_server_name[sntp_clock.server%GW_CLOCK_SERVERS],(unsigned long)sntp_clock.retry_in_ms);mgmt_write(reply);}
  if(wifi_link_line(reply,sizeof(reply),&link,&wifi_link_stats))mgmt_write(reply);
  /* The v0.1.1 front panel, one new line each (additions never go onto a line a client already parses). */
  {char priorities[8*4+1]="";size_t used=0;for(unsigned i=0;i<wifi_saved.count && used+4<sizeof(priorities);i++)used+=(size_t)snprintf(priorities+used,sizeof(priorities)-used,"%s%u",i?",":"",(unsigned)wifi_meta.slot[i].priority);
   snprintf(reply,sizeof(reply),"wifi_prefs saved=%u preferred=%d priorities=%s roaming_assist=%d roams=%lu\r\n",(unsigned)wifi_saved.count,wifi_meta.preferred+1,priorities[0]?priorities:"-",wifi_roaming_assist()?1:0,(unsigned long)wifi_link_stats.roams);mgmt_write(reply);}
  snprintf(reply,sizeof(reply),"display brightness=%u rotation=%u dim_seconds=%u page=%u\r\n",(unsigned)display_settings.brightness,(unsigned)display_settings.rotation,(unsigned)display_settings.dim_seconds,ui.page);mgmt_write(reply);
  snprintf(reply,sizeof(reply),"setup active=%d ap=%s seconds_left=%lu\r\n",setup_active?1:0,setup_active?setup_ap_name:"-",(unsigned long)setup_session_seconds_left(&setup_clock,(uint32_t)(esp_timer_get_time()/1000)));mgmt_write(reply);
  {traffic_counters c=traffic_read();snprintf(reply,sizeof(reply),"traffic down_bytes=%lu up_bytes=%lu down_frames=%lu up_frames=%lu down_kbps=%lu up_kbps=%lu usb_resets=%u\r\n",(unsigned long)c.down_bytes,(unsigned long)c.up_bytes,(unsigned long)c.down_frames,(unsigned long)c.up_frames,(unsigned long)ui.traffic.down_kbps,(unsigned long)ui.traffic.up_kbps,gateway_usb_health(8));mgmt_write(reply);}
  for(unsigned i=0;i<tdongle_memory_count();i++){tdongle_memory_record m=tdongle_memory_get(i);snprintf(reply,sizeof(reply),"memory_pressure uptime_ms=%lu operation=%lu requested=%lu free=%lu minimum=%lu largest=%lu failed=%lu\r\n",(unsigned long)m.uptime_ms,(unsigned long)m.operation,(unsigned long)m.requested,(unsigned long)m.free_bytes,(unsigned long)m.minimum_bytes,(unsigned long)m.largest_bytes,(unsigned long)m.failed);mgmt_write(reply);}
  return true;
 }
 if(!strncmp(line,"mode ",5)){
  tdongle_mode selected;
  if(!tdongle_mode_parse(line+5,&selected)){mgmt_write("ERR Invalid mode\r\n");return true;}
  if(xSemaphoreTake(members_lock,pdMS_TO_TICKS(100))!=pdTRUE){mgmt_write("ERR Settings busy\r\n");return true;}
  esp_err_t result=tdongle_mode_save(store,selected);xSemaphoreGive(members_lock);
  if(result!=ESP_OK){mgmt_write("ERR Mode was not saved\r\n");return true;}
  mgmt_write("OK mode saved; restarting\r\ndone>\r\n");vTaskDelay(pdMS_TO_TICKS(300));esp_restart();return true;
 }
 if(!strcmp(line,"scan")){
  if(!wifi_ready || xSemaphoreTake(wifi_scan_lock,0)!=pdTRUE){mgmt_write("ERR Scan busy\r\n");return true;}
  wifi_scan_pauses_reconnect=true;bool connected=online;if(!connected)esp_wifi_disconnect();
  wifi_scan_config_t config={.show_hidden=false,.scan_type=WIFI_SCAN_TYPE_ACTIVE,.scan_time.active={.min=40,.max=100}};
  esp_err_t result=esp_wifi_scan_start(&config,true);wifi_ap_record_t ap;unsigned count=0;
  if(result==ESP_OK)while(count<12 && esp_wifi_scan_get_ap_record(&ap)==ESP_OK){char ssid[33];memcpy(ssid,ap.ssid,32);ssid[32]=0;for(char *c=ssid;*c;c++)if((unsigned char)*c<32 || (unsigned char)*c>126)*c='?';snprintf(reply,sizeof(reply),"ssid=%s rssi=%d auth=%d\r\n",ssid,ap.rssi,ap.authmode);mgmt_write(reply);count++;}
  else {mgmt_write("ERR Scan failed; retry shortly\r\n");}
  esp_wifi_clear_ap_list();wifi_scan_pauses_reconnect=false;wifi_rescan=!connected;xSemaphoreGive(wifi_scan_lock);return true;
 }
 if(!strncmp(line,"display",7) && (!line[7] || line[7]==' ')){
  /* v0.1.1: display BRIGHTNESS ROTATION DIM_SECONDS. Without arguments, the current values. */
  if(!line[7]){snprintf(reply,sizeof(reply),"display brightness=%u rotation=%u dim_seconds=%u\r\n",(unsigned)display_settings.brightness,(unsigned)display_settings.rotation,(unsigned)display_settings.dim_seconds);mgmt_write(reply);return true;}
  ui_settings next;
  if(!ui_settings_parse(line+8,&next))mgmt_write("ERR display: brightness 5..100 rotation 0|1 dim 10..3600 seconds\r\n");
  else if(!display_save(&next))mgmt_write("ERR Storage save failed\r\n");
  else mgmt_write("OK display saved\r\n");
  return true;
 }
 if(!strcmp(line,"setup") || !strncmp(line,"setup ",6)){
  /* Restart into the setup access point (v0.1.1). `setup N` offers saved network N for replacement on the page. */
  unsigned slot=0;
  if(line[5]){char *end;long n=strtol(line+6,&end,10);if(*end || n<1 || n>WIFI_PROFILE_LIMIT){mgmt_write("ERR setup: optionally a saved network number 1 to 8\r\n");return true;}slot=(unsigned)n;}
  if(gateway_boot_recovery()){mgmt_write("ERR Setup is not available in recovery mode; use retry-startup\r\n");return true;}
  if(setup_active){setup_preselect=slot;mgmt_write("OK setup already open\r\n");return true;}
  mgmt_write("OK restarting into setup\r\ndone>\r\n");vTaskDelay(pdMS_TO_TICKS(300));setup_restart(SETUP_REQUEST_ENTER,slot);return true;
 }
 if(!strcmp(line,"cancel")){
  /* Leave setup for normal mode (v0.1.1). Outside setup it stays the no-op clients send after a `profile`. */
  if(setup_active){mgmt_write("OK leaving setup; restarting\r\ndone>\r\n");vTaskDelay(pdMS_TO_TICKS(300));setup_restart(SETUP_REQUEST_LEAVE,0);return true;}
  mgmt_write("OK setup saved\r\n");return true;
 }
 if(!strcmp(line,"reset")){
  /* Factory reset, step one of two (v0.1.1): forget the saved networks and the display settings, but only after `confirm-reset` within 10 s. */
  factory_reset_until_ms=(uint32_t)(esp_timer_get_time()/1000)+10000;factory_reset_armed=true;
  mgmt_write("Confirm within 10 seconds: confirm-reset\r\n");return true;
 }
 if(!strcmp(line,"confirm-reset")){
  uint32_t now=(uint32_t)(esp_timer_get_time()/1000);
  if(!factory_reset_armed || (int32_t)(now-factory_reset_until_ms)>=0){factory_reset_armed=false;mgmt_write("ERR reset confirmation expired\r\n");return true;}
  factory_reset_armed=false;
  if(xSemaphoreTake(members_lock,pdMS_TO_TICKS(1000))!=pdTRUE){mgmt_write("ERR Settings busy\r\n");return true;}
  bool erased=wifi_factory_reset();xSemaphoreGive(members_lock);
  if(!erased){mgmt_write("ERR Factory reset failed; storage could not be erased\r\n");return true;}
  mgmt_write("OK factory reset; restarting into setup\r\ndone>\r\n");vTaskDelay(pdMS_TO_TICKS(300));setup_restart(SETUP_REQUEST_ENTER,0);return true;
 }
 if(strcmp(line,"list") && strncmp(line,"profile ",8) && strncmp(line,"del ",4) && strncmp(line,"use ",4))return false;
 if(xSemaphoreTake(members_lock,pdMS_TO_TICKS(100))!=pdTRUE){mgmt_write("ERR Settings busy\r\n");return true;}
 if(!strcmp(line,"list"))for(unsigned i=0;i<wifi_saved.count;i++){snprintf(reply,sizeof(reply),"%u%s name=%.24s ssid=%s priority=%u\r\n",i+1,wifi_current==(int)i?"*":"",wifi_meta.slot[i].name,wifi_saved.profiles[i].ssid,(unsigned)wifi_meta.slot[i].priority);mgmt_write(reply);}
 else if(!strncmp(line,"profile ",8)){
  profile_t profile;int slot;
  if(!profile_parse_json(line+8,&slot,&profile) || slot>(int)wifi_saved.count)mgmt_write("ERR Refresh saved networks before editing\r\n");
  else if(wifi_save_with(profile.ssid,profile.pass,profile.name,profile.priority,false,slot)){snprintf(reply,sizeof(reply),"OK saved to slot %d; setup stays open\r\n",slot+1);mgmt_write(reply);}else {mgmt_write("ERR Wi-Fi could not be saved\r\n");}
  memset(&profile,0,sizeof(profile));
 }else if(!strncmp(line,"use ",4)){
  char *end;long slot=strtol(line+4,&end,10);
  /* Not during a setup boot: the one radio belongs to the access point, and joining a network would move it off its channel under the phone. */
  int result=*end?-1:setup_active?-3:wifi_use_profile(slot);
  if(result==0){
   /* v0.1.1: `use N` also makes N the preferred network, kept across restarts. The switch is already under way; a failed write only costs the preference. */
   bool kept=wifi_set_preferred((int)slot-1);
   snprintf(reply,sizeof(reply),kept?"OK switching to %ld\r\n":"OK switching to %ld (preference not saved)\r\n",slot);mgmt_write(reply);}
  else if(result==-2)mgmt_write("ERR Wi-Fi driver refused the network; previous setting kept\r\n");
  else if(result==-3)mgmt_write("ERR Not available while setup is open; finish with Done or cancel first\r\n");
  else mgmt_write("ERR Invalid saved network\r\n");
 }else{char *end;long slot=strtol(line+4,&end,10);if(*end || slot<1 || slot>(long)wifi_saved.count || !wifi_save_profile(wifi_saved.profiles[slot-1].ssid,"",true))mgmt_write("ERR Saved network could not be removed\r\n");else mgmt_write("OK deleted\r\n");}
 xSemaphoreGive(members_lock);return true;
}

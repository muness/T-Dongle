/* Same saved Wi-Fi store and mode setting over CDC, available without a USB IP. */
extern void mgmt_write(const char *s);
bool gateway_serial_command(const char *line) {
 char reply[768];
 if(!strcmp(line,"status")){
  tdongle_temperature t=tdongle_temperature_snapshot();
  wifi_link_info link=wifi_link_read();char rssi_buffer[5];const char *rssi_text=wifi_link_rssi_text(&link,rssi_buffer);
  snprintf(reply,sizeof(reply),"mode=%s trial=0 active=%d wifi=%s rssi=%s usb_enumerated=%d usb_transport_ready=%d host_interface_ready=unknown internet=not_checked\r\nfirmware=" GATEWAY_VERSION "\r\nuptime_ms=%llu free_heap=%lu\r\nchip_temperature valid=%d current_tenths=%ld peak_tenths=%ld sampled_uptime_ms=%lu errors=%lu age_ms=%lu samples=%lu changed_uptime_ms=%lu step_tenths=%d\r\n",
   gateway_tailnet_mode()?"tailnet":"adapter",wifi_current+1,online?"up":"joining",rssi_text,tud_mounted(),tud_ready(),(unsigned long long)(esp_timer_get_time()/1000),(unsigned long)esp_get_free_heap_size(),t.valid,(long)t.current_tenths,(long)t.peak_tenths,(unsigned long)t.sampled_at_ms,(unsigned long)t.errors,(unsigned long)t.age_ms,(unsigned long)t.samples,(unsigned long)t.changed_at_ms,TDONGLE_TEMPERATURE_STEP_TENTHS);mgmt_write(reply);
  {bool clock_valid=ml_derp_clock_valid();snprintf(reply,sizeof(reply),"clock=%s valid=%d sntp_restarts=%lu server=%s retry_in_ms=%lu\r\n",gw_clock_state(&sntp_clock,clock_valid,online),clock_valid,(unsigned long)sntp_clock.restarts,gw_clock_server_name[sntp_clock.server%GW_CLOCK_SERVERS],(unsigned long)sntp_clock.retry_in_ms);mgmt_write(reply);}
  if(wifi_link_line(reply,sizeof(reply),&link,&wifi_link_stats))mgmt_write(reply);
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
 if(!strcmp(line,"cancel")){mgmt_write("OK setup saved\r\n");return true;}
 if(strcmp(line,"list") && strncmp(line,"profile ",8) && strncmp(line,"del ",4) && strncmp(line,"use ",4))return false;
 if(xSemaphoreTake(members_lock,pdMS_TO_TICKS(100))!=pdTRUE){mgmt_write("ERR Settings busy\r\n");return true;}
 if(!strcmp(line,"list"))for(unsigned i=0;i<wifi_saved.count;i++){snprintf(reply,sizeof(reply),"%u%s name=%.24s ssid=%s priority=50\r\n",i+1,wifi_current==(int)i?"*":"",wifi_saved.profiles[i].ssid,wifi_saved.profiles[i].ssid);mgmt_write(reply);}
 else if(!strncmp(line,"profile ",8)){
  profile_t profile;int slot;
  if(!profile_parse_json(line+8,&slot,&profile) || slot>(int)wifi_saved.count)mgmt_write("ERR Refresh saved networks before editing\r\n");
  else if(wifi_save_at(profile.ssid,profile.pass,false,slot)){snprintf(reply,sizeof(reply),"OK saved to slot %d; setup stays open\r\n",slot+1);mgmt_write(reply);}else {mgmt_write("ERR Wi-Fi could not be saved\r\n");}
  memset(&profile,0,sizeof(profile));
 }else if(!strncmp(line,"use ",4)){
  char *end;long slot=strtol(line+4,&end,10);
  int result=*end?-1:wifi_use_profile(slot);
  if(result==0){snprintf(reply,sizeof(reply),"OK switching to %ld\r\n",slot);mgmt_write(reply);}
  else if(result==-2)mgmt_write("ERR Wi-Fi driver refused the network; previous setting kept\r\n");
  else mgmt_write("ERR Invalid saved network\r\n");
 }else{char *end;long slot=strtol(line+4,&end,10);if(*end || slot<1 || slot>(long)wifi_saved.count || !wifi_save_profile(wifi_saved.profiles[slot-1].ssid,"",true))mgmt_write("ERR Saved network could not be removed\r\n");else mgmt_write("OK deleted\r\n");}
 xSemaphoreGive(members_lock);return true;
}

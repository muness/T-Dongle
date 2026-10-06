#!/usr/bin/env python3
"""Compile the actual C status formatter, then parse its output with Android Java.

Usage: python tools/check-android-status.py /path/to/tdongle-android
Requires cc and JDK 17. No hardware or credentials are used.
"""
from pathlib import Path
import os, subprocess, sys
root=Path(__file__).resolve().parents[1]
android=Path(sys.argv[1]); build=root/'build-host/status-contract';build.mkdir(parents=True,exist_ok=True)
control=(root/'main/serial_setup.inc').read_text()
start=control.index('snprintf(reply,sizeof(reply),',control.index('serial_status(void)'))
formatter=control[start:control.index('mgmt_write(reply);',start)]
(build/'status.c').write_text('''#include <stdio.h>
#include <stdint.h>
#include "boot_health.h"
#include "tdongle_temperature.h"
static int online,mounted,ready,tailnet,wifi_current=0,setup_active=0;
static int gateway_tailnet_mode(void){return tailnet;}

static int gateway_online(void){return online;}
static int tud_mounted(void){return mounted;}
static int tud_ready(void){return ready;}
static uint64_t esp_timer_get_time(void){return 1234000;}
static unsigned esp_get_free_heap_size(void){return 219640;}
#define rssi_text (online?"-61":"unknown")
int main(void){char reply[768];tdongle_temperature t={.valid=true,.current_tenths=553,.peak_tenths=600};
for(tailnet=0;tailnet<2;tailnet++)for(online=0;online<2;online++)for(mounted=0;mounted<2;mounted++)for(ready=0;ready<2;ready++){
''' + formatter + '''fputs(reply,stdout);fputs("done>\\r\\n\\f",stdout);}return 0;}
''')
subprocess.run(['cc','-std=c11','-I',str(root/'main'),'-I',str(root/'../../components/tdongle_runtime/include'),str(build/'status.c'),'-o',str(build/'status')],check=True)
(build/'responses.txt').write_bytes(subprocess.check_output([str(build/'status')]))
# Compatibility rule independent of the JDK: Android end-anchors the chip_temperature line after errors=, so every
# later field must live on its own line and nothing may be appended to a line it parses.
import re
for reply in (build/'responses.txt').read_bytes().decode().split('\f')[:-1]:
    if not re.search(r'^chip_temperature valid=[01] current_tenths=\d+ peak_tenths=\d+ sampled_uptime_ms=\d+ errors=\d+\r$',reply,re.M):sys.exit('chip_temperature line gained trailing fields; put them on chip_temperature_detail')
(build/'StatusContract.java').write_text('''import java.nio.file.*;
import com.muness.tdongle.core.DongleStatus;
public class StatusContract {public static void main(String[] args)throws Exception{
String[] replies=Files.readString(Path.of(args[0])).split("\\f");
if(replies.length!=16)throw new AssertionError("Missing status combinations");
for(int i=0;i<replies.length;i++){DongleStatus s=DongleStatus.parse(replies[i]);
if(!s.mode.equals(i>=8?"tailnet":"adapter") || !s.chipTemperature.contains("55.3") || s.associated()!=((i%8)>=4) || s.usbEnumerated!=((i&2)!=0) || s.usbReady!=((i&1)!=0))throw new AssertionError("Wrong parsed status");}
System.out.println("Actual firmware status: all 16 mode/Wi-Fi/USB combinations accepted by Android's production parser");}}
''')
java=Path(os.environ.get('JAVA_HOME','/usr'))/'bin'
source=android/'core/src/main/java/com/muness/tdongle/core'
subprocess.run([str(java/'javac'),'-d',str(build),str(source/'DongleStatus.java'),str(source/'Telemetry.java'),str(build/'StatusContract.java')],check=True)
subprocess.run([str(java/'java'),'-cp',str(build),'StatusContract',str(build/'responses.txt')],check=True)

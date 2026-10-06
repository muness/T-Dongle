#include "../main/lcd_view.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static void frame(const char *folder,const char *name,const lcd_state *s) {
    lcd_view view;lcd_compose(s,"0.2.21",&view);if(view.layout==LCD_LAYOUT_STATUS){assert(strlen(view.title)<=13);assert(strlen(view.detail)<=26);assert(strlen(view.hint)<=26);}
    if(!folder)return;char path[512];snprintf(path,sizeof(path),"%s/%s.ppm",folder,name);FILE *f=fopen(path,"wb");assert(f);fprintf(f,"P6\n160 80\n255\n");
    for(unsigned y=0;y<80;y++){uint16_t pixels[160];lcd_render_row(&view,y,pixels);for(unsigned x=0;x<160;x++){unsigned v=pixels[x];unsigned char rgb[3]={((v>>11)&31)*255/31,((v>>5)&63)*255/63,(v&31)*255/31};fwrite(rgb,1,3,f);}}fclose(f);
}
int main(int argc,char **argv) {
    const char *out=argc>1?argv[1]:NULL;lcd_state s={0};lcd_view v;
    lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.title,"SET UP WI-FI"));frame(out,"wifi",&s);
    assert(!strcmp(v.detail,"Hold button: setup AP") && !strcmp(v.hint,"or App: Networks"));
    s.saved_wifi=true;lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.detail,"Trying saved Wi-Fi"));s.saved_wifi=false;
    s.bridge=true;lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.title,"SET UP WI-FI") && !strcmp(v.detail,"Hold button: setup AP") && !strcmp(v.hint,"or muness.com/T-Dongle"));frame(out,"bridge-setup",&s);
    s.wifi=true;lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.title,"WI-FI BRIDGE") && !strstr(v.detail,"internet"));assert(!strcmp(v.hint,"Waiting for USB host"));s.usb=true;lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.hint,"USB host connected"));frame(out,"bridge",&s);s=(lcd_state){0};
    s=(lcd_state){.wifi=true,.bridge=true,.usb_configured=true,.usb_suspended=true};lcd_compose(&s,"0.2.22",&v);assert(!strcmp(v.hint,"USB suspended") && strstr(v.footer,"USB SUSPENDED"));frame(out,"suspended",&s);
    s.bridge=false;s.ready=s.enabled=1;lcd_compose(&s,"0.2.22",&v);assert(!strcmp(v.title,"TAILNET READY") && !strcmp(v.hint,"USB suspended"));
    s.usb_configured=false;lcd_compose(&s,"0.2.22",&v);assert(!strcmp(v.hint,"Waiting for USB host"));
    s.usb_configured=true;s.usb_suspended=false;s.usb=true;lcd_compose(&s,"0.2.22",&v);assert(!strcmp(v.hint,"USB routing is ready"));s=(lcd_state){0};
    s.starting=true;frame(out,"starting",&s);s.starting=false;
    s.wifi=true;lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.title,"ADD A TAILNET"));frame(out,"empty",&s);
    s.saved=s.enabled=s.login=1;lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.title,"APPROVE LOGIN"));frame(out,"signin",&s);
    s.login=0;s.ready=1;frame(out,"ready",&s);lcd_compose(&s,"0.2.21",&v);assert(strstr(v.detail,"1 OF 1"));
    s.saved=s.enabled=3;s.ready=2;frame(out,"multiple",&s);lcd_compose(&s,"0.2.21",&v);assert(strstr(v.detail,"2 OF 3"));
    s.ready=0;s.failed=0;lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.detail,"Joining your tailnet") && !strcmp(v.hint,"Please wait"));frame(out,"connecting",&s);s.failed=1;frame(out,"retry",&s);lcd_compose(&s,"0.2.21",&v);assert(!strstr(v.title,"READY"));assert(!strcmp(v.detail,"Tailnet connection failed"));
    s.recovery=true;s.ready=1;frame(out,"recovery",&s);lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.title,"RECOVERY"));assert(!strcmp(v.detail,"App: Overview") && !strcmp(v.hint,"Tap Restart services"));
    s.installing=true;frame(out,"installing",&s);lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.title,"INSTALLING"));
    s=(lcd_state){.wifi=true,.enabled=UINT32_MAX,.ready=UINT32_MAX};lcd_compose(&s,"1234567890123456789",&v);assert(strlen(v.detail)<=26 && strlen(v.footer)<=26);
    /* Every visible state fits the actual glyph widths, not just the buffers. */
    for(unsigned mask=0;mask<2048;mask++) {
        lcd_state state={.bridge=mask&1,.wifi=mask&2,.saved_wifi=mask&4,.recovery=mask&8,.starting=mask&16,.installing=mask&32,.usb=mask&64,.saved=(mask&128)?3:0,.enabled=(mask&256)?3:0,.ready=(mask&512)?1:0,.login=(mask&1024)?1:0,.failed=1};
        lcd_compose(&state,"0.2.21",&v);assert(strlen(v.title)<=13 && strlen(v.detail)<=26 && strlen(v.hint)<=26 && strlen(v.footer)<=26);
        assert(!strstr(v.hint,"Progress") && !strstr(v.hint,"Devices in"));
    }
    for(unsigned y=0;y<81;y++){struct{uint16_t first,p[160],last;} guarded={.first=42,.last=43};lcd_render_row(&v,y,guarded.p);assert(guarded.first==42 && guarded.last==43);}
    /* ---- The restored v0.1.1 pages: Connection, Traffic, Health, Setup; signal strength and rates; the setup access point; the menu. */
    s=(lcd_state){.wifi=true,.bridge=true,.usb=true,.usb_configured=true,.rssi_valid=true,.rssi=-57,.ssid="HomeNet"};
    lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.title,"WI-FI BRIDGE") && !strcmp(v.extra,"HomeNet -57dBm") && v.layout==LCD_LAYOUT_STATUS);frame(out,"connection",&s);
    s.ssid[0]=0;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.extra,"Signal -57dBm"));
    s.rssi_valid=false;s.ssid[0]='H';s.ssid[1]=0;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.extra,"H"));
    s.ssid[0]=0;lcd_compose(&s,"0.3.0",&v);assert(!v.extra[0]);
    memset(s.ssid,'N',32);s.ssid[32]=0;s.rssi_valid=true;s.rssi=-100;lcd_compose(&s,"0.3.0",&v);assert(strlen(v.extra)==26 && !strcmp(v.extra+26-7,"-100dBm"));   /* a 32 character name is cut to leave the signal */
    s.rssi=500;lcd_compose(&s,"0.3.0",&v);assert(strstr(v.extra,"0dBm") && !strstr(v.extra,"500"));
    s=(lcd_state){.rssi_valid=true,.rssi=-50,.ssid="Joining"};lcd_compose(&s,"0.3.0",&v);assert(!v.extra[0]);   /* no signal line while not joined */
    s=(lcd_state){.wifi=true,.saved=1,.enabled=1,.ready=1,.usb=true,.rssi_valid=true,.rssi=-71,.ssid="Office"};
    lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.title,"TAILNET READY") && !strcmp(v.extra,"Office -71dBm"));   /* signal strength in tailnet mode too */
    /* Traffic */
    s=(lcd_state){.page=1,.wifi=true,.bridge=true,.down_kbps=1234,.up_kbps=56,.down_bytes=12345678,.up_bytes=2345678,.down_frames=1234567,.up_frames=89};
    for(unsigned i=0;i<LCD_BARS;i++)s.bars[i]=(uint8_t)(i%21);
    lcd_compose(&s,"0.3.0",&v);
    assert(v.layout==LCD_LAYOUT_ROWS && !strcmp(v.row[0],"TRAFFIC") && !strcmp(v.row[1],"D 1.23 U 0.05 Mb/s") && !strcmp(v.row[2],"D 12.3 U 2.3 MB") && !strcmp(v.row[3],"Frames D 1234k U 89") && v.bar_count==LCD_BARS && v.bars[20]==20);
    frame(out,"traffic",&s);
    s.down_bytes=s.up_bytes=0;s.down_kbps=s.up_kbps=0;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.row[1],"D 0.00 U 0.00 Mb/s") && !strcmp(v.row[2],"D 0.0 U 0.0 MB"));
    s.down_kbps=0xffffffffu;s.down_bytes=~0ull;s.down_frames=~0ull;lcd_compose(&s,"0.3.0",&v);for(unsigned r=0;r<LCD_ROWS;r++)assert(strlen(v.row[r])<=26);   /* nothing a counter can hold overflows a row */
    /* Health: three views, rotated by the caller */
    s=(lcd_state){.page=2,.uptime_s=3*3600+12*60,.wifi_up_s=3*3600+10*60,.connects=4,.last_reason=201,.usb_resets=2,.heap_free=123456,.heap_min=98765,.heap_largest=55000,.reset_reason=3,.boots=5,.watchdogs=1,.panics=2};
    lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.row[0],"HEALTH 1/3") && !strcmp(v.row[1],"Up 3h12m WiFi 3h10m") && !strcmp(v.row[2],"Joins 4 Reason 201") && !strcmp(v.row[3],"USB resets 2") && !strcmp(v.row[4],"Details rotate every 4s"));frame(out,"health1",&s);
    s.health_view=1;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.row[0],"HEALTH 2/3") && !strcmp(v.row[1],"Heap 123456") && !strcmp(v.row[2],"Min heap 98765") && !strcmp(v.row[3],"Largest 55000 Rst 3"));frame(out,"health2",&s);
    s.health_view=2;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.row[0],"HEALTH 3/3") && !strcmp(v.row[1],"Session boots 5") && !strcmp(v.row[2],"WDT 1 Panic 2") && !strcmp(v.row[3],"No recovery needed") && !v.attention);frame(out,"health3",&s);
    s.recovery=true;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.row[3],"Recovery: services off") && v.attention);   /* the page stays reachable in recovery */
    s.health_view=7;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.row[0],"HEALTH 2/3"));
    char d[16];
    lcd_format_duration(d,sizeof(d),0);assert(!strcmp(d,"0s"));lcd_format_duration(d,sizeof(d),59);assert(!strcmp(d,"59s"));lcd_format_duration(d,sizeof(d),60);assert(!strcmp(d,"1m00s"));
    lcd_format_duration(d,sizeof(d),3599);assert(!strcmp(d,"59m59s"));lcd_format_duration(d,sizeof(d),3600);assert(!strcmp(d,"1h00m"));lcd_format_duration(d,sizeof(d),86399);assert(!strcmp(d,"23h59m"));
    lcd_format_duration(d,sizeof(d),86400);assert(!strcmp(d,"1d00h"));lcd_format_duration(d,sizeof(d),UINT32_MAX);assert(!strcmp(d,"49710d06h") && strlen(d)<=9);
    lcd_format_count(d,sizeof(d),0);assert(!strcmp(d,"0"));lcd_format_count(d,sizeof(d),999999);assert(!strcmp(d,"999999"));lcd_format_count(d,sizeof(d),1000000);assert(!strcmp(d,"1000k"));
    lcd_format_count(d,sizeof(d),999999999);assert(!strcmp(d,"999999k"));lcd_format_count(d,sizeof(d),1000000000ull);assert(!strcmp(d,"1000M"));lcd_format_count(d,sizeof(d),~0ull);assert(strlen(d)<=7);
    /* Setup page */
    s=(lcd_state){.page=3,.bridge=true,.saved_wifi=true,.active_slot=2};strcpy(s.active_name,"Phone hotspot");
    lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.row[0],"SETUP / NETWORKS") && !strcmp(v.row[1],"2 Phone hotspot") && !strcmp(v.row[2],"Mode: Wi-Fi bridge") && !strcmp(v.row[3],"Hold to open menu") && !strcmp(v.row[4],"Hold BOOT at plug: ROM"));frame(out,"setup-page",&s);
    s.active_slot=0;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.row[1],"No network joined"));s.saved_wifi=false;s.bridge=false;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.row[1],"No Wi-Fi saved") && !strcmp(v.row[2],"Mode: tailnet gateway"));
    /* A page number out of range shows the Connection page; overlays beat every page. */
    s=(lcd_state){.page=9,.wifi=true,.bridge=true};lcd_compose(&s,"0.3.0",&v);assert(v.layout==LCD_LAYOUT_STATUS && !strcmp(v.title,"WI-FI BRIDGE"));
    for(unsigned page=0;page<LCD_PAGES;page++){s=(lcd_state){.page=page,.installing=true};lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.title,"INSTALLING"));s=(lcd_state){.page=page,.starting=true};lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.title,"STARTING"));}
    s=(lcd_state){.page=1,.recovery=true,.wifi=true};lcd_compose(&s,"0.3.0",&v);assert(v.layout==LCD_LAYOUT_ROWS);   /* recovery is the Connection page's content only */
    s.page=0;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.title,"RECOVERY") && v.attention);
    /* The setup access point: what to join, where to go, when it closes. It replaces every page. */
    s=(lcd_state){.page=2,.setup=true,.bridge=true,.setup_seconds_left=581};strcpy(s.ap_ssid,"TDongle-AB0CF9");
    lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.title,"SETUP WI-FI") && !strcmp(v.detail,"Join TDongle-AB0CF9") && !strcmp(v.hint,"Then open 192.168.4.1") && !strcmp(v.extra,"No password. Closes 9:41") && strstr(v.footer,"Hold: menu"));frame(out,"setup-ap",&s);
    s.setup_seconds_left=0;lcd_compose(&s,"0.3.0",&v);assert(strstr(v.extra,"0:00"));s.setup_seconds_left=600;lcd_compose(&s,"0.3.0",&v);assert(strstr(v.extra,"10:00"));s.setup_seconds_left=UINT32_MAX;lcd_compose(&s,"0.3.0",&v);assert(strlen(v.extra)<=26);
    s.installing=true;lcd_compose(&s,"0.3.0",&v);assert(!strcmp(v.title,"INSTALLING"));
    /* The menu: rows exactly as the menu produced them. */
    char rows[LCD_ROWS][27]={"SETUP MENU","1 Home","","Short: next  Hold: select",""};
    lcd_compose_rows(&v,(const char (*)[27])rows,false);assert(v.layout==LCD_LAYOUT_ROWS && !strcmp(v.row[0],"SETUP MENU") && !strcmp(v.row[1],"1 Home") && !v.attention && !v.bar_count);
    {lcd_view shot;lcd_compose_rows(&shot,(const char (*)[27])rows,false);if(out){char path[512];snprintf(path,sizeof(path),"%s/menu.ppm",out);FILE *f=fopen(path,"wb");assert(f);fprintf(f,"P6\n160 80\n255\n");for(unsigned y=0;y<80;y++){uint16_t px[160];lcd_render_row(&shot,y,px);for(unsigned x=0;x<160;x++){unsigned c=px[x];unsigned char rgb[3]={((c>>11)&31)*255/31,((c>>5)&63)*255/63,(c&31)*255/31};fwrite(rgb,1,3,f);}}fclose(f);}}
    strcpy(rows[0],"CONFIRM FACTORY RESET");lcd_compose_rows(&v,(const char (*)[27])rows,true);assert(v.attention);
    /* Every state of every page fits: no string beyond the glyph columns, whatever the snapshot holds. */
    for(unsigned mask=0;mask<1024;mask++) {
        lcd_state state={.bridge=mask&1,.wifi=mask&2,.saved_wifi=mask&4,.recovery=mask&8,.setup=mask&16,.usb=mask&32,.rssi_valid=mask&64,.saved=(mask&128)?3:0,.enabled=(mask&128)?3:0,.ready=(mask&256)?1:0,.login=(mask&512)?1:0,.failed=1,
                         .rssi=-127,.down_kbps=UINT32_MAX,.up_kbps=UINT32_MAX,.down_bytes=~0ull,.up_bytes=~0ull,.down_frames=~0ull,.up_frames=~0ull,.uptime_s=UINT32_MAX,.wifi_up_s=UINT32_MAX,.connects=UINT32_MAX,.last_reason=UINT32_MAX,
                         .usb_resets=UINT32_MAX,.heap_free=UINT32_MAX,.heap_min=UINT32_MAX,.heap_largest=UINT32_MAX,.reset_reason=UINT32_MAX,.boots=UINT32_MAX,.watchdogs=UINT32_MAX,.panics=UINT32_MAX,.setup_seconds_left=UINT32_MAX,.active_slot=UINT32_MAX};
        memset(state.ssid,'W',32);memset(state.ap_ssid,'A',15);memset(state.active_name,'n',24);
        for(unsigned page=0;page<LCD_PAGES;page++)for(unsigned view=0;view<3;view++){
            state.page=page;state.health_view=view;lcd_compose(&state,"1234567890123456789",&v);
            if(v.layout==LCD_LAYOUT_STATUS)assert(strlen(v.title)<=13 && strlen(v.detail)<=26 && strlen(v.hint)<=26 && strlen(v.extra)<=26 && strlen(v.footer)<=26);
            else for(unsigned r=0;r<LCD_ROWS;r++)assert(strlen(v.row[r])<=26);   /* the layouts share storage */
        }
    }
    /* Scanline canaries for both layouts and the graph. */
    s=(lcd_state){.page=1,.wifi=true};for(unsigned i=0;i<LCD_BARS;i++)s.bars[i]=20;lcd_compose(&s,"0.3.0",&v);
    for(unsigned y=0;y<81;y++){struct{uint16_t first,p[160],last;} guarded={.first=42,.last=43};lcd_render_row(&v,y,guarded.p);assert(guarded.first==42 && guarded.last==43);}
    {uint16_t px[160];lcd_render_row(&v,79,px);unsigned lit=0;for(unsigned x=0;x<160;x++)if(px[x]==0x86b8)lit++;assert(lit==LCD_BARS*4);   /* a full-height bar is lit on the bottom row: 32 bars of 4 px */
     lcd_render_row(&v,59,px);lit=0;for(unsigned x=0;x<160;x++)if(px[x]==0x86b8)lit++;assert(lit==0);   /* and nothing above its 20 px */
     lcd_render_row(&v,60,px);lit=0;for(unsigned x=0;x<160;x++)if(px[x]==0x86b8)lit++;assert(lit==LCD_BARS*4);}
    s.bars[3]=0;lcd_compose(&s,"0.3.0",&v);{uint16_t px[160];lcd_render_row(&v,79,px);assert(px[3*5]==0x86b8);lcd_render_row(&v,78,px);assert(px[3*5]!=0x86b8);}   /* a zero reading is still a 1 px stub, so an idle link shows a baseline */
    puts("LCD: 0/1/N, unready/recovery precedence, bounded labels and scanline canaries pass; Connection signal line, Traffic, Health, Setup pages, setup AP screen and menu rows");
}

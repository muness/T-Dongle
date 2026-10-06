#include "lcd_view.h"
#include "traffic.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
static void put(char *dst,size_t cap,const char *text){snprintf(dst,cap,"%s",text);}
void lcd_format_duration(char *out,unsigned size,uint32_t s) {
    char text[24];   /* the widest is "49710d23h": a 32 bit second count */
    if(s<60)snprintf(text,sizeof(text),"%us",(unsigned)s);
    else if(s<3600)snprintf(text,sizeof(text),"%um%02us",(unsigned)(s/60),(unsigned)(s%60));
    else if(s<86400)snprintf(text,sizeof(text),"%uh%02um",(unsigned)(s/3600),(unsigned)(s%3600/60));
    else snprintf(text,sizeof(text),"%ud%02uh",(unsigned)(s/86400),(unsigned)(s%86400/3600));
    snprintf(out,size,"%s",text);
}
/* A count in at most 7 characters: 123456, 1234k, 1234M. */
void lcd_format_count(char *out,unsigned size,uint64_t n) {
    char text[24];
    if(n<1000000)snprintf(text,sizeof(text),"%u",(unsigned)n);
    else if(n<1000000000ull)snprintf(text,sizeof(text),"%uk",(unsigned)(n/1000));
    else snprintf(text,sizeof(text),"%uM",(unsigned)(n/1000000>999999?999999:n/1000000));
    snprintf(out,size,"%s",text);
}
/* The joined network and its signal: "HomeNet -57dBm". Shown on the Connection page whenever Wi-Fi is joined. */
static void signal_line(const lcd_state *s,char *out,size_t cap) {
    out[0]=0;
    if(!s->wifi)return;
    char level[12]="";
    if(s->rssi_valid)snprintf(level,sizeof(level),"%ddBm",s->rssi>0?0:s->rssi<-127?-127:s->rssi);
    if(s->ssid[0]&&level[0])snprintf(out,cap,"%.*s %s",(int)(26-1-strlen(level)),s->ssid,level);
    else if(s->ssid[0])snprintf(out,cap,"%.26s",s->ssid);
    else if(level[0])snprintf(out,cap,"Signal %s",level);
}
static void compose_connection(const lcd_state *s,const char *version,lcd_view *v) {
    const char *title,*detail,*hint;
    bool suspended=s->usb_configured && s->usb_suspended;
    const char *usb_wait=suspended?"USB suspended":"Waiting for USB host";
    if(s->installing){title="INSTALLING";detail="Installing firmware";hint="Keep USB plugged in";}
    else if(s->starting){title="STARTING";detail="Starting dongle services";hint="Please wait";}
    else if(s->recovery){title="RECOVERY";detail="App: Overview";hint="Tap Restart services";v->attention=true;}
    else if(!s->wifi){
        title=s->saved_wifi?"JOINING WI-FI":"SET UP WI-FI";
        detail=s->saved_wifi?"Trying saved Wi-Fi":"App: Networks";
        hint=s->saved_wifi?"App: Networks to change":"Add a 2.4 GHz network";
        /* Bridge mode has no USB web page: Wi-Fi is added with the button (setup access point), the flash page or the app. */
        if(s->bridge && !s->saved_wifi){detail="Hold button: setup AP";hint="or muness.com/T-Dongle";}
        else if(!s->saved_wifi){detail="Hold button: setup AP";hint="or App: Networks";}
    }
    else if(s->bridge){title="WI-FI BRIDGE";detail="Wi-Fi connected";hint=s->usb?"USB host connected":usb_wait;}
    else if(s->login){title="APPROVE LOGIN";detail="App: Networks - Sign in";hint="Approve in your browser";}
    else if(s->ready){title="TAILNET READY";detail="Wi-Fi connected";hint=!s->usb?usb_wait:s->ready<s->enabled?"App: Networks for details":"USB routing is ready";}
    else if(!s->enabled){title=s->saved?"TAILNET OFF":"ADD A TAILNET";detail=s->saved?"Wi-Fi connected":"App: Networks";hint=s->saved?"App: Networks - Reconnect":"Sign in with Tailscale";}
    else {title=s->failed?"RETRYING":"CONNECTING";detail=s->failed?"Tailnet connection failed":"Joining your tailnet";hint=s->failed?"App: Networks for details":"Please wait";v->attention=s->failed>0;}
    put(v->title,sizeof(v->title),title);put(v->detail,sizeof(v->detail),detail);put(v->hint,sizeof(v->hint),hint);
    if(!s->bridge && s->ready && !s->recovery && !s->installing && !s->starting && !s->login && s->wifi)
        snprintf(v->detail,sizeof(v->detail),"%u OF %u TAILNET%s READY",s->ready>999?999:s->ready,s->enabled>999?999:s->enabled,s->enabled==1?"":"S");
    if(!s->installing && !s->starting && !s->recovery)signal_line(s,v->extra,sizeof(v->extra));
    snprintf(v->footer,sizeof(v->footer),"v%.10s  USB %s",version,s->usb?"READY":suspended?"SUSPENDED":"NOT READY");
}
/* The setup access point: how to join it and when it closes. */
static void compose_setup_ap(const lcd_state *s,const char *version,lcd_view *v) {
    put(v->title,sizeof(v->title),"SETUP WI-FI");
    snprintf(v->detail,sizeof(v->detail),"Join %.20s",s->ap_ssid);
    put(v->hint,sizeof(v->hint),"Then open 192.168.4.1");
    {unsigned left=s->setup_seconds_left>5999?5999:s->setup_seconds_left;snprintf(v->extra,sizeof(v->extra),"No password. Closes %u:%02u",left/60,left%60);}
    snprintf(v->footer,sizeof(v->footer),"v%.10s  Hold: menu",version);
}
static void compose_traffic(const lcd_state *s,lcd_view *v) {
    char down[12],up[12],down_mb[16],up_mb[16];
    v->layout=LCD_LAYOUT_ROWS;
    put(v->row[0],sizeof(v->row[0]),"TRAFFIC");
    traffic_format_mbps(down,sizeof(down),s->down_kbps);traffic_format_mbps(up,sizeof(up),s->up_kbps);
    snprintf(v->row[1],sizeof(v->row[1]),"D %.6s U %.6s Mb/s",down,up);   /* 9 Mb/s at most on this link: six characters hold it */
    traffic_format_megabytes(down_mb,sizeof(down_mb),s->down_bytes);traffic_format_megabytes(up_mb,sizeof(up_mb),s->up_bytes);
    snprintf(v->row[2],sizeof(v->row[2]),"D %.8s U %.8s MB",down_mb,up_mb);
    char down_frames[10],up_frames[10];
    lcd_format_count(down_frames,sizeof(down_frames),s->down_frames);lcd_format_count(up_frames,sizeof(up_frames),s->up_frames);
    snprintf(v->row[3],sizeof(v->row[3]),"Frames D %.7s U %.7s",down_frames,up_frames);
    memcpy(v->bars,s->bars,sizeof(v->bars));v->bar_count=LCD_BARS;
}
static void compose_health(const lcd_state *s,lcd_view *v) {
    char up[10],wifi[10];
    unsigned view=s->health_view%3;
    v->layout=LCD_LAYOUT_ROWS;
    snprintf(v->row[0],sizeof(v->row[0]),"HEALTH %u/3",view+1);
    if(view==0){
        lcd_format_duration(up,sizeof(up),s->uptime_s);lcd_format_duration(wifi,sizeof(wifi),s->wifi_up_s);
        snprintf(v->row[1],sizeof(v->row[1]),"Up %.8s WiFi %.8s",up,wifi);
        snprintf(v->row[2],sizeof(v->row[2]),"Joins %lu Reason %lu",(unsigned long)s->connects,(unsigned long)s->last_reason);
        snprintf(v->row[3],sizeof(v->row[3]),"USB resets %lu",(unsigned long)s->usb_resets);
    }else if(view==1){
        snprintf(v->row[1],sizeof(v->row[1]),"Heap %lu",(unsigned long)s->heap_free);
        snprintf(v->row[2],sizeof(v->row[2]),"Min heap %lu",(unsigned long)s->heap_min);
        snprintf(v->row[3],sizeof(v->row[3]),"Largest %lu Rst %lu",(unsigned long)s->heap_largest,(unsigned long)s->reset_reason);
    }else{
        snprintf(v->row[1],sizeof(v->row[1]),"Session boots %lu",(unsigned long)s->boots);
        snprintf(v->row[2],sizeof(v->row[2]),"WDT %lu Panic %lu",(unsigned long)s->watchdogs,(unsigned long)s->panics);
        put(v->row[3],sizeof(v->row[3]),s->recovery?"Recovery: services off":"No recovery needed");
        v->attention=s->recovery;
    }
    put(v->row[4],sizeof(v->row[4]),"Details rotate every 4s");
}
static void compose_setup_page(const lcd_state *s,lcd_view *v) {
    v->layout=LCD_LAYOUT_ROWS;
    put(v->row[0],sizeof(v->row[0]),"SETUP / NETWORKS");
    if(s->active_slot)snprintf(v->row[1],sizeof(v->row[1]),"%u %.22s",s->active_slot%10,s->active_name);
    else put(v->row[1],sizeof(v->row[1]),s->saved_wifi?"No network joined":"No Wi-Fi saved");
    put(v->row[2],sizeof(v->row[2]),s->bridge?"Mode: Wi-Fi bridge":"Mode: tailnet gateway");
    put(v->row[3],sizeof(v->row[3]),"Hold to open menu");
    put(v->row[4],sizeof(v->row[4]),"Hold BOOT at plug: ROM");
}
void lcd_compose(const lcd_state *s,const char *version,lcd_view *v) {
    memset(v,0,sizeof(*v));
    bool overlay=s->installing||s->starting;
    if(s->setup && !overlay){compose_setup_ap(s,version,v);return;}
    unsigned page=s->page<LCD_PAGES?s->page:0;
    if(overlay||page==0)compose_connection(s,version,v);
    else if(page==1)compose_traffic(s,v);
    else if(page==2)compose_health(s,v);
    else compose_setup_page(s,v);
}
void lcd_compose_rows(lcd_view *v,const char rows[LCD_ROWS][27],bool attention) {
    memset(v,0,sizeof(*v));
    v->layout=LCD_LAYOUT_ROWS;v->attention=attention;
    for(unsigned i=0;i<LCD_ROWS;i++)snprintf(v->row[i],sizeof(v->row[i]),"%s",rows[i]);
}
/* Small fixed glyphs kept in flash. Unsupported characters render as '?'. */
static const struct {char c;uint8_t row[7];} glyphs[]={
 {'A',{14,17,17,31,17,17,17}},{'B',{30,17,17,30,17,17,30}},{'C',{14,17,16,16,16,17,14}},
 {'D',{30,17,17,17,17,17,30}},{'E',{31,16,16,30,16,16,31}},{'F',{31,16,16,30,16,16,16}},
 {'G',{14,17,16,23,17,17,15}},{'H',{17,17,17,31,17,17,17}},{'I',{31,4,4,4,4,4,31}},
 {'J',{7,2,2,2,18,18,12}},{'K',{17,18,20,24,20,18,17}},{'L',{16,16,16,16,16,16,31}},
 {'M',{17,27,21,21,17,17,17}},{'N',{17,25,25,21,19,19,17}},{'O',{14,17,17,17,17,17,14}},
 {'P',{30,17,17,30,16,16,16}},{'Q',{14,17,17,17,21,18,13}},{'R',{30,17,17,30,20,18,17}},
 {'S',{15,16,16,14,1,1,30}},{'T',{31,4,4,4,4,4,4}},{'U',{17,17,17,17,17,17,14}},
 {'V',{17,17,17,17,17,10,4}},{'W',{17,17,17,21,21,21,10}},{'X',{17,17,10,4,10,17,17}},
 {'Y',{17,17,10,4,4,4,4}},{'Z',{31,1,2,4,8,16,31}},
 {'0',{14,17,19,21,25,17,14}},{'1',{4,12,4,4,4,4,14}},{'2',{14,17,1,2,4,8,31}},
 {'3',{30,1,1,14,1,1,30}},{'4',{2,6,10,18,31,2,2}},{'5',{31,16,16,30,1,1,30}},
 {'6',{14,16,16,30,17,17,14}},{'7',{31,1,2,4,8,8,8}},{'8',{14,17,17,14,17,17,14}},
 {'9',{14,17,17,15,1,1,14}},{'-',{0,0,0,31,0,0,0}},{'.',{0,0,0,0,0,6,6}},
 {':',{0,6,6,0,6,6,0}},{'/',{1,2,2,4,8,8,16}},{',',{0,0,0,0,6,4,8}},{';',{0,6,6,0,6,4,8}},
 {'<',{2,4,8,16,8,4,2}},{'(',{2,4,8,8,8,4,2}},{')',{8,4,2,2,2,4,8}},{'+',{0,4,4,31,4,4,0}},
 {'%',{25,25,2,4,8,19,19}},{'=',{0,0,31,0,31,0,0}},
 {'?',{14,17,1,2,4,0,4}},{' ',{0}}
};
static unsigned glyph(char c,unsigned row) {
    c=(char)toupper((unsigned char)c);
    const unsigned count=sizeof(glyphs)/sizeof(glyphs[0]);
    for(unsigned i=0;i<count;i++)if(glyphs[i].c==c)return glyphs[i].row[row];
    return glyphs[count-2].row[row];   /* '?' */
}
static void line(uint16_t *out,unsigned y,unsigned top,unsigned scale,const char *text,uint16_t color) {
    if(y<top || y>=top+7*scale)return;
    unsigned row=(y-top)/scale;
    for(unsigned i=0;text[i] && i<26;i++)for(unsigned x=0;x<5*scale;x++) {
        unsigned pixel=3+i*6*scale+x;if(pixel>=157)break;
        if(glyph(text[i],row)&(1u<<(4-x/scale)))out[pixel]=color;
    }
}
enum {BACKGROUND=0x10a2,ACCENT=0x86b8,ATTENTION=0xff37,TEXT=0xdf3c,RULE=0x3a68,FOOTER=0xb637,MUTED=0x9d75};
static void bars(uint16_t *out,unsigned y,const lcd_view *v) {
    /* Traffic graph: LCD_BARS bars of 4 px at a 5 px pitch, growing up from the bottom edge (row 79), at most 20 px tall. */
    if(y<60)return;
    unsigned height_from_bottom=79-y+1;
    for(unsigned i=0;i<v->bar_count && i<LCD_BARS;i++){
        unsigned h=v->bars[i]>20?20:v->bars[i];if(!h)h=1;
        if(height_from_bottom<=h)for(unsigned x=0;x<4;x++)if(i*5+x<160)out[i*5+x]=ACCENT;
    }
}
void lcd_render_row(const lcd_view *v,unsigned y,uint16_t out[160]) {
    for(unsigned x=0;x<160;x++)out[x]=BACKGROUND;
    if(y>=80)return;
    if(v->layout==LCD_LAYOUT_ROWS){
        for(unsigned i=0;i<LCD_ROWS;i++)line(out,y,4+13*i,1,v->row[i],i==0?(v->attention?ATTENTION:ACCENT):TEXT);
        bars(out,y,v);
        return;
    }
    line(out,y,8,2,v->title,v->attention?ATTENTION:ACCENT);
    line(out,y,28,1,v->detail,TEXT);line(out,y,39,1,v->hint,TEXT);line(out,y,50,1,v->extra,MUTED);
    if(y==63)for(unsigned x=3;x<157;x++)out[x]=RULE;
    line(out,y,69,1,v->footer,FOOTER);
}

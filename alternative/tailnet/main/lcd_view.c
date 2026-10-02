#include "lcd_view.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
void lcd_compose(const lcd_state *s,const char *version,lcd_view *v) {
    memset(v,0,sizeof(*v));
    const char *title,*detail,*hint;
    if(s->installing){title="INSTALLING";detail="Follow progress in app";hint="Keep USB connected";}
    else if(s->starting){title="STARTING";detail="Preparing your dongle";hint="Settings stay saved";}
    else if(s->recovery){title="RECOVERY";detail="Settings are preserved";hint="App: Restart services";v->attention=true;}
    else if(!s->wifi){title=s->saved_wifi?"JOINING WI-FI":"SET UP WI-FI";detail="Open Networks in the app";hint="Use a 2.4 GHz network";}
    else if(s->login){title="SIGN IN";detail="Open Networks in the app";hint="Approve in your browser";}
    else if(s->ready){title="ROUTING READY";detail="Wi-Fi connected";hint="Devices in Networks";}
    else if(!s->enabled){title=s->saved?"DISCONNECTED":"ADD A TAILNET";detail="Wi-Fi connected";hint=s->saved?"Reconnect in Networks":"Sign in from Networks";}
    else {title=s->failed?"RECONNECTING":"CONNECTING";detail="Wi-Fi connected";hint="Progress in Networks";v->attention=s->failed>0;}
    snprintf(v->title,sizeof(v->title),"%s",title);snprintf(v->detail,sizeof(v->detail),"%s",detail);snprintf(v->hint,sizeof(v->hint),"%s",hint);
    if(s->ready && !s->recovery && !s->installing && !s->starting && !s->login && s->wifi)
        snprintf(v->detail,sizeof(v->detail),"%u OF %u TAILNET%s READY",s->ready>999?999:s->ready,s->enabled>999?999:s->enabled,s->enabled==1?"":"S");
    snprintf(v->footer,sizeof(v->footer),"v%.10s  USB %s",version,s->usb?"READY":"WAIT");
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
 {':',{0,6,6,0,6,6,0}},{'/',{1,2,2,4,8,8,16}},{'?',{14,17,1,2,4,0,4}},{' ',{0}}
};
static unsigned glyph(char c,unsigned row) {
    c=(char)toupper((unsigned char)c);
    for(unsigned i=0;i<sizeof(glyphs)/sizeof(glyphs[0]);i++)if(glyphs[i].c==c)return glyphs[i].row[row];
    return glyphs[sizeof(glyphs)/sizeof(glyphs[0])-2].row[row];
}
static void line(uint16_t *out,unsigned y,unsigned top,unsigned scale,const char *text,uint16_t color) {
    if(y<top || y>=top+7*scale)return;
    unsigned row=(y-top)/scale;
    for(unsigned i=0;text[i] && i<26;i++)for(unsigned x=0;x<5*scale;x++) {
        unsigned pixel=3+i*6*scale+x;if(pixel>=157)break;
        if(glyph(text[i],row)&(1u<<(4-x/scale)))out[pixel]=color;
    }
}
void lcd_render_row(const lcd_view *v,unsigned y,uint16_t out[160]) {
    for(unsigned x=0;x<160;x++)out[x]=0x10a2;
    if(y>=80)return;
    line(out,y,8,2,v->title,v->attention?0xff37:0x86b8);
    line(out,y,34,1,v->detail,0xdf3c);line(out,y,47,1,v->hint,0xdf3c);
    if(y==63)for(unsigned x=3;x<157;x++)out[x]=0x3a68;
    line(out,y,69,1,v->footer,0xb637);
}

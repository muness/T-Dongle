#include "../main/lcd_view.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static void frame(const char *folder,const char *name,const lcd_state *s) {
    lcd_view view;lcd_compose(s,"0.2.21",&view);assert(strlen(view.title)<=13);assert(strlen(view.detail)<=26);assert(strlen(view.hint)<=26);
    if(!folder)return;char path[512];snprintf(path,sizeof(path),"%s/%s.ppm",folder,name);FILE *f=fopen(path,"wb");assert(f);fprintf(f,"P6\n160 80\n255\n");
    for(unsigned y=0;y<80;y++){uint16_t pixels[160];lcd_render_row(&view,y,pixels);for(unsigned x=0;x<160;x++){unsigned v=pixels[x];unsigned char rgb[3]={((v>>11)&31)*255/31,((v>>5)&63)*255/63,(v&31)*255/31};fwrite(rgb,1,3,f);}}fclose(f);
}
int main(int argc,char **argv) {
    const char *out=argc>1?argv[1]:NULL;lcd_state s={0};lcd_view v;
    lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.title,"SET UP WI-FI"));frame(out,"wifi",&s);
    assert(!strcmp(v.hint,"Add a 2.4 GHz network"));
    s.saved_wifi=true;lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.detail,"Trying saved Wi-Fi"));s.saved_wifi=false;
    s.bridge=true;s.wifi=true;lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.title,"WI-FI BRIDGE") && !strstr(v.detail,"internet"));assert(!strcmp(v.hint,"Waiting for USB host"));s.usb=true;lcd_compose(&s,"0.2.21",&v);assert(!strcmp(v.hint,"USB host connected"));frame(out,"bridge",&s);s=(lcd_state){0};
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
    puts("LCD: 0/1/N, unready/recovery precedence, bounded labels and scanline canaries pass");
}

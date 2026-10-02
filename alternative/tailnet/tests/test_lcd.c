#include "../main/lcd_view.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static void frame(const char *folder,const char *name,const lcd_state *s) {
    lcd_view view;lcd_compose(s,"0.2.15",&view);assert(strlen(view.title)<=13);assert(strlen(view.detail)<=26);assert(strlen(view.hint)<=26);
    if(!folder)return;char path[512];snprintf(path,sizeof(path),"%s/%s.ppm",folder,name);FILE *f=fopen(path,"wb");assert(f);fprintf(f,"P6\n160 80\n255\n");
    for(unsigned y=0;y<80;y++){uint16_t pixels[160];lcd_render_row(&view,y,pixels);for(unsigned x=0;x<160;x++){unsigned v=pixels[x];unsigned char rgb[3]={((v>>11)&31)*255/31,((v>>5)&63)*255/63,(v&31)*255/31};fwrite(rgb,1,3,f);}}fclose(f);
}
int main(int argc,char **argv) {
    const char *out=argc>1?argv[1]:NULL;lcd_state s={0};lcd_view v;
    lcd_compose(&s,"0.2.15",&v);assert(!strcmp(v.title,"SET UP WI-FI"));frame(out,"wifi",&s);
    s.starting=true;frame(out,"starting",&s);s.starting=false;
    s.wifi=true;lcd_compose(&s,"0.2.15",&v);assert(!strcmp(v.title,"ADD A TAILNET"));frame(out,"empty",&s);
    s.saved=s.enabled=s.login=1;frame(out,"signin",&s);
    s.login=0;s.ready=1;frame(out,"ready",&s);lcd_compose(&s,"0.2.15",&v);assert(strstr(v.detail,"1 OF 1"));
    s.saved=s.enabled=3;s.ready=2;frame(out,"multiple",&s);lcd_compose(&s,"0.2.15",&v);assert(strstr(v.detail,"2 OF 3"));
    s.ready=0;s.failed=1;frame(out,"retry",&s);lcd_compose(&s,"0.2.15",&v);assert(!strstr(v.title,"READY"));
    s.recovery=true;s.ready=1;frame(out,"recovery",&s);lcd_compose(&s,"0.2.15",&v);assert(!strcmp(v.title,"RECOVERY"));
    s.installing=true;frame(out,"installing",&s);lcd_compose(&s,"0.2.15",&v);assert(!strcmp(v.title,"INSTALLING"));
    s=(lcd_state){.wifi=true,.enabled=UINT32_MAX,.ready=UINT32_MAX};lcd_compose(&s,"1234567890123456789",&v);assert(strlen(v.detail)<=26 && strlen(v.footer)<=26);
    for(unsigned y=0;y<81;y++){struct{uint16_t first,p[160],last;} guarded={.first=42,.last=43};lcd_render_row(&v,y,guarded.p);assert(guarded.first==42 && guarded.last==43);}
    puts("LCD: 0/1/N, unready/recovery precedence, bounded labels and scanline canaries pass");
}

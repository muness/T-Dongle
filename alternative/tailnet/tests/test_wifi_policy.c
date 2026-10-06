#include <assert.h>
#include "../main/wifi_policy.h"
int main(void){int16_t s[8]={-80,-60,-127,-65,-90,-50,-72,-40};assert(wifi_pick(s,8,-1,false)==7);assert(wifi_pick(s,8,7,true)==-1);assert(wifi_pick(s,8,0,true)==7);s[7]=-70;s[5]=-72;s[1]=-73;s[3]=-75;assert(wifi_pick(s,8,0,true)==-1);for(int i=0;i<8;i++)s[i]=-127;assert(wifi_pick(s,8,-1,false)==-1);}
/* Pinned selection (`use N`): unpinned behaviour is unchanged; a pin holds, retries, then gives up and reports. */
__attribute__((constructor)) static void pin_tests(void){
    int16_t s[8]={-80,-60,-127,-65,-90,-50,-72,-40};
    wifi_pin p=WIFI_PIN_INIT;
    assert(wifi_pin_pick(&p,s,8,-1,false)==7 && wifi_pin_pick(&p,s,8,7,true)==-1);   /* no pin: wifi_pick */
    wifi_pin_set(&p,0);
    assert(wifi_pin_pick(&p,s,8,0,true)==-1 && p.attempts==0);                        /* connected to the pin: stay, even at -80 */
    s[0]=-127;assert(wifi_pin_pick(&p,s,8,0,true)==-1);                               /* signal not seen in this scan: still stay */
    assert(wifi_pin_pick(&p,s,8,3,true)==0 && p.attempts==1);                         /* on another network: go to the pin */
    assert(wifi_pin_pick(&p,s,8,-1,false)==0 && wifi_pin_pick(&p,s,8,-1,false)==0 && p.attempts==3);
    assert(wifi_pin_pick(&p,s,8,-1,false)==7 && p.slot==-1 && p.failed_slot==1);      /* gave up: strongest, failure recorded */
    wifi_pin_set(&p,9);assert(wifi_pin_pick(&p,s,8,-1,false)==7 && p.slot==-1);       /* slot beyond the list drops the pin */
    wifi_pin_set(&p,2);assert(p.failed_slot==0);wifi_pin_clear(&p);assert(p.slot==-1 && p.failed_slot==0);
}
/* Priority and the preferred slot (restored from v0.1.1): they only ever reorder networks that can carry traffic. */
__attribute__((constructor)) static void rank_tests(void){
    int16_t s[8]={-60,-50,-70,-127,-127,-127,-127,-127};
    /* Defaults: no priorities and no preferred slot behave exactly like wifi_pick. */
    wifi_rank none=WIFI_RANK_NONE;
    assert(wifi_pick_ranked(s,3,-1,false,&none)==1 && wifi_pick_ranked(s,3,-1,false,NULL)==1 && wifi_pick_ranked(s,3,-1,false,&none)==wifi_pick(s,3,-1,false));
    uint8_t equal[8]={50,50,50,50,50,50,50,50};wifi_rank flat={equal,-1};
    assert(wifi_pick_ranked(s,3,-1,false,&flat)==1);
    /* A higher priority beats a stronger signal. */
    uint8_t pr[8]={50,50,80,50,50,50,50,50};wifi_rank prio={pr,-1};
    assert(wifi_pick_ranked(s,3,-1,false,&prio)==2);
    /* The preferred slot beats a higher priority. */
    wifi_rank pref={pr,0};
    assert(wifi_pick_ranked(s,3,-1,false,&pref)==0);
    /* ... unless it is not usable (below WIFI_USABLE_DBM): a barely visible preferred network does not outrank a good one. */
    s[0]=-90;assert(wifi_pick_ranked(s,3,-1,false,&pref)==2);
    /* Nothing usable: everything seen is ranked, so a weak network is still joined, preferred first. */
    s[1]=-92;s[2]=-95;assert(wifi_pick_ranked(s,3,-1,false,&pref)==0);
    s[0]=-86;s[1]=-86;s[2]=-86;assert(wifi_pick_ranked(s,3,-1,false,&pref)==0);   /* equal signals: preferred, then priority, then slot */
    pref.preferred=-1;assert(wifi_pick_ranked(s,3,-1,false,&pref)==2);
    pr[2]=50;assert(wifi_pick_ranked(s,3,-1,false,&pref)==0);                      /* every key equal: the lower slot */
    /* Connected: a healthy link is never left, whatever is preferred (v0.1.1: never oscillate a healthy link). */
    int16_t t[8]={-70,-40,-127,-127,-127,-127,-127,-127};uint8_t tp[8]={50,99,50,50,50,50,50,50};wifi_rank higher={tp,1};
    assert(wifi_pick_ranked(t,2,0,true,&higher)==-1);
    /* A weak one is left for a candidate 12 dB stronger, by the ranking. */
    t[0]=-80;t[1]=-70;assert(wifi_pick_ranked(t,2,0,true,&higher)==-1);            /* only 10 dB better */
    t[1]=-68;assert(wifi_pick_ranked(t,2,0,true,&higher)==1);
    t[1]=-60;wifi_rank other={tp,0};assert(wifi_pick_ranked(t,2,0,true,&other)==-1);   /* the current network is the best: stay */
    /* Unseen networks (hidden SSIDs) while offline: preferred first, then priority, then slot. */
    uint8_t order[8];uint8_t op[8]={50,50,70,50,90,50,50,50};wifi_rank orank={op,3};
    wifi_rank_order(&orank,5,order);
    assert(order[0]==3 && order[1]==4 && order[2]==2 && order[3]==0 && order[4]==1);
    wifi_rank_order(NULL,4,order);assert(order[0]==0 && order[1]==1 && order[2]==2 && order[3]==3);
    wifi_rank_order(&orank,0,order);
    /* A pin outranks all of it; the ranked pick applies once the pin is given up. */
    wifi_pin p=WIFI_PIN_INIT;int16_t u[8]={-70,-40,-127,-127,-127,-127,-127,-127};uint8_t up[8]={50,50,50,50,50,50,50,50};wifi_rank pinned_rank={up,0};
    wifi_pin_set(&p,1);assert(wifi_pin_pick_ranked(&p,u,2,-1,false,&pinned_rank)==1);
    wifi_pin_set(&p,1);p.attempts=WIFI_PIN_MAX_ATTEMPTS;assert(wifi_pin_pick_ranked(&p,u,2,-1,false,&pinned_rank)==0 && p.slot==-1 && p.failed_slot==2);
}

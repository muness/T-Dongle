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

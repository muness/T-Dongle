#include <assert.h>
#include "../main/wifi_policy.h"
int main(void){int16_t s[8]={-80,-60,-127,-65,-90,-50,-72,-40};assert(wifi_pick(s,8,-1,false)==7);assert(wifi_pick(s,8,7,true)==-1);assert(wifi_pick(s,8,0,true)==7);s[7]=-70;s[5]=-72;s[1]=-73;s[3]=-75;assert(wifi_pick(s,8,0,true)==-1);for(int i=0;i<8;i++)s[i]=-127;assert(wifi_pick(s,8,-1,false)==-1);}

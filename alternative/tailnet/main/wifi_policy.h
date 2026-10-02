#pragma once
#include <stdint.h>
#include <stdbool.h>
#define WIFI_PROFILE_LIMIT 8
/* Stable ties, 12 dB hysteresis and a weak-current threshold prevent churn. */
static int wifi_pick(const int16_t signal[WIFI_PROFILE_LIMIT],unsigned count,int current,bool connected){
    int best=-1;
    for(unsigned i=0;i<count;i++)if(signal[i]>-127 && (best<0 || signal[i]>signal[best]))best=i;
    if(!connected)return best;
    if(best<0 || best==current)return -1;
    if(current>=0 && signal[current]>-75)return -1;
    if(current>=0 && signal[best]<signal[current]+12)return -1;
    return best;
}

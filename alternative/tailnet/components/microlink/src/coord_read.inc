/* One deadline and cursor per exact record. Once bytes are consumed, timeout
 * is fatal: callers must recreate the session rather than reuse its nonce. */
static int coord_read_exact(microlink_t *ml, uint8_t *buf, size_t len, bool committed) {
    size_t used=0;
    int64_t started=esp_timer_get_time(), deadline=started+10000000;
    while(used<len) {
        if(esp_timer_get_time()>=deadline){errno=ETIMEDOUT;break;}
        int n=ml_conn_read(ml,buf+used,len-used);
        if(n>0){used+=n;continue;}
        if(!n){errno=ECONNRESET;break;}
        if(errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)break;
        if(!used && !committed && errno!=EINTR)break;
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    if(used==len)return 0;
    ml->read_expected=len;ml->read_received=used;
    ml->read_elapsed_ms=(esp_timer_get_time()-started)/1000;
    ml->read_errno=errno;ml->read_tls_result=ml->conn_tls_result;
    return -1;
}
static int coord_recv(microlink_t *ml,uint8_t *buf,size_t len){return coord_read_exact(ml,buf,len,false);}
static int coord_recv_committed(microlink_t *ml,uint8_t *buf,size_t len){return coord_read_exact(ml,buf,len,true);}

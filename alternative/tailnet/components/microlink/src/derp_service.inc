/* One task owns TLS reads, writes (including server-PING replies), reconnect,
 * and free. Bounded batches prevent either direction starving the other. */
static void derp_service_io(microlink_t *ml,uint32_t *frames_tx,uint32_t *frames_rx) {
    uint64_t started=ml_get_time_ms();
    for(unsigned i=0;i<4 && ml_get_time_ms()-started<30;i++) {
        ml_derp_tx_item_t item;
        if(xQueueReceive(ml->derp_tx_queue,&item,0)!=pdTRUE)break;
        if(!ml->derp.connected){free(item.data);continue;}
        int result=item.frame_type==DERP_FRAME_SEND_PACKET
            ?derp_send_packet(ml,item.dest_pubkey,item.data,item.len)
            :derp_write_frame(ml,item.frame_type,item.data,item.len);
        free(item.data);
        if(result<0){ml->derp.connected=false;xEventGroupSetBits(ml->events,ML_EVT_DERP_RECONNECT);break;}
        (*frames_tx)++;
    }
    started=ml_get_time_ms();
    for(unsigned i=0;i<8 && ml->derp.connected && ml_get_time_ms()-started<30;i++) {
        int result=poll_derp_read(ml);
        if(result>0){(*frames_rx)++;ml->derp.last_recv_ms=ml_get_time_ms();}
        else {
            if(result<0){ml->derp.connected=false;xEventGroupSetBits(ml->events,ML_EVT_DERP_RECONNECT);}
            break;
        }
    }
}

_Static_assert(sizeof(gateway_stage) <= sizeof(gateway_json),
               "Semantic staging exceeds shared workspace");
static bool gateway_stage_emit(gs_parser *p, char c) {
    gateway_stage *s = p->context;
    if (!s->capture)
        return true;
    if (s->record_used + 1 >= sizeof(s->record)) {
        p->overflow = true;
        s->failure = "Map record exceeds 4 KiB capacity";
        return false;
    }
    s->record[s->record_used++] = c;
    s->total++;
    return true;
}
static bool gateway_stage_key(gs_frame *f, const char *key) {
    gp_reader r = {.b = f->key, .n = f->key_length};
    return gp_key(&r, 0, f->key_length, key);
}
static bool gateway_stage_record(microlink_t *ml, gateway_stage *s) {
    s->record[s->record_used] = 0;
    cJSON *record = gr_parse(&s->reader, s->record);
    if (!record) {
        s->failure =
            "Map record exceeds decoding bounds or contains unsupported text";
        return false;
    }
    if (s->kind == 1) {
        if (!cJSON_IsObject(record))
            return false;
        cJSON *n = cJSON_GetObjectItem(record, "Name");
        if (cJSON_IsString(n) && strlen(n->valuestring) < sizeof(s->dns)) {
            s->has_name = true;
            strlcpy(s->dns, n->valuestring, sizeof(s->dns));
        }
        cJSON *a =
            cJSON_GetArrayItem(cJSON_GetObjectItem(record, "Addresses"), 0);
        if (cJSON_IsString(a)) {
            unsigned b, c, d, e;
            if (sscanf(a->valuestring, "%u.%u.%u.%u", &b, &c, &d, &e) == 4) {
                s->has_ip = true;
                s->vpn_ip = (b << 24) | (c << 16) | (d << 8) | e;
            }
        }
        s->expired = cJSON_IsTrue(cJSON_GetObjectItem(record, "Expired"));
    } else if (s->kind == 5) {
        if (!cJSON_IsObject(record))
            return false;
        cJSON regions = {.type = cJSON_Object, .child = record};
        uint8_t count = 0;
        cJSON *id = cJSON_GetObjectItem(record, "RegionID");
        bool home =
            cJSON_IsNumber(id) && id->valueint == ml->derp_region_default;
        if (s->region_count >= ML_MAX_DERP_REGIONS) {
            if (!home)
                return true;
            s->region_count--;
        }
        decode_derp_regions(&s->regions[s->region_count], &count,
                            ml->derp_region_default, &regions);
        s->region_count += count;
    } else {
#ifndef GATEWAY_FLASH_DIRECTORY
        if (++s->group_count[s->kind] > ML_MAX_PEERS) {
            s->failure = "Map peer update section exceeds configured capacity";
            return false;
        }
#endif
        const char *name = s->kind == 3   ? "PeersRemoved"
                           : s->kind == 4 ? "PeersChangedPatch"
                                          : "PeersChanged";
        cJSON array = {
            .type = cJSON_Array, .string = (char *)name, .child = record};
        cJSON root = {.type = cJSON_Object, .child = &array};
        s->group_now = s->kind;
        gateway_capture = s;
        parse_peers_from_map_response(ml, &root);
        gateway_capture = NULL;
        if (s->failed)
            return false;
    }
    return true;
}
/* Reader emits projected bytes only while one semantic record is open. */
static bool gateway_stage_event(gs_parser *p, bool begin, char type) {
    gateway_stage *s = p->context;
    if (!begin) {
        if (s->capture && p->depth == s->capture_parent) {
            s->capture = false;
            return gateway_stage_record((microlink_t *)s->reader_context, s);
        }
        return true;
    }
    if (s->capture)
        return true;
    unsigned kind = 0;
    if (p->depth == 1) {
        gs_frame *f = &p->frames[0];
        const char *fields[] = {"Node",
                                "Peers",
                                "PeersChanged",
                                "PeersRemoved",
                                "PeersChangedPatch",
                                "DERPMap"};
        for (unsigned i = 0; i < 6; i++)
            if (gateway_stage_key(f, fields[i])) {
                unsigned bit = 1u << i;
                if (s->seen_fields & bit) {
                    s->failure = "Map contains duplicate control fields";
                    return false;
                }
                s->seen_fields |= bit;
            }
        if (gateway_stage_key(f, "Node") && type != 'n') {
            if (type != '{')
                return false;
            kind = 1;
        }
        if (gateway_stage_key(f, "Peers") && type == '[')
            s->authoritative = true;
        if (gateway_stage_key(f, "DERPMap") && type != 'n' && type != '{')
            return false;
    } else if (p->depth == 2 && !p->frames[1].object) {
        gs_frame *f = &p->frames[0];
        if (gateway_stage_key(f, "Peers"))
            kind = 2;
        else if (gateway_stage_key(f, "PeersChanged"))
            kind = 6;
        else if (gateway_stage_key(f, "PeersRemoved"))
            kind = 3;
        else if (gateway_stage_key(f, "PeersChangedPatch"))
            kind = 4;
    } else if (p->depth == 2 && p->frames[1].scope == GP_DERP &&
               gateway_stage_key(&p->frames[1], "Regions")) {
        if (type != '{' || s->derp_present)
            return false;
        s->derp_present = true;
    } else if (p->depth == 3 && p->frames[2].scope == GP_REGIONS &&
               p->frames[2].child != GP_DROP) {
        if (type != '{')
            return false;
        kind = 5;
    }
    if (kind) {
        s->kind = kind;
        s->capture = true;
        s->capture_parent = p->depth;
        s->record_used = 0;
    }
    return true;
}
static void gateway_stage_init(gs_parser *p, microlink_t *ml) {
    gateway_stage *s = (gateway_stage *)gateway_json;
    memset(s, 0, sizeof(*s));
    s->reader_context = ml;

    gs_init(p, NULL, 0);
    p->home = ml->derp_region_default;
    p->context = s;
    p->emit = gateway_stage_emit;
    p->event = gateway_stage_event;
}
static bool gateway_stage_commit(microlink_t *ml, gs_parser *p) {
    gateway_stage *s = p->context;
    if (s->capture || s->failed || ml->last_error[0])
        return !s->capture && !s->failed;
    ml_peer_batch_t *batch = NULL;
    unsigned count = 0;
    if (!s->expired) {
#ifdef GATEWAY_FLASH_DIRECTORY
        count=s->count;
#else
        for (unsigned i = 0; i < s->count; i++)
            if (!(s->authoritative && s->group[i] == 6))
                count++;
#endif
        if (count || s->authoritative) {
            uint64_t deadline = ml_get_time_ms() + 1000;
            while (__atomic_load_n(&ml->map_batch_pending, __ATOMIC_ACQUIRE)) {
                if (ml_get_time_ms() >= deadline) {
                    s->failure =
                        "Previous map batch is still pending; retrying";
                    return false;
                }
                vTaskDelay(pdMS_TO_TICKS(5));
            }
            __atomic_store_n(&ml->map_batch_pending, true, __ATOMIC_RELEASE);
#ifdef GATEWAY_FLASH_DIRECTORY
            batch=ml_psram_calloc(1,sizeof(*batch));
            if (!batch || (!s->count && !ml_directory_begin(ml)) || !ml_directory_commit(ml,s->authoritative)) {
                free(batch);s->failure="Peer flash commit failed; previous directory retained";
                __atomic_store_n(&ml->map_batch_pending,false,__ATOMIC_RELEASE);return false;
            }
            batch->header.action=ML_PEER_BATCH;
            batch->authoritative=true;
#else
            batch = ml_psram_calloc(1, sizeof(*batch) +
                                           count * sizeof(ml_peer_update_t));
            if (!batch) {
                s->failure = "Not enough memory for a validated map batch";
                __atomic_store_n(&ml->map_batch_pending, false,
                                 __ATOMIC_RELEASE);
                return false;
            }
            batch->header.action = ML_PEER_BATCH;
            batch->count = count;
            batch->authoritative = s->authoritative;
            unsigned n = 0;
            /* Preserve operation order regardless of root field order. */
            for (unsigned pass = 0; pass < 3; pass++)
                for (unsigned i = 0; i < s->count; i++) {
                    ml_peer_update_t *u = &s->updates[i];
                    if (s->authoritative && s->group[i] == 6)
                        continue;
                    unsigned order = u->action == ML_PEER_ADD      ? 0
                                     : u->action == ML_PEER_REMOVE ? 1
                                                                   : 2;
                    if (order == pass)
                        batch->updates[n++] = *u;
                }
#endif
            if (xQueueSend(ml->peer_update_queue, &batch, pdMS_TO_TICKS(100)) !=
                pdTRUE) {
                free(batch);
                s->failure = "Map update queue is busy; retrying";
                __atomic_store_n(&ml->map_batch_pending, false,
                                 __ATOMIC_RELEASE);
                return false;
            }
        }
    }
    if (s->has_ip)
        ml->vpn_ip = s->vpn_ip;
    if (s->has_name)
        strlcpy(ml->self_dns_name, s->dns, sizeof(ml->self_dns_name));
    ml->map_generation++;
    if (s->expired) {
        ml->key_expired = true;
        strlcpy(ml->last_error, "authorization_expired",
                sizeof(ml->last_error));
        return true;
    }
    if (s->derp_present) {
        ml->derp_region_count = s->region_count;
        memcpy(ml->derp_regions, s->regions, sizeof(s->regions));
        if (activate_derp_regions(ml) && !ml->derp.connected)
            xEventGroupSetBits(ml->events, ML_EVT_DERP_CONNECT_REQ);
    }
    return true;
}

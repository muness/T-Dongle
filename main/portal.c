// SPDX-License-Identifier: MIT
#include "app.h"
#include "cJSON.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "dhcpserver/dhcpserver.h"
#include "lwip/sockets.h"
#include <stdio.h>
#include <string.h>
static char ap_ssid[25], ap_pass[17], token[33];
void portal_identity(char *ssid, char *pass) {
    uint8_t mac[6];
    bridge_get_mac(mac);
    snprintf(ap_ssid, sizeof(ap_ssid), "TDongle-%02X%02X%02X", mac[3], mac[4], mac[5]);
    for (int i = 0; i < 16; i++)
        ap_pass[i] = "abcdefghijkmnpqrstuvwxyz23456789"[esp_random() % 32];
    ap_pass[16] = 0;
#if CONFIG_ADAPTER_OPEN_SETUP_AP
    ap_pass[0] = 0;
#endif
    for (int i = 0; i < 32; i++)
        token[i] = "0123456789abcdef"[esp_random() % 16];
    token[32] = 0;
    strcpy(ssid, ap_ssid);
    strcpy(pass, ap_pass);
}
static esp_err_t headers(httpd_req_t *r) {
    httpd_resp_set_hdr(r, "Cache-Control", "no-store");
    httpd_resp_set_hdr(r, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(r, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(r, "Content-Security-Policy",
                       "default-src 'none'; script-src 'unsafe-inline'; style-src "
                       "'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'");
    return ESP_OK;
}
static const char PAGE_HEAD[] =
    "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>T-Dongle setup</title>\n"
    "<style>\n"
    ":root{--bg:#0e1a24;--panel:#15252f;--line:#294050;--text:#eaf3f7;--mute:#9db3c0;--acc:#40dfff;--ok:#5fe0a0;--err:#ff8a80;--ease:cubic-bezier(.25,1,.5,1)}\n"
    "*{box-sizing:border-box}\n"
    "body{margin:0;font:17px/1.5 system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text)}\n"
    "main{max-width:30em;margin:0 auto;padding:1.25em 1em 3em}\n"
    "h1{font-size:1.45em;line-height:1.2;margin:.2em 0 .3em}\n"
    ".chip{display:inline-block;font-size:.75em;letter-spacing:.06em;text-transform:uppercase;color:var(--acc);border:1px solid var(--line);border-radius:2em;padding:.15em .8em}\n"
    ".lead{color:var(--mute);margin:0 0 1.2em}\n"
    "ol{margin:0 0 1.4em;padding:0;list-style:none;display:grid;gap:.4em;color:var(--mute);font-size:.9em}\n"
    "ol li::before{content:attr(data-n);display:inline-grid;place-items:center;width:1.6em;height:1.6em;margin-right:.6em;border-radius:50%;background:var(--panel);color:var(--acc);font-weight:600}\n"
    "form,.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:1em}\n"
    "label{display:block;font-weight:600;margin:.9em 0 0}\n"
    "label:first-of-type{margin-top:0}\n"
    ".hint{display:block;font-weight:400;font-size:.82em;color:var(--mute)}\n"
    "input{width:100%;font:inherit;color:var(--text);background:#0b141b;border:1px solid var(--line);border-radius:10px;padding:.65em .75em;margin-top:.3em;min-height:44px;transition:border-color .2s var(--ease),box-shadow .2s var(--ease)}\n"
    "input:focus-visible,button:focus-visible,summary:focus-visible{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px rgba(64,223,255,.35)}\n"
    ".nets{display:grid;grid-template-columns:minmax(0,1fr);gap:.4em;margin:.5em 0 0}\n"
    ".net{display:flex;justify-content:space-between;gap:1em;text-align:left;margin:0;min-height:44px;background:#0b141b;color:var(--text);border:1px solid var(--line);font-weight:400}\n"
    ".net:hover{border-color:var(--acc);background:#0b141b}\n"
    ".net span:first-child{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n"
    ".net span:last-child{color:var(--mute);white-space:nowrap}\n"
    ".saved{display:flex;justify-content:space-between;align-items:center;gap:1em;padding:.35em .4em .35em .9em;min-height:48px;border:1px solid var(--line);border-radius:12px;background:#0b141b}\n"
    ".saved span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n"
    "#savedbox{display:grid;grid-template-columns:minmax(0,1fr);gap:.4em;margin-bottom:1.2em}#savedbox[hidden]{display:none}\n"
    ".saved button.quiet{flex:none;width:auto;margin:0;min-height:38px;padding:.3em .9em}\n"
    ".note{color:var(--mute);font-size:.9em;margin:.5em 0 0}\n"
    ".show{display:flex;align-items:center;gap:.5em;font-weight:400;font-size:.9em;margin-top:.5em;min-height:44px}\n"
    ".show input{width:auto;min-height:0;margin:0;accent-color:var(--acc)}\n"
    "details{margin-top:1em;color:var(--mute)}\n"
    "summary{cursor:pointer;min-height:44px;display:flex;align-items:center}\n"
    "summary::before{content:'▸';color:var(--acc);margin-right:.5em;transition:transform .2s var(--ease)}\n"
    "details[open] summary::before{transform:rotate(90deg)}\n"
    ".row{display:grid;grid-template-columns:1fr 1fr;gap:.8em}\n"
    "button{font:inherit;font-weight:600;min-height:48px;width:100%;border:0;border-radius:12px;padding:.7em 1em;cursor:pointer;background:var(--acc);color:#04202a;margin-top:1.1em;transition:transform .12s var(--ease),opacity .2s var(--ease),background-color .2s var(--ease)}\n"
    "button:hover{background:#7aebff}\n"
    "button:active{transform:translateY(2px) scale(.99)}\n"
    "button:disabled{opacity:.55;cursor:progress;transform:none}\n"
    "button.quiet{background:transparent;color:var(--mute);border:1px solid var(--line);margin-top:.7em}\n"
    "#result{margin-top:1em}\n"
    "#result p{margin:0}\n"
    ".msg{border-radius:12px;padding:.8em 1em;border:1px solid var(--line);animation:in .3s var(--ease)}\n"
    ".msg.err{border-color:var(--err);color:var(--err)}\n"
    ".done{text-align:center;animation:in .35s var(--ease)}\n"
    ".done svg{width:64px;height:64px;stroke:var(--ok);fill:none;stroke-width:4;stroke-linecap:round;stroke-linejoin:round}\n"
    ".done circle{stroke-dasharray:151;stroke-dashoffset:151;animation:draw .6s var(--ease) forwards}\n"
    ".done path{stroke-dasharray:40;stroke-dashoffset:40;animation:draw .4s .35s var(--ease) forwards}\n"
    ".done h2{margin:.4em 0 .2em;font-size:1.2em}\n"
    ".done p{color:var(--mute);text-align:left;margin:.6em 0 0;font-size:.92em}\n"
    ".legend{display:grid;gap:.25em;margin:.8em 0 0;padding:0;list-style:none;text-align:left;font-size:.92em}\n"
    ".dot{display:inline-block;width:.8em;height:.8em;border-radius:50%;margin-right:.55em;vertical-align:-.05em}\n"
    "small{display:block;margin-top:1.2em;color:var(--mute);font-size:.8em}\n"
    "[hidden]{display:none!important}\n"
    "@keyframes in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}\n"
    "@keyframes draw{to{stroke-dashoffset:0}}\n"
    "@media(prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;animation-delay:0s!important;transition-duration:.01ms!important}}\n"
    "</style>\n"
    "<main>\n"
    "<span class=chip>T-Dongle setup</span>\n"
    "<h1>Connect your dongle to Wi-Fi</h1>\n"
    "<p class=lead>About a minute. Internet forwarding is paused while you do this.</p>\n"
    "<ol><li data-n=1>Pick the 2.4 GHz network the dongle should use</li><li data-n=2>Save it. Add more networks the same way if you like</li><li data-n=3>Tap Done; the dongle restarts and joins the best one</li></ol>\n"
    "<form id=f autocomplete=off>\n"
    "<section id=savedbox hidden><label>Saved networks<span class=hint>The dongle joins the highest-priority one it can find.</span></label><div id=savedlist class=nets style=margin-top:0></div></section>\n"
    "<label>Nearby networks<span class=hint>Tap one to use it.</span></label>\n"
    "<div id=nets class=nets></div>\n"
    "<button id=scan type=button class=quiet>Scan again</button>\n"
    "<label>Wi-Fi network name (SSID)<span class=hint>Exactly as it appears, including capitals. 2.4 GHz only.</span><input name=ssid maxlength=32 required autocapitalize=off autocorrect=off spellcheck=false></label>\n"
    "<label>Password<span class=hint>Leave empty for an open network. 8 to 63 characters.</span><input id=pw name=password type=password maxlength=63 autocomplete=new-password autocapitalize=off autocorrect=off spellcheck=false></label>\n"
    "<label class=show><input type=checkbox id=show>Show password</label>\n"
    "<details><summary>Advanced: profile name, slot, priority</summary>\n"
    "<label>Profile name<span class=hint>Defaults to the network name.</span><input name=name maxlength=24></label>\n"
    "<div class=row><label>Slot (1 to 8)<input name=slot type=number inputmode=numeric min=1 max=8 value=1 required></label><label>Priority (0 to 100)<input name=priority type=number inputmode=numeric min=0 max=100 value=50 required></label></div>\n"
    "</details>\n"
    "<button id=save>Save network</button>\n"
    "<button id=cancel type=button class=quiet>Cancel setup</button>\n"
    "</form>\n"
    "<div id=result role=status aria-live=polite></div>\n"
    "<small>A new network is saved right away. Replacing a saved one (same slot) restarts the dongle into a 45 second trial and keeps the old one unless the new one stays connected for 10 seconds. Neither checks Internet access. Setup closes by itself after 10 minutes.</small>\n"
    "</main>\n"
    "<script>const token='";
static const char PAGE_TAIL[] =
    "';\n"
    "const $=id=>document.getElementById(id),res=$('result'),f=$('f');\n"
    "$('show').onchange=e=>{$('pw').type=e.target.checked?'text':'password'};\n"
    "function say(html,cls){res.innerHTML='';const d=document.createElement('div');d.className=cls;if(typeof html==='string')d.textContent=html;else d.appendChild(html);res.appendChild(d)}\n"
    "function done(title,steps){\n"
    " f.hidden=true;res.innerHTML='';\n"
    " const d=document.createElement('div');d.className='card done';\n"
    " d.innerHTML=\"<svg viewBox='0 0 52 52' aria-hidden=true><circle cx=26 cy=26 r=24></circle><path d='M14 27l8 8 16-17'></path></svg>\";\n"
    " const h=document.createElement('h2');h.textContent=title;d.appendChild(h);\n"
    " const ul=document.createElement('ul');ul.className='legend';\n"
    " steps.forEach(s=>{const li=document.createElement('li');const dot=document.createElement('span');dot.className='dot';dot.style.background=s[0];li.appendChild(dot);li.appendChild(document.createTextNode(s[1]));ul.appendChild(li)});\n"
    " d.appendChild(ul);\n"
    " const p=document.createElement('p');p.textContent='This page will stop responding when the dongle restarts. That is expected. You can reconnect your phone or laptop to your normal Wi-Fi.';\n"
    " d.appendChild(p);res.appendChild(d);d.scrollIntoView({block:'nearest'});\n"
    "}\n"
    "async function send(path,data){\n"
    " try{\n"
    "  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Setup-Token':token},body:JSON.stringify(data)});\n"
    "  const t=await r.text();\n"
    "  return r.ok?{ok:true,text:t}:{ok:false,text:t};\n"
    " }catch(e){return {ok:null}}\n"
    "}\n"
    "function bars(r){return r>-60?'strong':r>-75?'ok':'weak'}\n"
    "function render(j){\n"
    " nets.innerHTML='';\n"
    " if(!j.n.length){const p=document.createElement('p');p.className='note';p.textContent=j.busy?'Scanning...':'No networks found. Type the name below.';nets.appendChild(p)}\n"
    " j.n.forEach(n=>{const b=document.createElement('button');b.type='button';b.className='net quiet';\n"
    "  const a=document.createElement('span');a.textContent=n.s;const c=document.createElement('span');c.textContent=(n.o?'open, ':'')+bars(n.r);\n"
    "  b.appendChild(a);b.appendChild(c);\n"
    "  b.onclick=()=>{f.ssid.value=n.s;if(n.o)f.password.value='';$('pw').focus()};nets.appendChild(b)});\n"
    "}\n"
    "async function scan(again){\n"
    " try{const r=await fetch('/scan'+(again?'?again=1':''),{headers:{'X-Setup-Token':token}});const j=await r.json();render(j);\n"
    "  $('scan').disabled=j.busy;$('scan').textContent=j.busy?'Scanning...':'Scan again';\n"
    "  if(j.busy)setTimeout(()=>scan(false),1500)}catch(e){}\n"
    "}\n"
    "$('scan').onclick=()=>scan(true);scan(false);\n"
    "let nsaved=0,slotTouched=false;f.slot.oninput=()=>{slotTouched=true};\n"
    "async function loadSaved(){\n"
    " try{const r=await fetch('/saved',{headers:{'X-Setup-Token':token}});const j=await r.json();\n"
    "  const L=$('savedlist');L.innerHTML='';nsaved=j.n.length;$('savedbox').hidden=!nsaved;\n"
    "  $('cancel').textContent=nsaved?'Done':'Cancel setup';\n"
    "  j.n.forEach(n=>{const row=document.createElement('div');row.className='saved';\n"
    "   const a=document.createElement('span');a.textContent=n.ssid.startsWith(n.name)?n.ssid:n.name+' ('+n.ssid+')';a.title=n.ssid;\n"
    "   const del=document.createElement('button');del.type='button';del.className='quiet';del.textContent='Delete';\n"
    "   del.onclick=async()=>{if(!confirm('Delete '+n.name+'?'))return;del.disabled=true;const r=await send('/del',{slot:n.slot});if(r.ok===false)say(r.text||'Could not delete.','msg err');setTimeout(loadSaved,600)};\n"
    "   row.appendChild(a);row.appendChild(del);L.appendChild(row)});\n"
    "  if(!slotTouched)f.slot.value=j.free||1;\n"
    " }catch(e){}\n"
    "}\n"
    "loadSaved();\n"
    "const saved=[['#ffb020','Amber, breathing: joining your network'],['#5fe0a0','Green with a brief glow: connected and USB ready'],['#ff5a4d','Red, two blinks: network not found or wrong password']];\n"
    "f.onsubmit=async e=>{\n"
    " e.preventDefault();\n"
    " const d=Object.fromEntries(new FormData(f));\n"
    " d.slot=Number(d.slot);d.priority=Number(d.priority);\n"
    " if(!d.name)d.name=d.ssid.slice(0,24);\n"
    " if(d.password&&d.password.length<8){say('Passwords need at least 8 characters. Leave it empty only for an open network.','msg err');$('pw').focus();return}\n"
    " if(!/^[\\x20-\\x7e]*$/.test(d.ssid+d.name+d.password)){say('Only plain ASCII letters, numbers and symbols are supported for now.','msg err');return}\n"
    " $('save').disabled=true;$('save').textContent='Saving...';\n"
    " const r=await send('/save',d);\n"
    " if(r.ok===false){say(r.text||'The dongle rejected that. Check the fields and try again.','msg err');$('save').disabled=false;$('save').textContent='Save network';return}\n"
    " f.password.value='';\n"
    " if(r.text==='saved'){\n"
    "  say('Saved '+d.ssid+'. Add another network, or tap Done.','msg');\n"
    "  f.ssid.value='';f.name.value='';slotTouched=false;$('save').disabled=false;$('save').textContent='Save network';\n"
    "  setTimeout(loadSaved,600);return}\n"
    " done('Saved. The dongle is testing it now.',saved);\n"
    "};\n"
    "$('cancel').onclick=async()=>{\n"
    " $('cancel').disabled=true;\n"
    " const r=await send('/cancel',{});\n"
    " if(r.ok===false){say(r.text||'Could not cancel. Try again.','msg err');$('cancel').disabled=false;return}\n"
    " if(nsaved){done('Done. The dongle is restarting and joining your network.',saved);return}\n"
    " f.hidden=true;say('Setup cancelled. The dongle is restarting into adapter mode.','msg');\n"
    "};\n"
    "</script>\n";
/* Setup-mode timeline for diagnosing slow captive-portal pop-ups: station join, DHCP lease, each
 * DNS query, each HTTP request and page send, in ms since the AP started. Each station join
 * restarts it, so it holds the first TRACE_MAX events of the latest join, the part that shows
 * where a pop-up stalls. Console: portal. */
#define TRACE_MAX 64
static struct {
    uint32_t ms;
    char kind;
    char text[43];
} s_trace[TRACE_MAX];
static int s_trace_n;
static int64_t s_trace_t0;
static portMUX_TYPE s_trace_lock = portMUX_INITIALIZER_UNLOCKED;
static void trace(char kind, const char *text) {
    uint32_t ms = (uint32_t)((esp_timer_get_time() - s_trace_t0) / 1000);
    portENTER_CRITICAL(&s_trace_lock);
    if (s_trace_n < TRACE_MAX) {
        s_trace[s_trace_n].ms = ms;
        s_trace[s_trace_n].kind = kind;
        snprintf(s_trace[s_trace_n].text, sizeof(s_trace[0].text), "%s", text);
        s_trace_n++;
    }
    portEXIT_CRITICAL(&s_trace_lock);
}
void portal_trace_dump(void) {
    static const char *const names[128] = {['J'] = "join", ['L'] = "leave", ['I'] = "dhcp",
                                           ['D'] = "dns", ['H'] = "http", ['S'] = "start"};
    int n = s_trace_n;
    console_printf("portal trace: %d events%s\r\n", n, n == TRACE_MAX ? " (full)" : "");
    for (int i = 0; i < n; i++)
        console_printf("%7lu ms %-5s %s\r\n", (unsigned long)s_trace[i].ms,
                       names[(int)s_trace[i].kind] ? names[(int)s_trace[i].kind] : "?", s_trace[i].text);
}
static void trace_uri(httpd_req_t *r) {
    char host[24] = "", t[43];
    httpd_req_get_hdr_value_str(r, "Host", host, sizeof(host));
    snprintf(t, sizeof(t), "%.20s%.22s", host, r->uri);
    trace('H', t);
}
static void trace_wifi(void *arg, esp_event_base_t base, int32_t id, void *data) {
    char t[43];
    if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *e = data;
        snprintf(t, sizeof(t), "%02x:%02x:%02x:%02x:%02x:%02x", e->mac[0], e->mac[1], e->mac[2],
                 e->mac[3], e->mac[4], e->mac[5]);
        portENTER_CRITICAL(&s_trace_lock);
        s_trace_n = 0; /* keep the latest join's sequence, not the first join's */
        portEXIT_CRITICAL(&s_trace_lock);
        trace('J', t);
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *e = data;
        snprintf(t, sizeof(t), "reason %u", e->reason);
        trace('L', t);
    } else if (base == IP_EVENT && id == IP_EVENT_AP_STAIPASSIGNED) {
        ip_event_ap_staipassigned_t *e = data;
        snprintf(t, sizeof(t), IPSTR, IP2STR(&e->ip));
        trace('I', t);
    }
}
static esp_err_t page(httpd_req_t *r) {
    trace_uri(r);
    headers(r);
    httpd_resp_set_type(r, "text/html");
    int64_t t0 = esp_timer_get_time();
    esp_err_t e = httpd_resp_send_chunk(r, PAGE_HEAD, sizeof(PAGE_HEAD) - 1);
    if (e == ESP_OK)
        e = httpd_resp_send_chunk(r, token, HTTPD_RESP_USE_STRLEN);
    if (e == ESP_OK)
        e = httpd_resp_send_chunk(r, PAGE_TAIL, sizeof(PAGE_TAIL) - 1);
    if (e == ESP_OK)
        e = httpd_resp_send_chunk(r, NULL, 0);
    char t[43];
    snprintf(t, sizeof(t), "page %s in %lld ms", e == ESP_OK ? "sent" : esp_err_to_name(e),
             (long long)((esp_timer_get_time() - t0) / 1000));
    trace('H', t);
    return e;
}
static bool token_ok(httpd_req_t *r) {
    char supplied[40];
    return httpd_req_get_hdr_value_str(r, "X-Setup-Token", supplied, sizeof(supplied)) == ESP_OK &&
           !strcmp(supplied, token);
}
/* Nearby-network list. The scan runs in its own task so the HTTP server never blocks; the page
 * polls /scan until "busy" clears. Results are deduplicated by SSID, strongest first. */
#define SCAN_MAX 16
static struct {
    char ssid[33];
    int8_t rssi;
    uint8_t open;
} nets[SCAN_MAX];
static volatile int net_count;
static volatile bool scanning;
static void scan_task(void *arg) {
    wifi_scan_config_t sc = {.show_hidden = false};
    uint16_t n = 24;
    wifi_ap_record_t *rec = calloc(n, sizeof(*rec));
    int count = 0;
    if (rec && esp_wifi_scan_start(&sc, true) == ESP_OK &&
        esp_wifi_scan_get_ap_records(&n, rec) == ESP_OK) {
        for (int i = 0; i < n; i++) { /* records arrive sorted by RSSI, strongest first */
            const char *s = (const char *)rec[i].ssid;
            bool ascii = s[0] != 0, dup = false;
            for (const char *c = s; *c; c++)
                if ((unsigned char)*c < 32 || (unsigned char)*c > 126)
                    ascii = false;
            for (int j = 0; j < count; j++)
                if (!strcmp(nets[j].ssid, s))
                    dup = true;
            if (!ascii || dup || count == SCAN_MAX)
                continue;
            strcpy(nets[count].ssid, s);
            nets[count].rssi = rec[i].rssi;
            nets[count].open = rec[i].authmode == WIFI_AUTH_OPEN;
            count++;
        }
    }
    free(rec);
    net_count = count;
    scanning = false;
    vTaskDelete(NULL);
}
static void scan_begin(void) {
    if (scanning)
        return;
    scanning = true;
    if (xTaskCreate(scan_task, "scan", 4096, NULL, 2, NULL) != pdPASS)
        scanning = false;
}
static esp_err_t scan_get(httpd_req_t *r) {
    trace_uri(r);
    headers(r);
    if (!token_ok(r))
        return httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "Invalid setup token");
    static bool scanned;
    if (strstr(r->uri, "again") || !scanned) {
        scanned = true;
        scan_begin();
    }
    cJSON *o = cJSON_CreateObject(), *a = cJSON_AddArrayToObject(o, "n");
    cJSON_AddBoolToObject(o, "busy", scanning);
    for (int i = 0; i < net_count; i++) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "s", nets[i].ssid);
        cJSON_AddNumberToObject(e, "r", nets[i].rssi);
        cJSON_AddBoolToObject(e, "o", nets[i].open);
        cJSON_AddItemToArray(a, e);
    }
    char *txt = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    if (!txt)
        return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
    httpd_resp_set_type(r, "application/json");
    esp_err_t e = httpd_resp_sendstr(r, txt);
    free(txt);
    return e;
}
static app_snapshot_t s_snap; /* httpd runs one handler at a time */
static esp_err_t saved_get(httpd_req_t *r) {
    trace_uri(r);
    headers(r);
    if (!token_ok(r))
        return httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "Invalid setup token");
    app_snapshot(&s_snap); /* passwords already cleared in the public copy */
    cJSON *o = cJSON_CreateObject(), *a = cJSON_AddArrayToObject(o, "n");
    int free_slot = 0;
    for (int i = 0; i < PROFILE_MAX; i++) {
        const profile_t *p = &s_snap.cfg.p[i];
        if (!p->ssid[0]) {
            if (!free_slot)
                free_slot = i + 1;
            continue;
        }
        cJSON *e = cJSON_CreateObject();
        cJSON_AddNumberToObject(e, "slot", i + 1);
        cJSON_AddStringToObject(e, "name", p->name[0] ? p->name : p->ssid);
        cJSON_AddStringToObject(e, "ssid", p->ssid);
        cJSON_AddNumberToObject(e, "priority", p->priority);
        cJSON_AddItemToArray(a, e);
    }
    int want = setup_preferred_slot(); /* slot picked from the button menu, while still empty */
    if (want && !s_snap.cfg.p[want - 1].ssid[0])
        free_slot = want;
    cJSON_AddNumberToObject(o, "free", free_slot);
    char *txt = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    if (!txt)
        return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
    httpd_resp_set_type(r, "application/json");
    esp_err_t e = httpd_resp_sendstr(r, txt);
    free(txt);
    return e;
}
static esp_err_t post(httpd_req_t *r) {
    headers(r);
    if (!token_ok(r))
        return httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "Invalid setup token");
    if (r->content_len < 2 || r->content_len > 400)
        return httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "Body must be 2..400 bytes");
    char body[401];
    size_t n = 0;
    while (n < r->content_len) {
        int got = httpd_req_recv(r, body + n, r->content_len - n);
        if (got <= 0)
            return httpd_resp_send_err(r, HTTPD_408_REQ_TIMEOUT, "Incomplete request");
        n += got;
    }
    body[n] = 0;
    if (memchr(body, 0, n))
        return httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "Invalid body");
    bool ok, direct = false;
    if (!strcmp(r->uri, "/cancel"))
        ok = control_submit("cancel");
    else if (!strcmp(r->uri, "/del")) {
        cJSON *j = cJSON_Parse(body), *sl = cJSON_GetObjectItem(j, "slot");
        int slot = cJSON_IsNumber(sl) ? sl->valueint : 0;
        cJSON_Delete(j);
        if (slot < 1 || slot > PROFILE_MAX)
            return httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "Slot must be 1 to 8");
        char cmd[16];
        snprintf(cmd, sizeof(cmd), "del %d", slot);
        ok = control_submit(cmd);
    } else {
        /* Reject controls and escaped NUL before cJSON can truncate strings. */
        for (size_t i = 0; i < n; i++)
            if ((unsigned char)body[i] < 32)
                return httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "Compact JSON required");
        profile_t p;
        int slot;
        if (!profile_parse_json(body, &slot, &p))
            return httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST,
                                       "Invalid profile fields (ASCII, lengths, slot "
                                       "and priority required; no duplicates)");
        memset(&p, 0, sizeof(p));
        app_snapshot(&s_snap);
        direct = s_snap.setup && !s_snap.cfg.p[slot].ssid[0]; /* same rule as control.c */
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "profile %s", body);
        ok = control_submit(cmd);
        memset(cmd, 0, sizeof(cmd));
    }
    memset(body, 0, sizeof(body));
    if (!ok)
        return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "Busy; retry");
    if (!strcmp(r->uri, "/save"))
        return httpd_resp_sendstr(r, direct ? "saved" : "trial");
    return httpd_resp_sendstr(r, "ok");
}
/* Captive portal: every DNS name resolves to the dongle and every unknown URL redirects to the
 * setup page, so phones and laptops pop the setup sheet on their own. Setup mode only. */
static void dns_task(void *arg) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(53)};
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) {
        if (s >= 0)
            close(s);
        vTaskDelete(NULL);
    }
    uint8_t q[256];
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        int n = recvfrom(s, q, sizeof(q) - 16, 0, (struct sockaddr *)&from, &fl);
        if (n < 17)
            continue;
        int i = 12; /* end of the question name, then QTYPE and QCLASS */
        while (i < n && q[i])
            i += q[i] + 1;
        if (i + 5 > n)
            continue;
        uint16_t qtype = (q[i + 1] << 8) | q[i + 2];
        int end = i + 5;
        {
            char name[43];
            int o = snprintf(name, sizeof(name), "t%u ", qtype);
            for (int k = 12; k < i && o < (int)sizeof(name) - 1;) {
                int len = q[k++];
                for (int c = 0; c < len && k < i && o < (int)sizeof(name) - 1; c++)
                    name[o++] = (q[k] >= 32 && q[k] < 127) ? q[k] : '?', k++;
                if (k < i && o < (int)sizeof(name) - 1)
                    name[o++] = '.';
            }
            name[o] = 0;
            trace('D', name);
        }
        q[2] = 0x81; /* response, recursion desired */
        q[3] = 0x80; /* recursion available, no error */
        q[6] = 0;
        q[7] = qtype == 1 ? 1 : 0; /* answer only A records; AAAA gets an empty NOERROR */
        q[8] = q[9] = q[10] = q[11] = 0;
        if (qtype == 1) {
            static const uint8_t ans[] = {0xc0, 0x0c, 0,  1,  0,   1,   0,   0,
                                          0,    60,   0,  4,  192, 168, 4,   1};
            memcpy(q + end, ans, sizeof(ans));
            end += sizeof(ans);
        }
        sendto(s, q, end, 0, (struct sockaddr *)&from, fl);
    }
}
static esp_err_t redirect(httpd_req_t *r, httpd_err_code_t err) {
    trace_uri(r);
    httpd_resp_set_status(r, "302 Found");
    httpd_resp_set_hdr(r, "Location", "http://192.168.4.1/");
    httpd_resp_set_hdr(r, "Cache-Control", "no-store");
    return httpd_resp_send(r, NULL, 0);
}
void portal_start(void) {
    /* Only setup mode creates an esp_netif. Adapter mode has no LwIP interface.
     */
    esp_wifi_disconnect();
    esp_wifi_stop();
    bridge_clear_addresses();
    ESP_ERROR_CHECK(esp_netif_init());
    esp_netif_t *ap = esp_netif_create_default_wifi_ap();
    assert(ap);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    wifi_config_t c = {0};
    strcpy((char *)c.ap.ssid, ap_ssid);
    strcpy((char *)c.ap.password, ap_pass);
    c.ap.ssid_len = strlen(ap_ssid);
    c.ap.channel = 1;
#if CONFIG_ADAPTER_OPEN_SETUP_AP
    c.ap.authmode = WIFI_AUTH_OPEN;
#else
    c.ap.authmode = WIFI_AUTH_WPA2_PSK;
    c.ap.pmf_cfg.capable = true;
#endif
    c.ap.max_connection = 2;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &c));
    s_trace_t0 = esp_timer_get_time();
    s_trace_n = 0;
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_AP_STACONNECTED, trace_wifi, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_AP_STADISCONNECTED, trace_wifi, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, trace_wifi, NULL);
    ESP_ERROR_CHECK(esp_wifi_start());
    trace('S', "AP up");
    /* Hand out the dongle as DNS server. No DHCP option 114: RFC 8910 requires it to name an
     * RFC 8908 captive portal API served over HTTPS with a valid certificate, which a dongle at
     * 192.168.4.1 cannot provide. Pointing it at this HTML page violates both, and phones that
     * honour the option then have to fail over to their usual probe. DNS hijack plus the
     * redirect below is what triggers the setup sheet. */
    esp_netif_dhcps_stop(ap);
    esp_netif_dns_info_t dns = {.ip.type = IPADDR_TYPE_V4};
    dns.ip.u_addr.ip4.addr = esp_ip4addr_aton("192.168.4.1");
    esp_netif_set_dns_info(ap, ESP_NETIF_DNS_MAIN, &dns);
    dhcps_offer_t offer = OFFER_DNS;
    esp_netif_dhcps_option(ap, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &offer, sizeof(offer));
    esp_netif_dhcps_start(ap);
    xTaskCreate(dns_task, "dns", 3072, NULL, 3, NULL);
    /* No scan here: a scan takes the radio off the AP channel for a couple of seconds, exactly
     * while the phone is joining and probing. The page's first /scan request starts it. */
    httpd_config_t h = HTTPD_DEFAULT_CONFIG();
    h.stack_size = 6144;
    h.uri_match_fn = NULL;
    /* Phones open several connections at once (OS probe, page, favicon). With 4 slots and LRU
     * purge, live ones were evicted and retried. 7 = LWIP_MAX_SOCKETS 10 - 3 httpd internal. */
    h.max_open_sockets = 7;
    h.lru_purge_enable = true;
    /* ESP-IDF default send/recv timeouts (5 s). At 3 s a send to a phone still waking from Wi-Fi
     * power save could abort the 12 KB page mid-transfer; iOS then waited ~60 s to retry. */
    httpd_handle_t server;
    if (httpd_start(&server, &h) != ESP_OK) {
        mgmt_write("ERR setup HTTP start failed\r\n");
        return;
    }
    httpd_uri_t root = {.uri = "/", .method = HTTP_GET, .handler = page},
                save = {.uri = "/save", .method = HTTP_POST, .handler = post},
                cancel = {.uri = "/cancel", .method = HTTP_POST, .handler = post};
    httpd_register_uri_handler(server, &root);
    httpd_register_uri_handler(server, &save);
    httpd_uri_t scan = {.uri = "/scan", .method = HTTP_GET, .handler = scan_get},
                saved = {.uri = "/saved", .method = HTTP_GET, .handler = saved_get},
                del = {.uri = "/del", .method = HTTP_POST, .handler = post};
    httpd_register_uri_handler(server, &saved);
    httpd_register_uri_handler(server, &del);
    httpd_register_uri_handler(server, &scan);
    httpd_register_uri_handler(server, &cancel);
    httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, redirect);
}

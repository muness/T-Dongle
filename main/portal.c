// SPDX-License-Identifier: MIT
#include "app.h"
#include "cJSON.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_wifi.h"
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
    ".show{display:flex;align-items:center;gap:.5em;font-weight:400;font-size:.9em;margin-top:.5em;min-height:44px}\n"
    ".show input{width:auto;min-height:0;margin:0;accent-color:var(--acc)}\n"
    "details{margin-top:1em;color:var(--mute)}\n"
    "summary{cursor:pointer;min-height:44px;display:flex;align-items:center}\n"
    "summary::before{content:'\u25b8';color:var(--acc);margin-right:.5em;transition:transform .2s var(--ease)}\n"
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
    "<ol><li data-n=1>Enter the 2.4 GHz network the dongle should use</li><li data-n=2>Save; it restarts and tests the connection</li><li data-n=3>Watch the dongle's light: amber, then green</li></ol>\n"
    "<form id=f autocomplete=off>\n"
    "<label>Wi-Fi network name (SSID)<span class=hint>Exactly as it appears, including capitals. 2.4 GHz only.</span><input name=ssid maxlength=32 required autocapitalize=off autocorrect=off spellcheck=false></label>\n"
    "<label>Password<span class=hint>Leave empty for an open network. 8 to 63 characters.</span><input id=pw name=password type=password maxlength=63 autocomplete=new-password autocapitalize=off autocorrect=off spellcheck=false></label>\n"
    "<label class=show><input type=checkbox id=show>Show password</label>\n"
    "<details><summary>Advanced: profile name, slot, priority</summary>\n"
    "<label>Profile name<span class=hint>Defaults to the network name.</span><input name=name maxlength=24></label>\n"
    "<div class=row><label>Slot (1 to 8)<input name=slot type=number inputmode=numeric min=1 max=8 value=1 required></label><label>Priority (0 to 100)<input name=priority type=number inputmode=numeric min=0 max=100 value=50 required></label></div>\n"
    "</details>\n"
    "<button id=save>Save and test connection</button>\n"
    "<button id=cancel type=button class=quiet>Cancel setup</button>\n"
    "</form>\n"
    "<div id=result role=status aria-live=polite></div>\n"
    "<small>The dongle keeps your previous networks until the new one stays connected for 10 seconds, within a 45 second trial. This checks that it can join the network. It does not check Internet access. Setup closes by itself after 10 minutes.</small>\n"
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
    "  return r.ok?{ok:true}:{ok:false,text:t};\n"
    " }catch(e){return {ok:null}}\n"
    "}\n"
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
    " if(r.ok===false){say(r.text||'The dongle rejected that. Check the fields and try again.','msg err');$('save').disabled=false;$('save').textContent='Save and test connection';return}\n"
    " f.password.value='';\n"
    " done('Saved. The dongle is testing it now.',saved);\n"
    "};\n"
    "$('cancel').onclick=async()=>{\n"
    " $('cancel').disabled=true;\n"
    " const r=await send('/cancel',{});\n"
    " if(r.ok===false){say(r.text||'Could not cancel. Try again.','msg err');$('cancel').disabled=false;return}\n"
    " f.hidden=true;say('Setup cancelled. The dongle is restarting into adapter mode.','msg');\n"
    "};\n"
    "</script>\n";
static esp_err_t page(httpd_req_t *r) {
    headers(r);
    httpd_resp_set_type(r, "text/html");
    httpd_resp_send_chunk(r, PAGE_HEAD, sizeof(PAGE_HEAD) - 1);
    httpd_resp_send_chunk(r, token, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(r, PAGE_TAIL, sizeof(PAGE_TAIL) - 1);
    return httpd_resp_send_chunk(r, NULL, 0);
}
static esp_err_t post(httpd_req_t *r) {
    headers(r);
    char supplied[40];
    if (httpd_req_get_hdr_value_str(r, "X-Setup-Token", supplied, sizeof(supplied)) != ESP_OK ||
        strcmp(supplied, token))
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
    bool ok;
    if (!strcmp(r->uri, "/cancel"))
        ok = control_submit("cancel");
    else {
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
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "profile %s", body);
        ok = control_submit(cmd);
        memset(cmd, 0, sizeof(cmd));
    }
    memset(body, 0, sizeof(body));
    if (!ok)
        return httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "Busy; retry");
    return httpd_resp_sendstr(r, "Request queued. Check screen for validation; "
                                 "valid save/cancel disconnects setup and reboots.");
}
void portal_start(void) {
    /* Only setup mode creates an esp_netif. Adapter mode has no LwIP interface.
     */
    esp_wifi_disconnect();
    esp_wifi_stop();
    bridge_clear_addresses();
    ESP_ERROR_CHECK(esp_netif_init());
    assert(esp_netif_create_default_wifi_ap());
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    wifi_config_t c = {0};
    strcpy((char *)c.ap.ssid, ap_ssid);
    strcpy((char *)c.ap.password, ap_pass);
    c.ap.ssid_len = strlen(ap_ssid);
    c.ap.channel = 1;
    c.ap.authmode = WIFI_AUTH_WPA2_PSK;
    c.ap.max_connection = 2;
    c.ap.pmf_cfg.capable = true;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &c));
    ESP_ERROR_CHECK(esp_wifi_start());
    httpd_config_t h = HTTPD_DEFAULT_CONFIG();
    h.stack_size = 6144;
    h.max_open_sockets = 3;
    h.lru_purge_enable = true;
    h.recv_wait_timeout = 3;
    h.send_wait_timeout = 3;
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
    httpd_register_uri_handler(server, &cancel);
}

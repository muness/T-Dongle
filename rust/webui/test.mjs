// Headless test of the controller page's command layer: both transports against a fake dongle whose replies are the serial goldens
// (rust/crates/tdongle-serial/tests/golden, the text the Android app parses). Run: node rust/webui/test.mjs
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(here, 'controller.html'), 'utf8');
const script = /<script>([\s\S]*)<\/script>/.exec(html)[1];
const module_ = { exports: {} };
new Function('module', script)(module_);
const TD = module_.exports;

function golden(file) {
  const t = fs.readFileSync(path.join(here, '../crates/tdongle-serial/tests/golden', file), 'latin1');
  const out = {};
  for (const m of t.matchAll(/@@@@ SCENARIO (.+?) LEN (\d+) @@@@\n/g)) {
    const at = m.index + m[0].length;
    out[m[1]] = t.slice(at, at + Number(m[2]));
  }
  return out;
}
const statusG = golden('status.golden'), repliesG = golden('replies.golden');
const TAILNET_JSON = JSON.stringify({
  firmware: 'x', mode: 'tailnet_gateway', wifi: true, saved_wifi: ['HomeNet'], free_memory: 100000,
  members: [{ id: 3, label: 'work', enabled: true, error: '', state: 4, routing_ready: true, tailnet_ip: '100.64.0.9', tailnet_dns_name: 'dongle.x.ts.net',
    login_url: '', protocol_error: '', derp_link: { state: 'connected' }, directory_records: 2,
    peers: [{ name: 'laptop', qualifiedName: 'laptop.work.tailnet', address: '100.64.0.1' }, { name: 'nas', qualifiedName: 'nas.work.tailnet', address: '100.64.0.2' }] },
  { id: 4, label: 'new', enabled: true, state: 3, routing_ready: false, login_url: 'https://login.tailscale.com/a/abc', error: '' }] });

// the fake dongle: one dispatcher, used by both transports
const seen = [];
function dongle(line) {
  seen.push(line);
  if (line === 'status') return statusG.tailnet_online.replace('\r\n\r\n', '\r\n') + 'tn_wg member_slot=0 peer=100.64.0.1 session=1 attempts=0 hs_ms=Some(5) rx_ms=Some(1) tx_ms=Some(1) tx_bytes=10 rx_bytes=20 path=direct now_ms=9\r\ntn_wg member_slot=0 peer=100.64.0.2 session=1 attempts=0 hs_ms=None rx_ms=None tx_ms=None tx_bytes=1 rx_bytes=2 path=derp now_ms=9\r\n';
  if (line === 'list') return repliesG['list/two_second_current'];
  if (line === 'scan') return 'ssid=Cafe bssid=aa:bb:cc:dd:ee:ff channel=6 rssi=-50 auth=3 usable=1\r\nssid=Open bssid=aa:bb:cc:dd:ee:00 channel=1 rssi=-80 auth=0 usable=1 saved=1\r\nscan_done seen=2 listed=2 seq=1\r\n';
  if (line === 'tailnet-status') return TAILNET_JSON + '\r\n';
  if (line.startsWith('profile ')) return 'OK saved to slot 3; setup stays open\r\n';
  if (line.startsWith('use ')) return 'OK switching to 2\r\n';
  if (line === 'del 9') return 'ERR Saved network could not be removed\r\n';
  if (line.startsWith('mode ')) return 'OK mode saved; restarting\r\ndone>\r\n';
  return 'OK\r\n';
}

// transport 1: HTTP. The fake fetch enforces what the firmware enforces about the request shape.
const calls = [];
globalThis.fetch = async (url, o) => {
  calls.push({ url, o });
  assert.equal(url, '/serial'); assert.equal(o.method, 'POST');
  assert.equal(o.headers['Content-Type'], 'application/x-tdongle-command');
  assert.equal(o.credentials, 'omit');
  if (o.body === 'bootloader') return { ok: false, status: 403, text: async () => 'That command is not available here\n' };
  return { ok: true, status: 200, text: async () => dongle(o.body) };
};
// transport 2: Web Serial. A fake port: the console echoes nothing, answers a line when it gets its newline.
function fakePort(answer = dongle) {
  let push; let closed = false;
  const readable = new ReadableStream({ start(c) { push = (s) => c.enqueue(new TextEncoder().encode(s)); } });
  const writable = new WritableStream({ write(chunk) {
    const line = new TextDecoder().decode(chunk).replace(/\n$/, '');
    setTimeout(() => push(answer(line)), 5);
  } });
  return { readable, writable, async open() {}, async close() { closed = true; }, async setSignals() {}, get closed() { return closed; } };
}

const http = TD.layer(TD.httpTransport(''));
const ser = TD.layer(await TD.serialTransport(fakePort()));

for (const [name, L] of [['http', http], ['serial', ser]]) {
  const st = await L.status();
  assert.equal(st.mode, 'tailnet', name); assert.equal(st.wifi, 'up'); assert.equal(st.rssi, -61); assert.equal(st.active, 3); assert.equal(st.usbReady, true);
  assert.equal(st.flat.free_heap, '219640'); assert.equal(st.sections.display.brightness, '60'); assert.equal(st.sections.traffic.down_kbps, '0');
  assert.equal(st.sections.wifi_link.channel, '6');
  assert.equal(st.rows.tn_wg.length, 2); assert.equal(st.rows.tn_wg[1].path, 'derp');
  const list = await L.list();
  assert.deepEqual(list.map(n => [n.slot, n.current, n.name, n.ssid, n.priority]), [[1, false, 'Home sweet', 'HomeNet', 80], [2, true, 'Car', 'CarWifi', 10]]);
  const scan = await L.scan();
  assert.deepEqual(scan, [{ ssid: 'Cafe', rssi: -50, secure: true }, { ssid: 'Open', rssi: -80, secure: false }]);
  const tn = await L.tailnet();
  assert.equal(tn.members.length, 2); assert.equal(TD.memberState(tn.members[0]), 'Ready to route'); assert.equal(TD.memberState(tn.members[1]), 'Sign-in required');
  assert.equal(TD.loginUrl(tn.members[1]), 'https://login.tailscale.com/a/abc');
  assert.equal(TD.loginUrl({ login_url: 'https://evil.example/' }), '');
  // mutations: the same command text on both transports
  seen.length = 0;
  const p = { slot: 3, name: 'Phone "hot"', ssid: 'My\\Net', password: 'pass word1', priority: 40 };
  assert.match(await L.act(TD.profileLine(p)), /^OK saved to slot 3/);
  await L.act('use 2');
  await assert.rejects(() => L.act('del 9'), /could not be removed/);
  assert.equal((await L.raw('mode tailnet_gateway')).includes('restarting'), true);
  assert.deepEqual(seen, ['profile {"slot":3,"name":"Phone \\"hot\\"","ssid":"My\\\\Net","password":"pass word1","priority":40}', 'use 2', 'del 9', 'mode tailnet_gateway'], name);
}
// both transports gave the same parsed state
assert.deepEqual(await http.status(), await ser.status());
assert.deepEqual(await http.list(), await ser.list());

// every serial golden list/status reply parses the way the Android app parses it
for (const [k, v] of Object.entries(repliesG)) if (k.startsWith('list/') && !/non_utf8|out_of_range/.test(k)) assert.doesNotThrow(() => TD.parseList(v), k);
for (const [k, v] of Object.entries(statusG)) { const s = TD.parseStatus(v); assert.ok(['adapter', 'tailnet', 'setup'].includes(s.mode), k); }
assert.deepEqual(TD.parseList(repliesG['list/empty']), []);
assert.throws(() => TD.parseList('garbage'), /incomplete/);
assert.throws(() => TD.parseStatus('nope'), /incomplete/);

// validation (same rules as the Android Profile class and the firmware)
assert.throws(() => TD.profileLine({ slot: 1, name: 'n', ssid: 's', password: 'short', priority: 1 }), /8-63/);
assert.throws(() => TD.profileLine({ slot: 9, name: 'n', ssid: 's', password: '', priority: 1 }), /slot/);
assert.throws(() => TD.profileLine({ slot: 1, name: 'n', ssid: 'café', password: '', priority: 1 }), /ASCII/);
assert.equal(TD.memberLine({ verb: 'add', label: 'work', key: 'tskey-abc' }), 'member add work tskey-abc');
assert.equal(TD.memberLine({ verb: 'add', label: 'work', key: '' }), 'member add work');
assert.equal(TD.memberLine({ verb: 'remove', id: 3 }), 'member remove 3');
assert.throws(() => TD.memberLine({ verb: 'add', label: 'bad label', key: '' }), /letters/);
assert.throws(() => TD.memberLine({ verb: 'enable', id: 0 }), /id/);
assert.equal(TD.displayLine(60, 1, 120), 'display 60 1 120');
assert.throws(() => TD.displayLine(1, 0, 60), /Brightness/);

// a command that restarts the dongle may drop the connection mid-answer: that is success; any other dropped command is an error
globalThis.fetch = async () => { throw new TypeError('network error'); };
assert.match(await TD.layer(TD.httpTransport('')).raw('reboot'), /^OK/);
assert.match(await TD.layer(TD.httpTransport('')).raw('mode wifi_bridge'), /^OK/);
await assert.rejects(() => TD.layer(TD.httpTransport('')).raw('status'), TypeError);
// the firmware's refusal text reaches the user
globalThis.fetch = async () => ({ ok: false, status: 403, text: async () => 'USB access required\n' });
await assert.rejects(() => TD.layer(TD.httpTransport('')).raw('status'), /USB access required/);

// ---- the transport contract (rust/webui/contract.txt; the Rust side is tdongle-setup/tests/webui_contract.rs) ----
const contract = fs.readFileSync(path.join(here, 'contract.txt'), 'utf8').split('\n')
  .filter(l => l.trim() && !l.startsWith('#'))
  .map(l => { const [kind, pattern, exemplar, note] = l.split(' | ').map(s => s.trim()); return { kind, re: pattern === '-' ? null : new RegExp('^(?:' + pattern + ')$'), exemplar, note }; });
const both = contract.filter(e => e.kind === 'both');
assert.ok(both.length > 10 && contract.some(e => e.exemplar === 'selftest flash' && e.kind === 'serial') && contract.some(e => e.exemplar === 'temperature' && e.kind === 'absent'));
for (const e of both) assert.ok(e.re.test(e.exemplar), 'contract exemplar matches its own pattern: ' + e.exemplar);
const inContract = line => both.some(e => e.re.test(line));
// every line sent above over HTTP is a `both` command (except 'del 9', the test's own refused probe)
for (const c of calls.filter(c => c.o.body !== 'del 9')) assert.ok(inContract(c.o.body), 'the page sent a command outside the contract over HTTP: ' + c.o.body);
// every line the page's builders produce is a `both` command
for (const l of [TD.profileLine({ slot: 3, name: 'n', ssid: 's', password: '', priority: 1 }), TD.memberLine({ verb: 'add', label: 'w', key: '' }), TD.memberLine({ verb: 'add', label: 'w', key: 'k' }),
  TD.memberLine({ verb: 'enable', id: 1 }), TD.memberLine({ verb: 'disable', id: 1 }), TD.memberLine({ verb: 'remove', id: 1 }), TD.displayLine(5, 0, 10), TD.displayLine(100, 1, 3600),
  'use 8', 'del 1', 'mode wifi_bridge', 'mode tailnet_gateway', 'reboot', 'status', 'list', 'scan', 'tailnet-status']) assert.ok(inContract(l), l);
// every command literal in the page's script is a `both` command (a new button that sends 'boot-status' fails here)
const heads = new Set(contract.map(e => e.exemplar.split(' ')[0]));
for (const m of script.matchAll(/'([a-z][a-z-]*)( [^']*)?'/g)) if (heads.has(m[1]) && !both.some(e => e.exemplar.split(' ')[0] === m[1])) assert.fail('the page names a console-only command: ' + m[0]);
// same bytes on both transports, for every `both` exemplar, through the page's own command layer
{
  const reply = l => l === 'status' ? statusG.temp_valid : l === 'list' ? repliesG['list/two_second_current'] : l === 'tailnet-status' ? TAILNET_JSON + '\r\n' : 'OK ' + l + '\r\n';
  globalThis.fetch = async (url, o) => ({ ok: true, status: 200, text: async () => reply(o.body) });
  const ser2 = TD.layer(await TD.serialTransport(fakePort(reply)));
  const http2 = TD.layer(TD.httpTransport(''));
  for (const e of both) {
    if (/^(reboot|mode )/.test(e.exemplar)) continue; // restart: covered above (a dropped connection is success)
    assert.equal(await ser2.raw(e.exemplar), await http2.raw(e.exemplar), 'same reply bytes for ' + e.exemplar);
  }
  // temperature: the chip_temperature line of `status`, the same on both transports, read the way the Android app reads it
  for (const g of ['temp_valid', 'temp_negative', 'temp_invalid']) {
    const fix = statusG[g];
    globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => fix });
    const viaHttp = await TD.layer(TD.httpTransport('')).status();
    const ct = viaHttp.sections.chip_temperature;
    const android = /^chip_temperature valid=1 current_tenths=([0-9]{1,4}) peak_tenths=([0-9]{1,4}) sampled_uptime_ms=[0-9]+ errors=[0-9]+\r?$/m.exec(fix);
    if (g === 'temp_valid') { assert.equal(ct.valid, '1'); assert.ok(android); assert.equal(ct.current_tenths, android[1]); assert.equal(ct.peak_tenths, android[2]); }
    if (g === 'temp_invalid') { assert.equal(ct.valid, '0'); assert.equal(android, null); }
    if (g === 'temp_negative') { assert.equal(ct.valid, '1'); assert.ok(+ct.current_tenths < 0); } // the web UI shows it; the Android regex has no minus sign (reported gap)
  }
}

// the page has no external resources
for (const bad of ['cdn.', 'unpkg', 'googleapis', '<link ']) assert.ok(!html.includes(bad), bad);
console.log('webui: ok (' + html.length + ' bytes)');
process.exit(0);

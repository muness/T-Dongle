import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const html=fs.readFileSync(new URL('../main/setup.html',import.meta.url),'utf8');
const between=(a,b)=>html.slice(html.indexOf(a),html.indexOf(b,html.indexOf(a)));
const names=between('function suggestedName','function el');
const redirect=between('function continueJoin','function renderMembers');
const opens=[];const store=new Map();
const c=vm.createContext({URL,sessionStorage:{getItem:k=>store.get(k),setItem:(k,v)=>store.set(k,v),removeItem:k=>store.delete(k)},window:{location:{assign:url=>opens.push(url)}},notice:{textContent:''}});
vm.runInContext("let joining='',approvedLabel='';function savedJoin(value){if(value)sessionStorage.setItem('joiningTailnet',value);else sessionStorage.removeItem('joiningTailnet')}"+names+redirect,c);
assert.equal(vm.runInContext('suggestedName([])',c),'tailnet');
assert.equal(vm.runInContext("suggestedName([{label:'TAILNET'},{label:'tailnet-2'}])",c),'tailnet-3');
const attempt=(members)=>{c.members=members;vm.runInContext('continueJoin(members)',c)};
vm.runInContext("joining='tailnet'",c);
attempt([{label:'other',enabled:true,state:3,login_url:'https://login.tailscale.com/a/fixture'}]);assert.equal(opens.length,0);
attempt([{label:'tailnet',enabled:true,state:3,login_url:'https://login.tailscale.com.evil.invalid/a/fixture'}]);assert.equal(opens.length,0);
attempt([{label:'tailnet',enabled:true,state:3,login_url:'http://login.tailscale.com/a/fixture'}]);assert.equal(opens.length,0);
attempt([{label:'tailnet',enabled:true,state:3,login_url:'https://login.tailscale.com/a/fixture'}]);assert.equal(opens.length,1);
attempt([{label:'tailnet',enabled:true,state:3,login_url:'https://login.tailscale.com/a/fixture'}]);assert.equal(opens.length,1,'approval link must not repeatedly reopen');
vm.runInContext("joining='tailnet'",c);attempt([{label:'tailnet',enabled:true,state:4}]);assert.equal(vm.runInContext('joining',c),'');
vm.runInContext("joining='tailnet'",c);attempt([{label:'tailnet',enabled:false,state:3,login_url:'https://login.tailscale.com/a/fixture'}]);assert.equal(opens.length,1);
console.log('Onboarding checks passed: unique suggested names, intended membership, safe login origin, one-time handoff, approved/disabled recovery.');

class Element {
  constructor(tag,text=''){this.tagName=tag.toUpperCase();this.textContent=text;this.children=[];this.style={};}
  append(...children){this.children.push(...children)}
  replaceChildren(...children){this.children=children}
  contains(){return false}
  setAttribute(){}
}
const root=new Element('div');
const renderContext=vm.createContext({URL,document:{activeElement:null},$:()=>root,el:(tag,text)=>new Element(tag,text),copyAddress(){},command(){},confirm:()=>false});
vm.runInContext('let lastMembers="";'+between('function renderMembers','async function refresh'),renderContext);
const render=m=>{renderContext.members=[m];vm.runInContext('renderMembers(members)',renderContext);return root.children[0]};
const peer={name:'server.example.ts.net',qualifiedName:'server.work.tailnet',address:'100.77.1.4'};
const texts=e=>[e.textContent,...e.children.flatMap(texts)].filter(Boolean);
let card=render({id:1,label:'work',enabled:true,state:5,protocol_error:'Registration failed',routing_ready:false,peers:[peer]});
assert(texts(card).includes('Registration retrying · routing unavailable'));
assert(texts(card).some(t=>t.includes('saved or earlier map')));
const row=card.children.find(e=>e.className==='peer');
assert.equal(row.children.length,2,'one address block and one copy control');
assert.deepEqual(texts(row.children[0]),['server','server.work.tailnet','100.77.1.4']);
assert(!row.children.some(e=>e.tagName==='INPUT'||e.tagName==='DETAILS'));
card=render({id:1,label:'work',enabled:true,state:4,routing_ready:true,peers:[peer]});
assert(texts(card).includes('Connected · USB routing ready'));
assert(!texts(card).some(t=>t.includes('saved or earlier map')));
console.log('Device presentation checks passed: current routing status, retained known peers, visible IP, compact row.');

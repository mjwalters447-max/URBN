const $ = (id) => typeof document !== "undefined" ? document.getElementById(id) : null;
const state = { data:null, view:"browse", pending:null, savedFilters:null, previousAttribute:"" };

async function unpack(bytes) {
  if (!("DecompressionStream" in window)) throw new Error("Unsupported browser");
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function openData(password) {
  const raw = new Uint8Array(await fetch("r.dat", {cache:"no-store"}).then(async r => {
    if (!r.ok) throw new Error("Data unavailable");
    return r.arrayBuffer();
  }));
  if (raw.length < 34 || raw[0] !== 2) throw new Error("Unsupported format");
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const rounds = view.getUint32(1, false);
  const salt = raw.slice(5, 21);
  const iv = raw.slice(21, 33);
  const sealed = raw.slice(33);
  const base = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    {name:"PBKDF2", salt, iterations:rounds, hash:"SHA-256"},
    base, {name:"AES-GCM", length:256}, false, ["decrypt"]
  );
  const packed = await crypto.subtle.decrypt(
    {name:"AES-GCM", iv, additionalData:new TextEncoder().encode("r2")},
    key, sealed
  );
  const plain = await unpack(packed);
  return JSON.parse(new TextDecoder().decode(plain));
}

function money(v){ return v == null ? "" : `$${Number(v).toFixed(2)}`; }
function pct(v){ return v == null ? "" : `${Number(v).toFixed(2).replace(/\.00$/,"").replace(/(\.\d)0$/,"$1")}%`; }
function esc(s=""){ return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function metricNumber(v){ const m=String(v||"").match(/\d+(?:\.\d+)?/); return m ? Number(m[0]) : null; }
function sizeLabel(v){ const n=Number(v); return `${n.toFixed(3).replace(/0+$/,"").replace(/\.$/,"")}g`; }

function nextAttributeSort(previous,current,currentSort){
  return !previous && current ? "metric-r" : currentSort;
}
function compareFilterDefaults(values){
  return {...values,search:"",source:"",group:"",size:"",attribute:""};
}

function rememberedAgeMatches(password,remember,storedPassword,storedAge){
  return Boolean(remember && storedAge==="1" && storedPassword===password);
}
function clearEntryMemory(){
  localStorage.removeItem("u-k");
  localStorage.removeItem("u-a");
}
function showAgeGate(data,password,remember){
  state.pending={data,password,remember};
  $("unlock-error").textContent="";
  $("lock").classList.add("hidden");
  $("age-gate").classList.remove("hidden");
}
function approveAge(){
  const pending=state.pending;
  if(!pending) return;
  if(pending.remember){
    localStorage.setItem("u-k",pending.password);
    localStorage.setItem("u-a","1");
  } else {
    clearEntryMemory();
  }
  $("age-gate").classList.add("hidden");
  initData(pending.data);
  state.pending=null;
}
function declineAge(){
  clearEntryMemory();
  state.pending=null;
  state.data=null;
  state.savedFilters=null;
  state.previousAttribute="";
  $("age-gate").classList.add("hidden");
  $("app").classList.add("hidden");
  $("lock").classList.remove("hidden");
  $("unlock-error").textContent="";
  $("password").value="";
  $("remember").checked=false;
  $("password").focus();
}

function attributeValue(item, key){
  if(!key || !item || !item.q || !(key in item.q)) return null;
  const value=Number(item.q[key]);
  return Number.isFinite(value) ? value : null;
}
function hasAttribute(item, key){
  const value=attributeValue(item,key);
  return value !== null && value > 0;
}
function descNumber(a,b){
  const av=Number.isFinite(a) ? a : -Infinity, bv=Number.isFinite(b) ? b : -Infinity;
  if(av===bv) return 0;
  return bv>av ? 1 : -1;
}
function compareItems(a,b,sort,key=""){
  let result=0;
  if(sort==="price-asc") result=(a.p??Infinity)-(b.p??Infinity);
  else if(sort==="price-desc") result=(b.p??-Infinity)-(a.p??-Infinity);
  else if(sort==="discount") result=descNumber(Number(a.d),Number(b.d));
  else if(sort==="metric-h") result=descNumber(metricNumber(a.h),metricNumber(b.h));
  else if(sort==="metric-r") {
    result=key
      ? descNumber(attributeValue(a,key),attributeValue(b,key))
      : descNumber(metricNumber(a.r),metricNumber(b.r));
  }
  else if(sort==="ppg") result=(a.g??Infinity)-(b.g??Infinity);
  else result=String(a.n||"").localeCompare(String(b.n||""));

  if(!Number.isFinite(result)) result=0;
  if(result===0 && key){
    result=descNumber(attributeValue(a,key),attributeValue(b,key));
  }
  if(result===0) result=String(a.n||"").localeCompare(String(b.n||""));
  return result;
}

function unitValueMarkup(item, sort){
  if(!item || item.g == null) return "";
  if(sort==="ppg"){
    return `<div class="unit-value unit-value-active"><span>Unit value</span><strong>${money(item.g)}/g</strong></div>`;
  }
  return `<div class="meta unit-value">${money(item.g)}/g</div>`;
}

function itemCard(p){
  const labels=state.data.l||{};
  const selected=$("attribute-filter")?.value||"";
  const selectedValue=attributeValue(p,selected);
  const old = p.P && p.P > p.p ? `<span class="old">${money(p.P)}</span>` : "";
  const sale = p.d ? `<span class="badge sale">${pct(p.d)} off</span>` : (p.s ? `<span class="badge sale">Offer</span>` : "");
  const meta = [p.c,p.t,p.z,p.h?`${labels.h||"M1"} ${p.h}`:null,p.r?`${labels.r||"M2"} ${p.r}`:null].filter(Boolean).join(" • ");
  const focus = selected && selectedValue !== null
    ? `<div class="focus-metric"><span>${esc(selected)}</span><strong>${pct(selectedValue)}</strong></div>` : "";
  const unitValue=unitValueMarkup(p,$("sort")?.value||"");
  return `<article class="card">
    <div class="store">${esc(p.A||"")}</div>
    <div class="brand">${esc(p.b||"")}</div>
    <h3>${esc(p.n||"")}</h3>
    ${focus}
    <div class="meta">${esc(meta)}</div>
    ${sale}
    <div class="price">${money(p.p)}${old}</div>
    ${unitValue}
    ${p.m ? `<div class="promo">${esc(p.m)}</div>` : ""}
    ${p.v ? `<div class="meta">${esc(p.v)}</div>` : ""}
    ${p.l ? `<a class="source" href="${esc(p.l)}" target="_blank" rel="noopener">Open ↗</a>` : ""}
  </article>`;
}

function filtered(){
  const q=$("search").value.trim().toLowerCase();
  const source=$("source-filter").value, group=$("group-filter").value;
  const size=$("size-filter").value, attribute=$("attribute-filter").value;
  let items=[...(state.data.p||[])];
  if(state.view==="offers") items=items.filter(p=>p.s);
  if(q) items=items.filter(p=>[p.n,p.b,p.c,p.t,p.A].some(x=>String(x||"").toLowerCase().includes(q)));
  if(source) items=items.filter(p=>p.a===source);
  if(group) items=items.filter(p=>p.c===group);
  if(size) items=items.filter(p=>Number(p.w)===Number(size));
  if(attribute) items=items.filter(p=>hasAttribute(p,attribute));
  const sort=$("sort").value;
  items.sort((a,b)=>compareItems(a,b,sort,attribute));
  return items;
}

function renderBrowse(){
  const items=filtered();
  const attribute=$("attribute-filter").value;
  if(attribute){
    $("summary").innerHTML=`<span>${items.length} items</span><span class="filter-note">Items without a reported ${esc(attribute)} concentration are excluded.</span>`;
  } else {
    $("summary").textContent=`${items.length} items`;
  }
  $("content").innerHTML=items.map(itemCard).join("") || `<div class="card">No matching items.</div>`;
}
function renderCompare(){
  const groups={};
  for(const p of filtered()) (groups[p.x] ||= []).push(p);
  const matches=Object.values(groups).filter(g=>new Set(g.map(x=>x.a)).size>1);
  $("summary").textContent=`${matches.length} exact cross-source matches`;
  $("content").innerHTML=matches.map(group=>{
    const p=group[0];
    const rows=group.sort((a,b)=>(a.p??Infinity)-(b.p??Infinity)).map(x=>
      `<div class="compare-row"><span>${esc(x.A||"")}</span><strong>${money(x.p)}</strong></div>`
    ).join("");
    return `<article class="card"><div class="brand">${esc(p.b||"")}</div><h3>${esc(p.n||"")}</h3><div class="meta">${esc([p.c,p.z].filter(Boolean).join(" • "))}</div>${rows}</article>`;
  }).join("") || `<div class="card">No exact matches across sources yet.</div>`;
}
function renderSources(){
  const sources=state.data.s||[];
  $("summary").textContent=`${sources.length} sources`;
  $("content").innerHTML=sources.map(s=>`<article class="card">
    <div class="store-status"><span class="dot ${esc(s.s||"")}"></span><h3>${esc(s.n||"")}</h3></div>
    <div class="meta">Status: ${esc(s.s||"unknown")}<br>Last update: ${esc(s.l||"Not yet")}</div>
    ${s.u?`<a class="source" href="${esc(s.u)}" target="_blank" rel="noopener">Open ↗</a>`:""}
  </article>`).join("");
}
function render(){
  document.querySelectorAll("nav button").forEach(b=>b.classList.toggle("active",b.dataset.view===state.view));
  if(state.view==="compare") renderCompare();
  else if(state.view==="sources") renderSources();
  else renderBrowse();
}

function readFilterState(){
  return {
    search:$("search").value,
    source:$("source-filter").value,
    group:$("group-filter").value,
    size:$("size-filter").value,
    attribute:$("attribute-filter").value,
    sort:$("sort").value,
  };
}
function applyFilterState(values){
  $("search").value=values.search||"";
  $("source-filter").value=values.source||"";
  $("group-filter").value=values.group||"";
  $("size-filter").value=values.size||"";
  $("attribute-filter").value=values.attribute||"";
  $("sort").value=values.sort||"name";
  state.previousAttribute=values.attribute||"";
}
function switchView(nextView){
  if(nextView==="compare"){
    if(!state.savedFilters) state.savedFilters=readFilterState();
    applyFilterState(compareFilterDefaults(readFilterState()));
  } else if((nextView==="browse" || nextView==="offers") && state.savedFilters){
    applyFilterState(state.savedFilters);
    state.savedFilters=null;
  }
  state.view=nextView;
  render();
}

function initData(data){
  state.data=data;
  state.savedFilters=null;
  state.previousAttribute="";
  const labels=data.l||{};
  $("main-title").textContent=labels.bn||"View";
  $("main-private").textContent=labels.bp||"";
  $("freshness").textContent=`Updated ${new Date(data.g).toLocaleString()}`;

  const sources=[...new Map((data.p||[]).map(p=>[p.a,p.A])).entries()].sort((a,b)=>String(a[1]).localeCompare(String(b[1])));
  $("source-filter").innerHTML=`<option value="">All Sources</option>`+sources.map(([v,n])=>`<option value="${esc(v)}">${esc(n)}</option>`).join("");

  const groups=[...new Set((data.p||[]).map(p=>p.c).filter(Boolean))].sort();
  $("group-filter").innerHTML=`<option value="">All Types</option>`+groups.map(c=>`<option>${esc(c)}</option>`).join("");

  const sizes=[...new Set((data.p||[]).map(p=>Number(p.w)).filter(v=>Number.isFinite(v)&&v>0))].sort((a,b)=>a-b);
  $("size-filter").innerHTML=`<option value="">Any Size</option>`+sizes.map(v=>`<option value="${v}">${sizeLabel(v)}</option>`).join("");

  const attrs=[...new Set((data.p||[]).flatMap(p=>Object.entries(p.q||{}).filter(([,v])=>Number(v)>0).map(([k])=>k)))].sort((a,b)=>a.localeCompare(b));
  $("attribute-caption").textContent=labels.f||"Attribute";
  $("attribute-filter").innerHTML=`<option value="">${esc(labels.af||"Any")}</option>`+attrs.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join("");

  $("sort").innerHTML=`
    <option value="name">Sort</option>
    <option value="price-asc">Price: Low to High</option>
    <option value="price-desc">Price: High to Low</option>
    <option value="discount">Largest Discount</option>
    <option value="metric-h">${esc(labels.sh||"Metric 1: High to Low")}</option>
    <option value="metric-r">${esc(labels.sr||"Metric 2: High to Low")}</option>
    <option value="ppg">Unit Value: Low to High</option>`;

  $("lock").classList.add("hidden");
  $("age-gate").classList.add("hidden");
  $("app").classList.remove("hidden");
  render();
}

async function tryUnlock(password, remember){
  $("unlock-error").textContent="Unlocking…";
  try{
    const data=await openData(password);
    const storedPassword=localStorage.getItem("u-k");
    const storedAge=localStorage.getItem("u-a");
    $("unlock-error").textContent="";
    if(rememberedAgeMatches(password,remember,storedPassword,storedAge)){
      initData(data);
    } else {
      clearEntryMemory();
      showAgeGate(data,password,remember);
    }
  }catch(err){
    $("unlock-error").textContent="Incorrect password or data unavailable.";
    clearEntryMemory();
  }
}

if(typeof document !== "undefined"){
  $("unlock-form").addEventListener("submit", e=>{e.preventDefault();tryUnlock($("password").value,$("remember").checked);});
  $("age-yes").addEventListener("click",approveAge);
  $("age-no").addEventListener("click",declineAge);
  $("lock-button").addEventListener("click",()=>{clearEntryMemory();location.reload();});
  for(const id of ["search","source-filter","group-filter","size-filter","sort"]) $(id).addEventListener("input",render);
  $("attribute-filter").addEventListener("change",()=>{
    const current=$("attribute-filter").value;
    $("sort").value=nextAttributeSort(state.previousAttribute,current,$("sort").value);
    state.previousAttribute=current;
    render();
  });
  document.querySelectorAll("nav button").forEach(b=>b.addEventListener("click",()=>switchView(b.dataset.view)));

  const saved=localStorage.getItem("u-k");
  if(saved){ $("remember").checked=true; $("password").value=saved; tryUnlock(saved,true); }
}

if(typeof module !== "undefined" && module.exports){
  module.exports={
    attributeValue,hasAttribute,compareItems,metricNumber,rememberedAgeMatches,
    unitValueMarkup,nextAttributeSort,compareFilterDefaults
  };
}

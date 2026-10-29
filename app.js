const $ = (id) => typeof document !== "undefined" ? document.getElementById(id) : null;
const state = { data:null, view:"browse", pending:null, savedFilters:null, previousAttribute:"", browseFilters:null, dealFilters:null, limit:60 };

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
function metricValue(v,unit="%"){
  const m=String(v||"").match(/^\s*(\d+(?:\.\d+)?)(?:\s*-\s*(\d+(?:\.\d+)?))?\s*(%|mg)\s*$/i);
  if(!m || m[3].toLowerCase()!==unit || Number(m[2]||m[1])<Number(m[1])) return null;
  if(unit==="%" && Number(m[2]||m[1])>100) return null;
  return Number(m[1]);
}
function safeUrl(value){
  try { const u=new URL(value); return ["https:","http:"].includes(u.protocol) ? u.href : ""; }
  catch { return ""; }
}
function sourceLink(url,label="Open source"){
  const href=safeUrl(url);
  return href ? `<a class="source" href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(label)} <span aria-hidden="true">↗</span></a>` : "";
}
function blankFilters(){return {search:"",source:"",group:"",size:"",attribute:"",sort:"name"};}
function entryMemory(key){try{return localStorage.getItem(key);}catch{return null;}}
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
  try {localStorage.removeItem("u-k");localStorage.removeItem("u-a");}catch{}
}
function showAgeGate(data,password,remember){
  state.pending={data,password,remember};
  $("unlock-error").textContent="";
  $("lock").classList.add("hidden");
  $("age-gate").classList.remove("hidden");
  $("age-yes").focus();
}
function approveAge(){
  const pending=state.pending;
  if(!pending) return;
  if(pending.remember){
    try {localStorage.setItem("u-k",pending.password);localStorage.setItem("u-a","1");}catch{clearEntryMemory();}
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
  document.body.classList.remove("is-open");
  $("lock").classList.remove("hidden");
  $("unlock-error").textContent="";
  $("password").value="";
  $("remember").checked=false;
  $("password").focus();
}

function attributeValue(item, key){
  if(!key || !item || !item.q || !(key in item.q)) return null;
  const value=item.q[key];
  return typeof value==="number" && Number.isFinite(value) && value>=0 && value<=100 ? value : null;
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
function compareNumber(a,b,descending=false){
  const av=typeof a==="number" && Number.isFinite(a), bv=typeof b==="number" && Number.isFinite(b);
  if(!av || !bv) return av ? -1 : bv ? 1 : 0;
  return descending ? b-a : a-b;
}
function compareItems(a,b,sort,key=""){
  let result=0;
  if(sort==="price-asc") result=compareNumber(a.p,b.p);
  else if(sort==="price-desc") result=compareNumber(a.p,b.p,true);
  else if(sort==="discount") result=compareNumber(a.d,b.d,true);
  else if(sort==="metric-h") result=descNumber(metricValue(a.h),metricValue(b.h));
  else if(sort==="metric-h-mg") result=descNumber(metricValue(a.h,"mg"),metricValue(b.h,"mg"));
  else if(sort==="metric-r") {
    result=key
      ? descNumber(attributeValue(a,key),attributeValue(b,key))
      : descNumber(metricValue(a.r),metricValue(b.r));
  }
  else if(sort==="ppg") result=compareNumber(a.g,b.g);
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

function sourceState(id){return (state.data.s||[]).find(s=>s.a===id);}
function isStale(source){
  return !source || source.s!=="fresh" || !source.l || Date.now()-Date.parse(source.l)>24*60*60*1000;
}
function staleBadge(id){return isStale(sourceState(id)) ? `<span class="badge warning">Earlier snapshot · verify at source</span>` : "";}
function dateLabel(value){const d=new Date(value);return value && !Number.isNaN(d.getTime()) ? d.toLocaleString() : "Not available";}

function itemCard(p){
  const labels=state.data.l||{};
  const selected=$("attribute-filter")?.value||"";
  const selectedValue=attributeValue(p,selected);
  const old = p.P && p.p!=null && p.P > p.p ? `<span class="old">${money(p.P)}</span>` : "";
  const sale = p.d>0 ? `<span class="badge sale">${pct(p.d)} off</span>` : (p.s ? `<span class="badge sale">Source offer</span>` : "");
  const meta = [p.c,p.t,p.z].filter(Boolean);
  const metrics = [p.h?`${labels.h||"M1"} ${p.h}`:null,p.H?`${labels.ha||"M3"} ${p.H}`:null,p.r?`${labels.r||"M2"} ${p.r}`:null].filter(Boolean);
  const focus = selected && selectedValue !== null
    ? `<div class="focus-metric"><span>${esc(selected)}</span><strong>${pct(selectedValue)}</strong></div>` : "";
  return `<article class="card">
    <div class="card-top"><div class="store">${esc(p.A||"")}</div>${sale}</div>
    ${staleBadge(p.a)}
    <div class="brand">${esc(p.b||"Source listing")}</div>
    <h3>${esc(p.n||"")}</h3>
    <div class="meta tags">${meta.map(v=>`<span>${esc(v)}</span>`).join("")}</div>
    ${focus}
    ${metrics.length?`<div class="metrics">${metrics.map(v=>`<span>${esc(v)}</span>`).join("")}</div>`:""}
    <div class="card-bottom"><div class="price">${p.p==null?`<span class="price-unknown">Price unavailable</span>`:money(p.p)}${old}</div>
    ${unitValueMarkup(p,$("sort")?.value||"")}
    ${p.m ? `<div class="promo">${esc(p.m)}</div>` : ""}
    ${p.v ? `<div class="inventory">${esc(p.v)}</div>` : ""}
    ${sourceLink(p.l,"View item")}</div>
  </article>`;
}
function offerCard(p){
  return `<article class="card offer-card"><div class="card-top"><div class="store">${esc(p.A||"")}</div><span class="badge">Store promotion</span></div>
    ${staleBadge(p.a)}<h3>${esc(p.n||"")}</h3>
    ${p.m?`<p class="offer-details">${esc(p.m)}</p>`:""}
    <div class="card-bottom">${sourceLink(p.l,"View eligible items & terms")}</div></article>`;
}
function filtered(){
  const q=$("search").value.trim().toLowerCase();
  const source=$("source-filter").value, group=$("group-filter").value;
  const size=$("size-filter").value, attribute=$("attribute-filter").value;
  let items=[...(state.view==="offers" ? state.data.o||[] : state.data.p||[])];
  if(q) items=items.filter(p=>[p.n,p.b,p.c,p.t,p.A,...(state.view==="offers"?[p.m]:[])].some(x=>String(x||"").toLowerCase().includes(q)));
  if(source) items=items.filter(p=>p.a===source);
  if(state.view!=="offers"){
    if(group) items=items.filter(p=>p.c===group);
    if(size) items=items.filter(p=>Number(p.w)===Number(size));
    if(attribute) items=items.filter(p=>hasAttribute(p,attribute));
  }
  items.sort((a,b)=>compareItems(a,b,state.view==="offers"?"name":$("sort").value,attribute));
  return items;
}
function emptyState(message){
  return `<div class="empty-state"><h3>${esc(message)}</h3><p>Try a broader search or clear the selected filters.</p><button type="button" data-reset>Clear filters</button></div>`;
}
function renderBrowse(){
  const items=filtered(), offers=state.view==="offers";
  const attribute=offers?"":$("attribute-filter").value;
  const visible=items.slice(0,state.limit);
  const noun=offers?"deals":"products";
  $("summary").innerHTML=`<strong>${items.length.toLocaleString()} ${noun}</strong><span>${items.length>visible.length?`Showing ${visible.length.toLocaleString()}`:""}</span>`;
  const note=offers ? state.data.l?.dealNote||"Check current terms at the source." : attribute ? `Products without a reported ${attribute} concentration are excluded.` : $("sort").value.startsWith("metric-h") ? "Only the selected unit is ranked. Other or missing measurements appear last; ranges use their lower value." : "";
  $("view-note").textContent=note;
  $("content").innerHTML=visible.map(offers?offerCard:itemCard).join("") || emptyState(offers?"No matching promotions":"No matching products");
  $("load-more").classList.toggle("hidden",items.length<=visible.length);
  $("load-more").textContent=`Show ${Math.min(60,Math.max(0,items.length-visible.length))} more`;
}
function renderCompare(){
  const groups=new Map();
  for(const p of filtered()) {if(!p.x) continue;if(!groups.has(p.x)) groups.set(p.x,[]);groups.get(p.x).push(p);}
  const matches=[...groups.values()].filter(g=>new Set(g.map(x=>x.a)).size>1);
  $("summary").innerHTML=`<strong>${matches.length} cross-source matches</strong>`;
  $("view-note").textContent="Same reported brand, name, type and size. Check each source for batch details and current availability.";
  $("load-more").classList.add("hidden");
  $("content").innerHTML=matches.map(group=>{
    const p=group[0];
    const rows=group.sort((a,b)=>compareNumber(a.p,b.p)).map(x=>
      `<div class="compare-row"><div>${sourceLink(x.l,x.A||"Source")}${staleBadge(x.a)}</div><strong>${x.p==null?"Unavailable":money(x.p)}</strong></div>`
    ).join("");
    return `<article class="card"><div class="brand">${esc(p.b||"")}</div><h3>${esc(p.n||"")}</h3><div class="meta">${esc([p.c,p.z].filter(Boolean).join(" • "))}</div>${rows}</article>`;
  }).join("") || emptyState("No exact matches across these sources");
}
function renderSources(){
  const sources=state.data.s||[];
  $("summary").innerHTML=`<strong>${sources.length} sources</strong>`;
  $("view-note").textContent="A refreshed catalog can include earlier store snapshots. The dates below show the last successful collection for each source.";
  $("load-more").classList.add("hidden");
  $("content").innerHTML=sources.map(s=>`<article class="card">
    <div class="store-status"><span class="dot ${isStale(s)?"stale":"fresh"}"></span><h3>${esc(s.n||"")}</h3></div>
    <div class="meta">${s.s==="unavailable"?"Unavailable":isStale(s)?"Earlier snapshot":"Latest collection available"}</div><p class="source-date">${esc(dateLabel(s.l))}</p>
    <div class="card-bottom">${sourceLink(s.u,"Open menu")}</div>
  </article>`).join("");
}
function renderFilterChips(){
  const ids=state.view==="offers"?["search","source-filter"]:["search","source-filter","group-filter","size-filter","attribute-filter"];
  $("active-filters").innerHTML=ids.filter(id=>$(id).value).map(id=>{
    const el=$(id), text=id==="search"?`Search: ${el.value}`:el.options[el.selectedIndex]?.text||el.value;
    return `<button class="filter-chip" type="button" data-clear="${id}" aria-label="${esc(`Remove ${text}`)}">${esc(text)} <span aria-hidden="true">×</span></button>`;
  }).join("");
}
function render(){
  document.querySelectorAll("nav button").forEach(b=>{b.classList.toggle("active",b.dataset.view===state.view);b.setAttribute("aria-pressed",String(b.dataset.view===state.view));});
  $("filter-panel").classList.toggle("hidden",state.view==="sources");
  document.querySelectorAll(".product-filter").forEach(el=>el.classList.toggle("hidden",state.view==="offers"));
  $("filter-panel").classList.toggle("offer-filters",state.view==="offers");
  $("content").classList.toggle("offer-grid",state.view==="offers");
  const title={browse:"Explore the menu",offers:"Deals worth a closer look",compare:"Compare across sources",sources:"Your menu sources"};
  $("view-title").textContent=title[state.view];
  renderFilterChips();
  if(state.view==="compare") renderCompare();
  else if(state.view==="sources") renderSources();
  else renderBrowse();
  $("content").querySelectorAll("[data-reset]").forEach(b=>b.addEventListener("click",resetFilters));
}
function resetFilters(){applyFilterState(blankFilters());state.limit=60;render();}
function filterChanged(){state.limit=60;render();}

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
  if(nextView===state.view) return;
  if(state.view==="browse") state.browseFilters=readFilterState();
  if(state.view==="offers") state.dealFilters=readFilterState();
  if(nextView==="compare"){
    applyFilterState(compareFilterDefaults(state.browseFilters||blankFilters()));
  } else if(nextView==="browse"){
    applyFilterState(state.browseFilters||blankFilters());
  } else if(nextView==="offers"){
    applyFilterState(state.dealFilters||blankFilters());
  }
  state.view=nextView;
  state.limit=60;
  render();
}

function initData(data){
  state.data=data;
  state.view="browse";
  state.browseFilters=null;
  state.dealFilters=null;
  state.limit=60;
  state.savedFilters=null;
  state.previousAttribute="";
  const labels=data.l||{};
  $("main-title").textContent=labels.bn||"View";
  $("main-private").textContent=labels.bp||"";
  document.title=labels.bn||"View";
  $("intro").textContent=labels.intro||"";
  $("footer-note").textContent=labels.foot||"";
  $("browse-count").textContent=(data.p||[]).length.toLocaleString();
  $("offers-count").textContent=(data.o||[]).length;
  $("sources-count").textContent=(data.s||[]).length;
  $("freshness").textContent=`Updated ${dateLabel(data.g)}`;

  const sources=[...new Map([...(data.p||[]),...(data.o||[])].map(p=>[p.a,p.A])).entries()].sort((a,b)=>String(a[1]).localeCompare(String(b[1])));
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
    <option value="metric-h-mg">${esc(labels.shm||"Metric 1 mg: High to Low")}</option>
    <option value="metric-r">${esc(labels.sr||"Metric 2: High to Low")}</option>
    <option value="ppg">Unit Value: Low to High</option>`;

  $("lock").classList.add("hidden");
  $("age-gate").classList.add("hidden");
  $("app").classList.remove("hidden");
  document.body.classList.add("is-open");
  applyFilterState(blankFilters());
  render();
}

async function tryUnlock(password, remember){
  $("unlock-error").textContent="Unlocking…";
  try{
    const data=await openData(password);
    const storedPassword=entryMemory("u-k");
    const storedAge=entryMemory("u-a");
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
  for(const id of ["search","source-filter","group-filter","size-filter","sort"]) $(id).addEventListener("input",filterChanged);
  $("attribute-filter").addEventListener("change",()=>{
    const current=$("attribute-filter").value;
    $("sort").value=nextAttributeSort(state.previousAttribute,current,$("sort").value);
    state.previousAttribute=current;
    filterChanged();
  });
  document.querySelectorAll("nav button").forEach(b=>b.addEventListener("click",()=>switchView(b.dataset.view)));

  $("reset-filters").addEventListener("click",resetFilters);
  $("load-more").addEventListener("click",()=>{state.limit+=60;render();});
  $("active-filters").addEventListener("click",e=>{
    const button=e.target.closest("[data-clear]");
    if(!button) return;
    $(button.dataset.clear).value="";
    state.previousAttribute=$("attribute-filter").value;
    filterChanged();
  });
  const saved=entryMemory("u-k");
  if(saved){ $("remember").checked=true; $("password").value=saved; tryUnlock(saved,true); }
}

if(typeof module !== "undefined" && module.exports){
  module.exports={
    attributeValue,hasAttribute,compareItems,metricNumber,rememberedAgeMatches,
    unitValueMarkup,nextAttributeSort,compareFilterDefaults,metricValue,safeUrl,compareNumber
  };
}

